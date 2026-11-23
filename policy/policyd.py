"""policyd: the policy engine as a separate process (SECURITY.md inv. 2).

Listens on a Unix socket at ``<state-dir>/policyd.sock`` on POSIX and
(on Windows, once the named-pipe listener lands) on the named pipe
``\\\\.\\pipe\\opencobot-policyd``. Speaks newline-delimited JSON: one
JSON request object per line, one JSON reply per line (see
:mod:`core.transport` for the shared framing). Every request must
carry the ``auth`` token from ``<state-dir>/policyd.auth`` (mode 0600,
generated once and reused); requests with a missing or wrong token
are rejected without being acted on. Handles one connection at a
time. Logs to stderr only.

Windows note: the named-pipe server is shape-only this round — the
stdlib cannot create a pipe with a current-user-only ACL, so
:func:`serve` refuses to start on Windows until the ``ctypes``
listener (``core.transport.NamedPipeListener``) is implemented and
verified on a Windows host.

Run: ``python -m policy.policyd --state-dir DIR``
"""

from __future__ import annotations

import argparse
import os
import secrets
import socket
import sys
import threading
from pathlib import Path

from .audit import PRIVATE_FILE_MODE, enforce_state_permissions
from .engine import PolicyEngine, _default_state_dir
from .tokens import CapabilityToken
from core.transport import (
    POLICYD_PIPE_PATH,
    NamedPipeListener,
    decode_message,
    is_windows,
    send_message,
)


def _load_or_create_auth(state_dir: Path) -> str:
    """Return the daemon auth token, creating it (0600) on first run."""
    auth_path = state_dir / "policyd.auth"
    if auth_path.exists():
        token = auth_path.read_text(encoding="utf-8").strip()
        if token:
            return token
    token = secrets.token_hex(32)
    auth_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(auth_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, (token + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    os.chmod(auth_path, 0o600)
    return token


def _is_network_call(tool_name: str, args: dict) -> bool:
    """Classify a call from the tool registry; False when unavailable."""
    try:
        from tools.definitions import is_network_call
    except ImportError:
        return False
    try:
        return bool(is_network_call(tool_name, args))
    except Exception:
        return False


def handle_request(
    engine: PolicyEngine, auth_token: str, request: dict
) -> dict:
    """Dispatch one request dict and return the reply dict."""
    if not isinstance(request, dict):
        return {"ok": False, "error": "request must be a JSON object"}
    if request.get("auth") != auth_token:
        return {"ok": False, "error": "auth failed", "code": "auth_failed"}

    op = request.get("op")
    try:
        if op == "check":
            token_data = request.get("token")
            token = (
                CapabilityToken.from_dict(token_data)
                if isinstance(token_data, dict)
                else None
            )
            tool_name = str(request.get("tool_name", ""))
            args = request.get("args") or {}
            # The caller normally supplies "network_call", but policyd
            # never trusts it alone: a network call is one the caller
            # says is network OR one policyd's own classification says
            # is network. A caller cannot downgrade a network call by
            # sending network_call=False.
            network_call = bool(request.get("network_call", False)) or (
                _is_network_call(tool_name, args))
            decision = engine.check(
                token,
                tool_name,
                int(request.get("level", 0)),
                args,
                bool(request.get("tainted", False)),
                network_call,
            )
            return {
                "ok": True,
                "allowed": decision.allowed,
                "reason": decision.reason,
                "needs_approval": decision.needs_approval,
                "decision": {
                    "allowed": decision.allowed,
                    "reason": decision.reason,
                    "needs_approval": decision.needs_approval,
                },
            }
        if op == "issue_token":
            token = engine.issue_token(
                request.get("scope_folders") or [],
                request.get("tools") or [],
                int(request.get("duration_seconds", 600)),
                bool(request.get("network", False)),
            )
            return {"ok": True, "token": token.to_dict()}
        if op == "approve":
            # R-007: the approval is bound to the exact level and the
            # exact arguments; a request without them records an
            # approval that can never match a real check (fail closed).
            level = request.get("level")
            args = request.get("args")
            approval_id = engine.approve(
                str(request.get("token_id", "")),
                str(request.get("tool_name", "")),
                int(level) if level is not None else None,
                dict(args) if isinstance(args, dict) else None,
                int(request.get("duration_seconds", 600)),
            )
            return {"ok": True, "approval_id": approval_id}
        if op == "taint":
            engine.mark_tainted(str(request.get("token_id", "")))
            return {"ok": True, "tainted": True}
        if op == "untaint":
            engine.clear_taint(str(request.get("token_id", "")))
            return {"ok": True, "tainted": False}
        if op == "kill":
            engine.set_kill(True)
            return {"ok": True, "killed": True}
        if op == "unkill":
            engine.set_kill(False)
            return {"ok": True, "killed": False}
        if op == "status":
            return {
                "ok": True,
                "killed": engine.is_killed(),
                "socket": (
                    POLICYD_PIPE_PATH
                    if is_windows()
                    else str(engine.state_dir / "policyd.sock")
                ),
                "audit_entries": len(engine.audit.read_all()),
            }
        if op == "audit_verify":
            valid, errors = engine.audit.verify()
            return {"ok": True, "valid": valid, "errors": errors}
        return {"ok": False, "error": f"unknown op: {op}"}
    except (ValueError, TypeError, KeyError) as exc:
        return {"ok": False, "error": f"bad request: {exc}"}


def serve(state_dir: Path, stop: threading.Event | None = None) -> None:
    """Serve policyd on ``state_dir/policyd.sock`` until ``stop`` is set.

    On Windows the named-pipe listener is shape-only this round (its
    ACL + ``ctypes`` implementation is deferred to laptop
    verification), so serving refuses to start there instead of
    listening on an ACL-less pipe.
    """
    state_dir = Path(state_dir)
    # R-006: tighten state-dir permissions before anything is created.
    enforce_state_permissions(state_dir)
    auth_token = _load_or_create_auth(state_dir)
    engine = PolicyEngine(state_dir)
    if is_windows():
        NamedPipeListener(POLICYD_PIPE_PATH).listen()
    sock_path = state_dir / "policyd.sock"
    if sock_path.exists():
        # Stale socket from a previous run; remove it before binding.
        sock_path.unlink()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(sock_path))
        # R-006: the socket is owner-only (0600) regardless of umask.
        os.chmod(sock_path, PRIVATE_FILE_MODE)
        server.listen(5)
        server.settimeout(0.5)
        print(f"policyd listening on {sock_path}", file=sys.stderr, flush=True)
        while stop is None or not stop.is_set():
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                handle_connection(conn, engine, auth_token)
    finally:
        server.close()
        sock_path.unlink(missing_ok=True)


def handle_connection(
    conn: socket.socket, engine: PolicyEngine, auth_token: str
) -> None:
    """Serve one connection: one JSON request per line, one reply per line.

    Framing (encode/decode) is shared with the client and the daemon
    via :mod:`core.transport`, so the bytes are identical on the Unix
    socket and on the Windows named pipe.
    """
    with conn.makefile("rwb") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            try:
                request = decode_message(line)
            except ValueError:
                reply = {"ok": False, "error": "invalid JSON"}
            else:
                reply = handle_request(engine, auth_token, request)
            send_message(f, reply)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="policyd")
    parser.add_argument(
        "--state-dir",
        default=None,
        help="state directory (default: $OPENCOBOT_STATE or ~/.opencobot)",
    )
    args = parser.parse_args(argv)
    state_dir = (
        Path(args.state_dir) if args.state_dir else _default_state_dir()
    )
    try:
        serve(state_dir)
    except KeyboardInterrupt:
        print("policyd stopping", file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
