"""Daemon: authenticated Unix-socket JSON-lines server for the core.

Listens on ``state_dir/daemon.sock`` (POSIX) and on
``\\\\.\\pipe\\opencobot-daemon`` (Windows, ``ctypes`` listener with
a current-user + Administrators DACL, ADR-010); every
request line must carry the token from ``state_dir/daemon.auth``
(0600, generated once and reused). The daemon owns the Runtime and
the Model Gateway, but policy decisions always go through a
PolicyClient talking to the separate ``policyd`` process -- if
policyd is unreachable, ``run_tool`` is refused rather than falling
back to an in-process policy (ARCHITECTURE.md section 2).

Windows note: serving on a named pipe is implemented in
:mod:`core.transport` (``ctypes`` ``CreateNamedPipeW`` with a
current-user + Administrators DACL, ADR-010), mock-verified on
Linux; it still needs live verification on a Windows host
(docs/WINDOWS_TESTING.md §6) before it counts as proven. The
JSON-lines protocol is shared with policyd via :mod:`core.transport`.

Run: ``python -m core.daemon --state-dir DIR`` (or ``python -m core``).
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import signal
import socket
import threading
from pathlib import Path
from typing import Any

from .memory import default_state_dir
from .model_gateway import Gateway
from .runtime import Runtime
from .transport import (
    DAEMON_PIPE_PATH,
    NamedPipeListener,
    NamedPipeTransport,
    TransportNotAvailableError,
    UnixSocketTransport,
    decode_message,
    is_windows,
    send_message,
)


def _load_registry() -> dict:
    """Best-effort import of the tool registry (may not exist yet)."""
    try:
        from tools.definitions import TOOLS  # type: ignore[import-not-found]

        return dict(TOOLS) if isinstance(TOOLS, dict) else {}
    except Exception:
        return {}


def _load_auth_token(state_dir: Path) -> str:
    """Read the daemon auth token, generating and storing it once (0600)."""
    auth_path = state_dir / "daemon.auth"
    try:
        token = auth_path.read_text(encoding="utf-8").strip()
        if token:
            return token
    except FileNotFoundError:
        pass
    token = secrets.token_hex(32)
    try:
        fd = os.open(auth_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return auth_path.read_text(encoding="utf-8").strip()
    try:
        os.write(fd, token.encode("utf-8"))
    finally:
        os.close(fd)
    try:
        os.chmod(auth_path, 0o600)
    except OSError:
        pass
    return token


def _read_daemon_auth(state_dir: Path) -> str | None:
    """Read the daemon auth token WITHOUT generating one.

    ``daemon.auth`` holds either the raw token or a JSON object
    (``token``/``auth``/``secret``). Never generates: a query must
    not create credentials for a daemon that is not running (that is
    :func:`_load_auth_token`'s job, at daemon startup). The CLI's
    copy of this reader used to live in cli/opencobot_cli.py; it
    moved here so the query below and the CLI share one reader.
    """
    auth_path = Path(state_dir) / "daemon.auth"
    if not auth_path.exists():
        return None
    raw = auth_path.read_text(encoding="utf-8").strip()
    if not raw:
        return None
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return data.get("token") or data.get("auth") or data.get("secret")
    except ValueError:
        pass
    return raw


def query_daemon(state_dir, op, timeout=3.0) -> dict | None:
    """Send one JSON request to the daemon over its live transport.

    POSIX: Unix socket ``state_dir/daemon.sock``; Windows: named
    pipe ``\\\\.\\pipe\\opencobot-daemon``. The JSON-lines protocol
    (and the auth token from ``daemon.auth``) is identical on both —
    see :mod:`core.transport`. Returns the reply dict, or None when
    the daemon is unreachable or the reply is invalid. On Windows
    the pipe open has no timeout (a known transport limitation);
    the call still returns promptly when no daemon is listening.
    The CLI, doctor and web UI all share this one query path.
    """
    state_dir = Path(state_dir)
    auth = _read_daemon_auth(state_dir)
    request = {"op": op}
    if auth:
        request["auth"] = auth
    try:
        if is_windows():
            stream = NamedPipeTransport(DAEMON_PIPE_PATH).connect()
        else:
            sock_path = state_dir / "daemon.sock"
            if not sock_path.exists():
                return None
            stream = UnixSocketTransport(sock_path, timeout=timeout).connect()
    except TransportNotAvailableError:
        return None
    try:
        with stream:
            send_message(stream, request)
            raw = stream.readline()
    except OSError:
        return None
    if not raw:
        return None
    try:
        return decode_message(raw)
    except ValueError:
        return None


def daemon_reachable(state_dir, timeout=1.0) -> bool:
    """True if a daemon answers on its live transport.

    A bare connect (no request, no auth): POSIX checks the Unix
    socket, Windows the named pipe. A stale socket file with no
    listener behind it counts as NOT reachable — unlike a bare
    ``Path.exists()`` check, which would lie about it. Never raises.
    """
    state_dir = Path(state_dir)
    try:
        if is_windows():
            stream = NamedPipeTransport(DAEMON_PIPE_PATH).connect()
        else:
            stream = UnixSocketTransport(
                state_dir / "daemon.sock", timeout=timeout).connect()
    except TransportNotAvailableError:
        return False
    except OSError:
        return False
    try:
        stream.close()
    except Exception:
        pass
    return True


class Daemon:
    """Unix-socket server fronting Runtime + Gateway + PolicyClient."""

    def __init__(
        self,
        state_dir: str | Path | None = None,
        registry: dict | None = None,
        gateway: Gateway | None = None,
    ):
        self.state_dir = Path(state_dir) if state_dir is not None else default_state_dir()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.sock_path = self.state_dir / "daemon.sock"
        # Windows address (unused on POSIX; the live transport there is
        # the socket above). Kept as the pipe path so callers can tell
        # which transport this platform would use.
        self.pipe_path = DAEMON_PIPE_PATH
        self.auth_token = _load_auth_token(self.state_dir)
        self.registry = dict(registry) if registry is not None else _load_registry()
        self.gateway = gateway if gateway is not None else Gateway()
        self._policy_client_obj: Any = None
        self._policy_client_tried = False
        self._stop = threading.Event()
        self._listener: socket.socket | None = None

    # -- policy client ---------------------------------------------------

    def _policy_client(self) -> Any | None:
        """Lazily construct PolicyClient; None if the module is absent."""
        if self._policy_client_tried:
            return self._policy_client_obj
        self._policy_client_tried = True
        try:
            from policy.client import PolicyClient  # type: ignore[import-not-found]

            self._policy_client_obj = PolicyClient(self.state_dir)
        except Exception:
            self._policy_client_obj = None
        return self._policy_client_obj

    def _policyd_reachable(self) -> bool:
        """True only if a live policyd answers through the PolicyClient."""
        client = self._policy_client()
        if client is None:
            return False
        # A configured socket path that does not exist means policyd is down.
        # Named-pipe addresses (``\\.\pipe\...``) are not files: never
        # probe them with Path.exists() — liveness is decided by the
        # status() call below, not by the filesystem.
        for attr in ("socket_path", "sock_path", "policyd_socket", "socket"):
            path = getattr(client, attr, None)
            if isinstance(path, str) and path.startswith("\\\\.\\pipe\\"):
                continue
            if isinstance(path, (str, Path)) and path:
                if not Path(path).exists():
                    return False
        for method in ("ping", "status", "is_killed"):
            fn = getattr(client, method, None)
            if callable(fn):
                try:
                    result = fn()
                except Exception:
                    return False
                if isinstance(result, dict):
                    if "reachable" in result:
                        return bool(result["reachable"])
                    return True
                return True
        return False

    def _policyd_killed(self) -> bool:
        client = self._policy_client()
        if client is None:
            return False
        is_killed = getattr(client, "is_killed", None)
        if callable(is_killed):
            try:
                return bool(is_killed())
            except Exception:
                return False
        status = getattr(client, "status", None)
        if callable(status):
            try:
                result = status()
                if isinstance(result, dict):
                    return bool(result.get("killed", False))
            except Exception:
                return False
        return False

    # -- read-only mode (Phase 2) ----------------------------------------
    def _readonly_env_override(self) -> bool | None:
        """The OPENCOBOT_READONLY override, read directly.

        Mirrors ``policy.engine._env_readonly_override`` (same variable
        name and truthy/falsy sets) so the fallback below keeps its
        exact semantics without importing ``policy.engine``.
        """
        raw = os.environ.get("OPENCOBOT_READONLY")
        if raw is None:
            return None
        normalized = raw.strip().lower()
        if normalized in ("1", "true", "yes", "on"):
            return True
        if normalized in ("0", "false", "no", "off"):
            return False
        return None

    def is_readonly(self) -> bool:
        """Effective read-only state (env override wins, else the flag).

        Asked of policyd first (R-022). When policyd is unreachable the
        read falls back to a direct read of ``readonly.json`` — read-only
        and safe: the daemon must know the mode to enforce it even when
        policyd is down.
        """
        client = self._policy_client()
        if client is not None:
            try:
                return bool(client.get_readonly())
            except Exception:
                pass
        override = self._readonly_env_override()
        if override is not None:
            return override
        try:
            data = json.loads((self.state_dir / "readonly.json").read_text())
            return bool(data.get("readonly", False))
        except (OSError, ValueError, AttributeError):
            return False

    def set_readonly(self, enabled: bool) -> bool:
        """Persist the read-only flag via policyd; returns the new value.

        Writes fail closed when policyd is unreachable: the daemon
        never writes ``readonly.json`` directly, so a set that policyd
        did not see (and audit) cannot happen. (Reads keep the file
        fallback above; writes deliberately do not.)
        """
        client = self._policy_client()
        if client is None:
            return False
        try:
            return bool(client.set_readonly(bool(enabled)))
        except Exception:
            return False

    # -- request handling -------------------------------------------------

    def handle_request(self, request: Any) -> dict:
        if not isinstance(request, dict):
            return {"ok": False, "error": "invalid request"}
        auth = request.get("auth")
        if not isinstance(auth, str) or not secrets.compare_digest(auth, self.auth_token):
            return {"ok": False, "error": "unauthorized"}
        op = request.get("op")
        if op == "status":
            reachable = self._policyd_reachable()
            return {
                "ok": True,
                "tools": len(self.registry),
                "killed": self._policyd_killed() if reachable else False,
                "policyd_reachable": reachable,
                "readonly": self.is_readonly(),
            }
        if op == "readonly_get":
            return {"ok": True, "readonly": self.is_readonly()}
        if op == "readonly_set":
            enabled = request.get("enabled")
            if enabled is None:
                enabled = request.get("readonly")
            if not isinstance(enabled, bool):
                return {"ok": False, "error": "readonly_set needs enabled: true/false"}
            return {"ok": True, "readonly": self.set_readonly(enabled)}
        if op == "list_tools":
            return {"ok": True, "tools": Runtime(self.state_dir, None, self.registry).list_tools()}
        if op == "run_tool":
            if not self._policyd_reachable():
                return {
                    "ok": False,
                    "verified": False,
                    "decision": {
                        "allowed": False,
                        "reason": "policyd unavailable",
                        "needs_approval": False,
                    },
                    "result": {},
                    "evidence": "",
                }
            runtime = Runtime(
                self.state_dir, self._policy_client(), self.registry,
                gateway=self.gateway,
            )
            return runtime.run_tool(
                request.get("token"),
                str(request.get("tool_name", "")),
                request.get("args") or {},
                bool(request.get("tainted", False)),
            )
        if op in ("kill", "unkill"):
            if not self._policyd_reachable():
                return {"ok": False, "error": "policyd unavailable"}
            client = self._policy_client()
            want_killed = op == "kill"
            last_error = "kill not supported by policy client"
            for method, args in (
                ("kill", ()) if want_killed else ("unkill", ()),
                ("set_killed", (want_killed,)),
                ("set_kill_switch", (want_killed,)),
            ):
                fn = getattr(client, method, None)
                if callable(fn):
                    try:
                        fn(*args)
                        return {"ok": True, "killed": want_killed}
                    except Exception as exc:
                        last_error = str(exc)
            return {"ok": False, "error": last_error}
        if op == "gateway_status":
            config = self.gateway.configs[0] if self.gateway.configs else None
            if config is None:
                return {"ok": True, "provider": None, "model": None, "available": False}
            return {
                "ok": True,
                "provider": config.name,
                "model": config.model,
                "available": self.gateway.ping(config),
            }
        return {"ok": False, "error": f"unknown op: {op}"}

    # -- serving ----------------------------------------------------------

    def _remove_stale_socket(self) -> None:
        if is_windows():
            # Named pipes have no socket file to go stale.
            return
        if not self.sock_path.exists():
            return
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.settimeout(1)
            probe.connect(str(self.sock_path))
            # Something live is listening -- do not steal its socket.
            raise RuntimeError(f"daemon already running on {self.sock_path}")
        except (ConnectionRefusedError, FileNotFoundError, OSError):
            self.sock_path.unlink()
        finally:
            probe.close()

    def _handle_connection(self, conn: socket.socket) -> None:
        # Framing is shared with policyd via core.transport, so the
        # bytes are identical on the Unix socket and the named pipe.
        try:
            with conn, conn.makefile("rwb", buffering=0) as stream:
                for raw in stream:
                    line = raw.strip()
                    if not line:
                        continue
                    try:
                        request = decode_message(line)
                    except ValueError:
                        response = {"ok": False, "error": "invalid request"}
                    else:
                        try:
                            response = self.handle_request(request)
                        except Exception as exc:
                            response = {"ok": False, "error": f"handler error: {exc}"}
                    send_message(stream, response)
        except OSError:
            pass

    def serve_forever(self) -> None:
        # R-006: tighten the state dir and the daemon auth file, then
        # bind the socket owner-only (0600) regardless of umask.
        from policy.audit import PRIVATE_FILE_MODE, enforce_state_permissions

        enforce_state_permissions(self.state_dir)
        if is_windows():
            # Refuse a second instance: if a daemon already answers
            # on the pipe, do not serve alongside it — a second
            # named-pipe instance would silently split clients
            # between two daemons. (The listener also caps pipe
            # instances at 1, so a simultaneous start still fails
            # at CreateNamedPipeW; this probe gives the clean
            # "already running" error instead of a create failure.)
            if daemon_reachable(self.state_dir):
                raise RuntimeError(
                    f"daemon already running on {DAEMON_PIPE_PATH}")
            # Named-pipe server with a ctypes current-user/Admin
            # DACL (core.transport, ADR-010); refuses to start if
            # the ACL cannot be built, rather than serving an
            # ACL-less pipe.
            NamedPipeListener(DAEMON_PIPE_PATH).listen(
                handler=self.handle_request, stop=self._stop)
            return
        self._remove_stale_socket()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.sock_path))
        os.chmod(self.sock_path, PRIVATE_FILE_MODE)
        listener.listen(16)
        listener.settimeout(0.5)
        self._listener = listener
        try:
            while not self._stop.is_set():
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                thread = threading.Thread(
                    target=self._handle_connection, args=(conn,), daemon=True
                )
                thread.start()
        finally:
            try:
                listener.close()
            except OSError:
                pass
            self._listener = None
            try:
                self.sock_path.unlink()
            except FileNotFoundError:
                pass

    def stop(self) -> None:
        self._stop.set()
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OpenCobot core daemon")
    parser.add_argument(
        "--state-dir",
        default=None,
        help="State directory (default: $OPENCOBOT_STATE or ~/.opencobot)",
    )
    args = parser.parse_args(argv)
    daemon = Daemon(state_dir=args.state_dir)

    def _on_signal(signum, frame):  # noqa: ARG001
        daemon.stop()

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)
    daemon.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
