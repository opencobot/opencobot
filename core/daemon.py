"""Daemon: authenticated Unix-socket JSON-lines server for the core.

Listens on ``state_dir/daemon.sock``; every request line must carry the
token from ``state_dir/daemon.auth`` (0600, generated once and reused).
The daemon owns the Runtime and the Model Gateway, but policy decisions
always go through a PolicyClient talking to the separate ``policyd``
process -- if policyd is unreachable, ``run_tool`` is refused rather
than falling back to an in-process policy (ARCHITECTURE.md section 2).

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
        for attr in ("socket_path", "sock_path", "policyd_socket", "socket"):
            path = getattr(client, attr, None)
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
            }
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
            runtime = Runtime(self.state_dir, self._policy_client(), self.registry)
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
        try:
            with conn, conn.makefile("rwb", buffering=0) as stream:
                for raw in stream:
                    line = raw.strip()
                    if not line:
                        continue
                    try:
                        request = json.loads(line.decode("utf-8"))
                    except (ValueError, UnicodeDecodeError):
                        response = {"ok": False, "error": "invalid request"}
                    else:
                        try:
                            response = self.handle_request(request)
                        except Exception as exc:
                            response = {"ok": False, "error": f"handler error: {exc}"}
                    stream.write((json.dumps(response) + "\n").encode("utf-8"))
        except OSError:
            pass

    def serve_forever(self) -> None:
        self._remove_stale_socket()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.sock_path))
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
