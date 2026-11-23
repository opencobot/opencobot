"""Client for policyd, the separate policy process.

Mirrors the :class:`policy.engine.PolicyEngine` API over the Unix socket
so callers use the same calls whether they talk to the engine in-process
or to the daemon. Raises :class:`PolicyUnavailable` when the socket is
missing (daemon not running) and :class:`PolicyAuthError` when the
daemon rejects the auth token.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path

from .engine import Decision, _default_state_dir
from .tokens import CapabilityToken


class PolicyError(Exception):
    """A policyd request failed for a reason other than auth/unavailable."""


class PolicyUnavailable(FileNotFoundError):
    """policyd is not running: its socket does not exist / cannot connect."""


class PolicyAuthError(PermissionError):
    """policyd rejected the client's auth token."""


class PolicyClient:
    """Talk to policyd over its Unix socket."""

    def __init__(self, state_dir: Path | str | None = None):
        self.state_dir = (
            Path(state_dir) if state_dir is not None else _default_state_dir()
        )
        self.sock_path = self.state_dir / "policyd.sock"
        self._auth = self._read_auth()

    def _read_auth(self) -> str:
        auth_path = self.state_dir / "policyd.auth"
        if not auth_path.exists():
            raise PolicyAuthError(f"policyd auth file missing: {auth_path}")
        token = auth_path.read_text(encoding="utf-8").strip()
        if not token:
            raise PolicyAuthError(f"policyd auth file empty: {auth_path}")
        return token

    def _request(self, op: str, **fields: object) -> dict:
        if not self.sock_path.exists():
            raise PolicyUnavailable(f"policyd socket missing: {self.sock_path}")
        payload = {"op": op, "auth": self._auth, **fields}
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            sock.connect(str(self.sock_path))
        except OSError as exc:
            raise PolicyUnavailable(
                f"cannot connect to policyd socket: {self.sock_path}"
            ) from exc
        with sock:
            with sock.makefile("rwb") as f:
                f.write((json.dumps(payload) + "\n").encode("utf-8"))
                f.flush()
                raw = f.readline()
            if not raw:
                raise PolicyError("policyd closed the connection")
            reply = json.loads(raw.decode("utf-8"))
        if not reply.get("ok", False):
            if reply.get("code") == "auth_failed" or reply.get("error") == "auth failed":
                raise PolicyAuthError("policyd rejected the auth token")
            raise PolicyError(str(reply.get("error", "policyd request failed")))
        return reply

    @staticmethod
    def _token_dict(token: CapabilityToken | dict | None) -> dict | None:
        if token is None:
            return None
        if isinstance(token, dict):
            return token
        return token.to_dict()

    # -- API mirroring PolicyEngine ------------------------------------
    def check(
        self,
        token: CapabilityToken | dict | None,
        tool_name: str,
        level: int,
        args: dict | None = None,
        tainted: bool = False,
        network_call: bool = False,
    ) -> Decision:
        """Ask policyd for a decision; returns an engine-compatible Decision.

        ``network_call`` says whether this exact call performs network
        access; policyd re-classifies the call itself when it is not
        supplied, so omitting it is safe but explicit is preferred.
        """
        reply = self._request(
            "check",
            token=self._token_dict(token),
            tool_name=tool_name,
            level=level,
            args=args or {},
            tainted=bool(tainted),
            network_call=bool(network_call),
        )
        return Decision(
            allowed=bool(reply["allowed"]),
            reason=str(reply["reason"]),
            needs_approval=bool(reply.get("needs_approval", False)),
        )

    def issue_token(
        self,
        scope_folders: list[str],
        tools: list[str],
        duration_seconds: int = 600,
        network: bool = False,
    ) -> CapabilityToken:
        reply = self._request(
            "issue_token",
            scope_folders=[str(p) for p in scope_folders],
            tools=list(tools),
            duration_seconds=duration_seconds,
            network=bool(network),
        )
        return CapabilityToken.from_dict(reply["token"])

    def approve(
        self,
        token_id: str,
        tool_name: str,
        level: int | None = None,
        args: dict | None = None,
        duration_seconds: int = 600,
    ) -> str:
        """Approve exactly one call (R-007): (token, tool, level, args).

        ``level`` and ``args`` must match the call that will run; an
        approval without them can never match a policy check.
        """
        reply = self._request(
            "approve",
            token_id=token_id,
            tool_name=tool_name,
            level=level,
            args=args or {},
            duration_seconds=duration_seconds,
        )
        return str(reply["approval_id"])

    def taint(self, token_id: str) -> bool:
        return bool(self._request("taint", token_id=token_id)["tainted"])

    def untaint(self, token_id: str) -> bool:
        return bool(self._request("untaint", token_id=token_id)["tainted"])

    def kill(self) -> bool:
        return bool(self._request("kill")["killed"])

    def unkill(self) -> bool:
        return bool(self._request("unkill")["killed"])

    def status(self) -> dict:
        """Return ``{killed, socket, audit_entries}`` from policyd."""
        reply = self._request("status")
        return {
            "killed": reply["killed"],
            "socket": reply["socket"],
            "audit_entries": reply["audit_entries"],
        }

    def audit_verify(self) -> dict:
        """Return ``{valid, errors}`` for the daemon's audit log."""
        reply = self._request("audit_verify")
        return {"valid": bool(reply["valid"]), "errors": list(reply["errors"])}
