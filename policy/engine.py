"""Policy engine (SPEC §5, ARCHITECTURE §5, SECURITY.md invariants 1-4, 8, 9).

The engine is the only component that decides whether a tool call may
run. The model proposes; this engine -- driven by a short-lived
capability token, taint state, live human approvals and the kill switch
-- authorises. Every decision is written to the tamper-evident audit log.

Permission levels (SPEC §5.1): 0 read/inspect, 1 basic interaction,
2 controlled modification, 3 sensitive (explicit approval), 4 high risk
(strong approval). While tainted (untrusted) data is in context, level
3+ is locked even if an approval exists.
"""

from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

from .audit import AuditLog
from .tokens import CapabilityToken

# Argument keys whose values name filesystem locations. Any of these
# outside the token's scope denies the call.
PATH_ARG_KEYS = frozenset(
    {"path", "source", "destination", "directory", "folder", "file", "cwd"}
)

# Env var that overrides the persisted read-only flag (Phase 2).
# Accepted true values: 1/true/yes/on; false values: 0/false/no/off.
# Anything else is ignored and the persisted flag wins.
READONLY_ENV_VAR = "OPENCOBOT_READONLY"
_READONLY_TRUE = frozenset({"1", "true", "yes", "on"})
_READONLY_FALSE = frozenset({"0", "false", "no", "off"})


def _env_readonly_override() -> bool | None:
    """Read-only override from the environment, or None when unset."""
    raw = os.environ.get(READONLY_ENV_VAR)
    if raw is None:
        return None
    value = raw.strip().lower()
    if value in _READONLY_TRUE:
        return True
    if value in _READONLY_FALSE:
        return False
    return None


@dataclass
class Decision:
    """The outcome of one policy check."""

    allowed: bool
    reason: str
    needs_approval: bool = False


def _default_state_dir() -> Path:
    return Path(os.environ.get("OPENCOBOT_STATE") or "~/.opencobot").expanduser()


def _write_json_0600(path: Path, data: object) -> None:
    """Atomically replace ``path`` with ``data`` as JSON, mode 0600."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _read_json(path: Path, default: object) -> object:
    if not path.exists():
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return default


class PolicyEngine:
    """Enforces tokens, taint, approvals and the kill switch."""

    def __init__(self, state_dir: Path | str | None = None):
        self.state_dir = (
            Path(state_dir) if state_dir is not None else _default_state_dir()
        )
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._killed = False
        self.audit = AuditLog(self.state_dir / "audit.jsonl")

    # -- paths ---------------------------------------------------------
    @property
    def _approvals_path(self) -> Path:
        return self.state_dir / "approvals.json"

    @property
    def _taint_path(self) -> Path:
        return self.state_dir / "taint.json"

    @property
    def _killswitch_path(self) -> Path:
        return self.state_dir / "killswitch"

    @property
    def _readonly_path(self) -> Path:
        return self.state_dir / "readonly.json"

    # -- read-only mode (Phase 2) --------------------------------------
    def set_readonly(self, enabled: bool) -> bool:
        """Persist the read-only flag (0600 JSON, like approvals/taint).

        The flag is read from disk on every check, so a change made here
        (CLI, web UI, daemon) takes effect for the separate policyd
        process immediately, and survives daemon/policyd restarts.
        Returns the new effective persisted value.
        """
        enabled = bool(enabled)
        _write_json_0600(self._readonly_path, {"readonly": enabled})
        self.audit.append(
            {"type": "readonly_changed", "readonly": enabled}
        )
        return enabled

    def is_readonly(self) -> bool:
        """Effective read-only state: env var override wins, else the
        persisted flag. Default OFF."""
        override = _env_readonly_override()
        if override is not None:
            return override
        data = _read_json(self._readonly_path, {})
        if isinstance(data, dict):
            return bool(data.get("readonly", False))
        return False

    def readonly_source(self) -> str:
        """Where the effective value comes from: "env" or "file"."""
        return "env" if _env_readonly_override() is not None else "file"

    # -- tokens --------------------------------------------------------
    def issue_token(
        self,
        scope_folders: list[str | Path],
        tools: list[str],
        duration_seconds: int = 600,
        network: bool = False,
    ) -> CapabilityToken:
        """Mint a short-lived capability token."""
        now = time.time()
        return CapabilityToken(
            token_id=secrets.token_hex(16),
            scope_folders=[str(p) for p in scope_folders],
            tools=list(tools),
            network=bool(network),
            expires_at=now + duration_seconds,
            issued_at=now,
        )

    # -- approvals -----------------------------------------------------
    def approve(
        self, token_id: str, tool_name: str, duration_seconds: int = 600
    ) -> str:
        """Record a human approval for (token, tool); returns its id."""
        approvals = _read_json(self._approvals_path, [])
        if not isinstance(approvals, list):
            approvals = []
        approval_id = secrets.token_hex(16)
        now = time.time()
        approvals.append(
            {
                "id": approval_id,
                "token_id": token_id,
                "tool_name": tool_name,
                "issued_at": now,
                "expires_at": now + duration_seconds,
            }
        )
        _write_json_0600(self._approvals_path, approvals)
        return approval_id

    def revoke_approval(self, approval_id: str) -> bool:
        """Remove an approval by id; True when one was removed."""
        approvals = _read_json(self._approvals_path, [])
        if not isinstance(approvals, list):
            return False
        kept = [a for a in approvals if a.get("id") != approval_id]
        if len(kept) == len(approvals):
            return False
        _write_json_0600(self._approvals_path, kept)
        return True

    def has_approval(self, token_id: str, tool_name: str) -> bool:
        """True when a live (unexpired) approval exists for (token, tool)."""
        approvals = _read_json(self._approvals_path, [])
        if not isinstance(approvals, list):
            return False
        now = time.time()
        return any(
            a.get("token_id") == token_id
            and a.get("tool_name") == tool_name
            and float(a.get("expires_at", 0)) > now
            for a in approvals
        )

    # -- taint ---------------------------------------------------------
    def mark_tainted(self, token_id: str) -> None:
        """Tag a token's context as tainted (untrusted data seen)."""
        taint = _read_json(self._taint_path, {})
        if not isinstance(taint, dict):
            taint = {}
        taint[token_id] = {"tainted_at": time.time()}
        _write_json_0600(self._taint_path, taint)

    def clear_taint(self, token_id: str) -> None:
        """Clear the taint flag for a token."""
        taint = _read_json(self._taint_path, {})
        if not isinstance(taint, dict) or token_id not in taint:
            return
        del taint[token_id]
        _write_json_0600(self._taint_path, taint)

    def is_tainted(self, token_id: str) -> bool:
        """True when the token is currently flagged tainted."""
        taint = _read_json(self._taint_path, {})
        return isinstance(taint, dict) and token_id in taint

    # -- kill switch ---------------------------------------------------
    def set_kill(self, killed: bool) -> None:
        """Engage (True) or release (False) the kill switch."""
        self._killed = bool(killed)
        if killed:
            self._killswitch_path.write_text("killed\n", encoding="utf-8")
        else:
            self._killswitch_path.unlink(missing_ok=True)

    def is_killed(self) -> bool:
        """True when the kill switch is engaged (file or in-memory flag)."""
        return self._killed or self._killswitch_path.exists()

    # -- the check -----------------------------------------------------
    def _path_args_outside_scope(
        self, token: CapabilityToken, args: dict
    ) -> str | None:
        """Name of the first out-of-scope path arg, or None."""
        for key, value in (args or {}).items():
            if key not in PATH_ARG_KEYS:
                continue
            candidates = value if isinstance(value, (list, tuple)) else [value]
            for candidate in candidates:
                if isinstance(candidate, (str, Path)) and candidate != "":
                    if not token.allows_path(candidate):
                        return key
        return None

    def check(
        self,
        token: CapabilityToken | None,
        tool_name: str,
        level: int,
        args: dict | None = None,
        tainted: bool = False,
    ) -> Decision:
        """Decide whether ``tool_name`` at ``level`` may run under ``token``.

        Rules, in order: kill switch; read-only mode (level 1+ denied);
        token present and unexpired; tool in token; every path-like
        argument inside token scope; tainted context locks level 3+;
        levels 3 and 4 need a live approval; levels 0-2 are allowed in
        scope.
        """
        args = args or {}
        effective_tainted = bool(tainted) or (
            token is not None and self.is_tainted(token.token_id)
        )

        if self.is_killed():
            decision = Decision(False, "kill switch active")
        elif self.is_readonly() and level >= 1:
            decision = Decision(False, "read-only mode")
        elif token is None:
            decision = Decision(False, "no capability token")
        elif token.is_expired():
            decision = Decision(False, "capability token expired")
        elif not token.allows_tool(tool_name):
            decision = Decision(False, "tool not allowed by capability token")
        elif self._path_args_outside_scope(token, args) is not None:
            decision = Decision(False, "outside capability token scope")
        elif effective_tainted and level >= 3:
            decision = Decision(False, "tainted context: level 3+ locked")
        elif level == 4:
            if self.has_approval(token.token_id, tool_name):
                decision = Decision(True, "allowed")
            else:
                decision = Decision(
                    False, "level 4 requires approval", needs_approval=True
                )
        elif level == 3:
            if self.has_approval(token.token_id, tool_name):
                decision = Decision(True, "allowed")
            else:
                decision = Decision(
                    False, "level 3 requires approval", needs_approval=True
                )
        elif level in (0, 1, 2):
            decision = Decision(True, "allowed")
        else:
            decision = Decision(False, f"invalid permission level: {level}")

        # Audit every decision, including denials (invariant 8).
        self.audit.append(
            {
                "type": "policy_decision",
                "tool": tool_name,
                "level": level,
                "allowed": decision.allowed,
                "reason": decision.reason,
                "needs_approval": decision.needs_approval,
                "token_id": token.token_id if token is not None else None,
                "tainted": effective_tainted,
            }
        )
        return decision
