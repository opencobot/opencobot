"""Capability tokens (OpenCobot SPEC §5.2, ARCHITECTURE §5).

A capability token scopes one task: which folders it may touch, which
tools it may call, whether it may use the network, and for how long.
Tokens are short-lived by design; the policy engine -- never the model --
decides whether a call fits the token.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class CapabilityToken:
    """A short-lived, scoped authorisation for one task."""

    token_id: str
    scope_folders: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)  # "*" allows any tool
    network: bool = False
    expires_at: float = 0.0
    issued_at: float = 0.0

    def is_expired(self, now: float | None = None) -> bool:
        """True when the token's expiry time has passed."""
        if now is None:
            now = time.time()
        return now >= self.expires_at

    def allows_tool(self, name: str) -> bool:
        """True when the token permits tool ``name`` ("*" permits any)."""
        return "*" in self.tools or name in self.tools

    def allows_path(self, path: str | Path) -> bool:
        """True when ``path`` resolves to inside one of the scope folders.

        The path is resolved (so ``..`` escapes and symlinks that point
        outside the scope are caught). With no scope folders there is
        nothing the token may touch, so every path is denied.
        """
        if not self.scope_folders:
            return False
        try:
            # Relative paths are relative to the token's workdir, i.e. the
            # first scope folder — the same rule the tools use to resolve
            # them. Resolving against the process CWD would wrongly deny
            # every relative path when the daemon runs from elsewhere.
            p = Path(path).expanduser()
            if not p.is_absolute():
                p = Path(self.scope_folders[0]).expanduser() / p
            resolved = p.resolve()
        except (OSError, RuntimeError):
            return False
        for folder in self.scope_folders:
            try:
                scope = Path(folder).expanduser().resolve()
            except (OSError, RuntimeError):
                continue
            if resolved.is_relative_to(scope):
                return True
        return False

    def to_dict(self) -> dict:
        """JSON-serialisable form (for the policyd wire protocol)."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "CapabilityToken":
        """Rebuild a token from :meth:`to_dict` output."""
        return cls(
            token_id=str(data["token_id"]),
            scope_folders=[str(p) for p in data.get("scope_folders", [])],
            tools=[str(t) for t in data.get("tools", [])],
            network=bool(data.get("network", False)),
            expires_at=float(data.get("expires_at", 0.0)),
            issued_at=float(data.get("issued_at", 0.0)),
        )
