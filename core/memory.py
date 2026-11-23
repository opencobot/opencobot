"""Local SQLite memory for OpenCobot.

Stores user preferences, project context and saved workflows. Fully local,
viewable and deletable. Secrets must never be stored here -- they belong in
the OS keychain (see ARCHITECTURE.md section 10 / SPEC.md section 5.2).
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

_SECRET_MARKERS = ("secret", "password", "token", "api_key")


def default_state_dir() -> Path:
    """Default state directory, honouring OPENCOBOT_STATE."""
    return Path(os.environ.get("OPENCOBOT_STATE") or "~/.opencobot").expanduser()


def _check_no_secrets(key: str, value: dict | None = None) -> None:
    """Reject keys (and top-level value keys) that look like secret names."""
    if any(marker in key.lower() for marker in _SECRET_MARKERS):
        raise ValueError("secrets must not be stored in memory")
    if isinstance(value, dict):
        for subkey in value:
            if isinstance(subkey, str) and any(
                marker in subkey.lower() for marker in _SECRET_MARKERS
            ):
                raise ValueError("secrets must not be stored in memory")


class Memory:
    """Key/value store backed by SQLite at ``state_dir/memory.sqlite``."""

    def __init__(self, state_dir: str | Path | None = None):
        self.state_dir = Path(state_dir) if state_dir is not None else default_state_dir()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.state_dir / "memory.sqlite"
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def store(self, key: str, value: dict) -> None:
        if not isinstance(key, str) or not key:
            raise ValueError("key must be a non-empty string")
        if not isinstance(value, dict):
            raise TypeError("value must be a dict")
        _check_no_secrets(key, value)
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)",
                (key, json.dumps(value)),
            )
            conn.commit()

    def get(self, key: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
        if row is None:
            return None
        return json.loads(row[0])

    def delete(self, key: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM kv WHERE key = ?", (key,))
            conn.commit()

    def list_keys(self) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute("SELECT key FROM kv ORDER BY key").fetchall()
        return [row[0] for row in rows]
