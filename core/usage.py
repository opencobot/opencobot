"""SQLite usage metering for the model gateway (SPEC.md section 8.4).

Per-provider daily and monthly call counts, persisted in the state dir
(``state_dir/usage.sqlite`` -- same convention as ``core/memory.py``,
which stores ``memory.sqlite`` there). Only counts are stored: provider
name, period and units. No prompts, no responses, no secrets, no keys.
"""

from __future__ import annotations

import sqlite3
from datetime import date
from pathlib import Path
from typing import Union

from .memory import default_state_dir


class UsageStore:
    """Persisted per-provider usage counts (daily + monthly)."""

    def __init__(self, state_dir: Union[str, Path, None] = None):
        self.state_dir = (
            Path(state_dir) if state_dir is not None else default_state_dir()
        )
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.state_dir / "usage.sqlite"
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS usage ("
                " provider TEXT NOT NULL,"
                " period TEXT NOT NULL,"  # "YYYY-MM-DD" (daily) or "YYYY-MM" (monthly)
                " units INTEGER NOT NULL DEFAULT 0,"
                " PRIMARY KEY (provider, period))"
            )
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def record(self, provider: str, units: int = 1) -> None:
        """Add ``units`` to the provider's daily and monthly counts."""
        if not isinstance(provider, str) or not provider:
            raise ValueError("provider must be a non-empty string")
        if units < 0:
            raise ValueError("units must be non-negative")
        today = date.today()
        periods = (today.isoformat(), today.strftime("%Y-%m"))
        with self._connect() as conn:
            for period in periods:
                conn.execute(
                    "INSERT INTO usage (provider, period, units) VALUES (?, ?, ?)"
                    " ON CONFLICT(provider, period) DO UPDATE"
                    " SET units = usage.units + excluded.units",
                    (provider, period, units),
                )
            conn.commit()

    def daily(self, provider: str, day: Union[str, date, None] = None) -> int:
        """Units used by ``provider`` on ``day`` (default: today)."""
        period = day.isoformat() if isinstance(day, date) else (day or date.today().isoformat())
        with self._connect() as conn:
            row = conn.execute(
                "SELECT units FROM usage WHERE provider = ? AND period = ?",
                (provider, period),
            ).fetchone()
        return int(row[0]) if row else 0

    def monthly(self, provider: str, month: Union[str, date, None] = None) -> int:
        """Units used by ``provider`` in ``month`` ("YYYY-MM", default: this month)."""
        if isinstance(month, date):
            period = month.strftime("%Y-%m")
        else:
            period = month or date.today().strftime("%Y-%m")
        with self._connect() as conn:
            row = conn.execute(
                "SELECT units FROM usage WHERE provider = ? AND period = ?",
                (provider, period),
            ).fetchone()
        return int(row[0]) if row else 0

    def providers(self) -> list[str]:
        """Provider names with any recorded usage."""
        with self._connect() as conn:
            rows = conn.execute("SELECT DISTINCT provider FROM usage ORDER BY provider").fetchall()
        return [row[0] for row in rows]
