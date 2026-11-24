"""Tamper-evident, append-only audit log (SECURITY.md invariant 8).

One JSON object per line. Each entry carries a 1-based sequence number,
an ISO-8601 UTC timestamp, the hash of the previous entry (64 zeroes for
the first), and its own SHA-256 hash over ``prev_hash + canonical_json``
of the entry without the ``hash`` field. Any later edit to any line
breaks the chain and :meth:`AuditLog.verify` reports it.

Appends are multi-process safe: the file is opened in append mode and an
exclusive lock is held while the next sequence number and previous hash
are read and the new line is written. On POSIX that lock is
``fcntl.flock``; on Windows (which has no ``fcntl``) it is
``msvcrt.locking`` on the first byte — see :func:`_exclusive_lock`.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

try:
    import fcntl
except ImportError:  # Windows has no fcntl; see _exclusive_lock.
    fcntl = None

try:
    import msvcrt
except ImportError:  # POSIX has no msvcrt; see _exclusive_lock.
    msvcrt = None

GENESIS_PREV_HASH = "0" * 64

# R-006: the state dir and everything in it must be owner-only. The
# policy boundary is a same-user boundary, not a real OS boundary
# (see docs/risks.md), but at minimum no other local user may read
# the audit log, approvals or auth secret through the filesystem.
STATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


def enforce_state_permissions(state_dir: Path | str) -> None:
    """Tighten ``state_dir`` to 0700 and its private files to 0600.

    Called on startup by the policy engine, policyd and the daemon.
    Raises :class:`PermissionError` (fail loudly) when a path cannot
    be tightened — a state dir other local users can read is a
    security failure, not a warning to log and continue.
    """
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(state_dir, STATE_DIR_MODE)
    except OSError as exc:
        raise PermissionError(
            f"cannot secure state dir {state_dir}: {exc}") from exc
    for name in ("audit.jsonl", "approvals.json", "policyd.auth",
                 "daemon.auth", "taint.json"):
        path = state_dir / name
        if path.exists():
            try:
                os.chmod(path, PRIVATE_FILE_MODE)
            except OSError as exc:
                raise PermissionError(
                    f"cannot secure {path}: {exc}") from exc


def _canonical(obj: object) -> str:
    """Deterministic JSON: sorted keys, no insignificant whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _entry_hash(entry_without_hash: dict) -> str:
    prev_hash = entry_without_hash["prev_hash"]
    return hashlib.sha256(
        (prev_hash + _canonical(entry_without_hash)).encode("utf-8")
    ).hexdigest()


# Process-local fallback lock, used only when neither fcntl nor msvcrt
# is importable. It serialises threads inside this process only.
_fallback_thread_lock = threading.Lock()


@contextmanager
def _exclusive_lock(f):
    """Hold an exclusive, cross-process lock on open file ``f``.

    Locking choice (BUG-1: ``fcntl`` does not exist on Windows, so the
    old unconditional ``import fcntl`` broke the whole ``policy``
    package there):

    - POSIX (``fcntl`` available): ``fcntl.flock(LOCK_EX)`` — the
      original behaviour, unchanged. Whole-file, blocking, released
      with ``LOCK_UN``.
    - Windows (``msvcrt`` available): ``msvcrt.locking(fd, LK_LOCK, 1)``
      on byte 0 — the closest stdlib equivalent to ``flock``. It is a
      blocking, cross-process byte-range lock: ``LK_LOCK`` waits until
      the range is free, and the locked range may extend beyond EOF,
      so it works on an empty audit log. The same 1-byte range at the
      same offset is locked and unlocked by every cooperating process,
      and the read-seq/write critical section runs inside it, exactly
      as with ``flock``.
    - Neither available: a process-local ``threading.Lock``. This only
      serialises threads in this process — concurrent *processes*
      could interleave appends and break the hash chain. It exists so
      the audit log still works rather than crashing the package on
      an exotic platform; in practice Windows always has ``msvcrt``
      and POSIX always has ``fcntl``, so this path should not be hit.

    Limits shared by both real locks: they are advisory/cooperative —
    a process that opens the file without locking can still write.
    ``msvcrt.locking`` additionally locks a byte range, not the whole
    file, so only the reserved byte 0 is protected; that is enough
    here because every append locks that same byte before touching
    the file. The hash chain, entry format and file format are
    identical on every platform.
    """
    if fcntl is not None:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)
    elif msvcrt is not None:
        f.seek(0)
        msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
        try:
            yield
        finally:
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        with _fallback_thread_lock:
            yield


class AuditLog:
    """Hash-chained JSON-lines audit log."""

    def __init__(self, path: Path | str):
        self.path = Path(path)

    def append(self, event: dict) -> dict:
        """Append ``event`` and return the stored entry (with seq/ts/hash)."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a+", encoding="utf-8") as f:
            # R-006: the audit log is owner-only (0600) even under a
            # permissive umask.
            try:
                os.chmod(self.path, PRIVATE_FILE_MODE)
            except OSError:
                pass
            with _exclusive_lock(f):
                f.seek(0)
                lines = [line for line in f.read().splitlines() if line.strip()]
                entries = [json.loads(line) for line in lines]
                if entries:
                    last = entries[-1]
                    seq = int(last.get("seq", len(entries))) + 1
                    prev_hash = str(last["hash"])
                else:
                    seq = 1
                    prev_hash = GENESIS_PREV_HASH
                entry = dict(event)
                entry["seq"] = seq
                entry["ts"] = datetime.now(timezone.utc).isoformat()
                entry["prev_hash"] = prev_hash
                entry["hash"] = _entry_hash(entry)
                f.seek(0, os.SEEK_END)
                f.write(_canonical(entry) + "\n")
                f.flush()
                os.fsync(f.fileno())
                return entry

    def read_all(self) -> list[dict]:
        """Return every entry in order; ``[]`` when the log does not exist."""
        if not self.path.exists():
            return []
        entries = []
        with open(self.path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    entries.append(json.loads(line))
        return entries

    def verify(self) -> tuple[bool, list[str]]:
        """Recompute the whole chain.

        Returns ``(True, [])`` when the chain is intact, otherwise
        ``(False, errors)`` with one message per problem, naming the
        offending sequence number.
        """
        errors: list[str] = []
        if not self.path.exists():
            return True, []
        prev_hash = GENESIS_PREV_HASH
        expected_seq = 1
        with open(self.path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    errors.append(f"line {line_no}: not valid JSON")
                    continue
                seq = entry.get("seq", expected_seq)
                label = f"seq {seq}"
                if seq != expected_seq:
                    errors.append(
                        f"{label}: expected seq {expected_seq}, got {seq}"
                    )
                if entry.get("prev_hash") != prev_hash:
                    errors.append(f"{label}: prev_hash mismatch")
                stored_hash = entry.get("hash")
                entry_without_hash = {
                    k: v for k, v in entry.items() if k != "hash"
                }
                try:
                    recomputed = _entry_hash(entry_without_hash)
                except KeyError:
                    errors.append(f"{label}: missing prev_hash")
                    recomputed = None
                if recomputed is not None and stored_hash != recomputed:
                    errors.append(f"{label}: hash mismatch")
                # Advance the chain on the stored hash so one bad entry
                # does not cascade into false errors for every later one.
                if isinstance(stored_hash, str):
                    prev_hash = stored_hash
                expected_seq = seq + 1 if isinstance(seq, int) else expected_seq + 1
        return (not errors), errors
