"""Tests for the Windows fallback in the audit log (BUG-1).

``policy/audit.py`` used to do ``import fcntl`` unconditionally, so the
whole ``policy`` package failed to import on Windows (no ``fcntl``
there) and policyd / ``tool run`` could not start. The import is now
guarded and appends fall back to ``msvcrt.locking`` on Windows, with a
threading lock as a last resort.

These tests simulate a Windows-style environment on Linux by blocking
``fcntl`` (``sys.modules["fcntl"] = None`` makes ``import fcntl`` raise
``ImportError``) and importing a *fresh* copy of ``policy.audit`` — a
plain ``importlib.reload`` would mutate the already-imported module in
place, so instead the ``policy`` / ``policy.audit`` entries are removed
from ``sys.modules`` and re-imported, and the originals are restored
afterwards. No existing audit test is weakened.
"""

import importlib
import sys
import threading
import types
from contextlib import contextmanager
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import policy.audit as audit_module  # noqa: E402

_MISSING = object()


class _FakeMsvcrt:
    """Stand-in for Windows' ``msvcrt``: records locking calls.

    Real constants (``LK_UNLCK, LK_LOCK, ... = range(5)``) and the real
    signature ``locking(fd, mode, nbytes)``. It tracks whether the
    1-byte range is currently locked so a missing unlock (or a double
    lock) fails loudly instead of silently passing.
    """

    LK_UNLCK = 0
    LK_LOCK = 1
    LK_NBLCK = 2
    LK_RLCK = 3
    LK_NBRLCK = 4

    def __init__(self):
        self.calls = []  # list of (fd, mode, nbytes)
        self.locked = False

    def locking(self, fd, mode, nbytes):
        assert isinstance(fd, int), f"msvcrt.locking got non-fd {fd!r}"
        assert nbytes == 1, f"expected 1-byte lock, got {nbytes}"
        if mode == self.LK_LOCK:
            assert not self.locked, "msvcrt LK_LOCK while already locked"
            self.locked = True
        elif mode == self.LK_UNLCK:
            assert self.locked, "msvcrt LK_UNLCK while not locked"
            self.locked = False
        else:
            raise AssertionError(f"unexpected msvcrt mode {mode}")
        self.calls.append((fd, mode, nbytes))


@contextmanager
def _audit_without_fcntl(fake_msvcrt=None):
    """Yield a freshly imported ``policy.audit`` with ``fcntl`` blocked.

    ``fake_msvcrt`` (a ``_FakeMsvcrt``) is injected as ``msvcrt`` to
    exercise the Windows path; when it is ``None``, ``msvcrt`` is
    blocked too, so the threading-lock fallback is exercised. The
    original ``sys.modules`` entries are restored on exit, so later
    tests see the real (``fcntl``) module again.
    """
    saved = {
        name: sys.modules.get(name, _MISSING)
        for name in ("fcntl", "msvcrt", "policy", "policy.audit")
    }
    try:
        # None in sys.modules makes `import <name>` raise ImportError.
        sys.modules["fcntl"] = None
        if fake_msvcrt is not None:
            sys.modules["msvcrt"] = fake_msvcrt
        else:
            sys.modules["msvcrt"] = None
        sys.modules.pop("policy.audit", None)
        sys.modules.pop("policy", None)
        module = importlib.import_module("policy.audit")
        assert module.fcntl is None, "fcntl was not blocked"
        yield module
    finally:
        sys.modules.pop("policy.audit", None)
        sys.modules.pop("policy", None)
        for name, value in saved.items():
            if value is _MISSING:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value


def test_policy_package_imports_with_fcntl_blocked(tmp_path):
    """The original bug: ``import policy`` must not fail without fcntl."""
    with _audit_without_fcntl() as module:
        assert module.msvcrt is None  # threading-fallback case
        # Fresh import of the whole package (its __init__ imports AuditLog).
        import policy

        log = policy.AuditLog(tmp_path / "audit.jsonl")
        entry = log.append({"type": "policy_decision", "tool": "read_file"})
        assert entry["seq"] == 1
        assert entry["prev_hash"] == "0" * 64
        assert len(entry["hash"]) == 64


def test_append_with_fcntl_blocked_keeps_hash_chain(tmp_path):
    """Threading-fallback appends keep seq, prev_hash and verify()."""
    with _audit_without_fcntl() as module:
        log = module.AuditLog(tmp_path / "audit.jsonl")
        first = log.append({"type": "x", "i": 0})
        second = log.append({"type": "x", "i": 1})
        third = log.append({"type": "x", "i": 2})

        assert [e["seq"] for e in (first, second, third)] == [1, 2, 3]
        assert second["prev_hash"] == first["hash"]
        assert third["prev_hash"] == second["hash"]
        assert log.read_all()[1]["i"] == 1

        valid, errors = log.verify()
        assert valid is True, errors

        # Same on-disk format as the fcntl path: one JSON object/line.
        lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
        assert len(lines) == 3


def test_msvcrt_fallback_lock_is_used_and_released(tmp_path):
    """With a fake msvcrt, each append locks/unlocks byte 0 exactly once."""
    fake = _FakeMsvcrt()
    with _audit_without_fcntl(fake_msvcrt=fake) as module:
        assert module.msvcrt is fake
        log = module.AuditLog(tmp_path / "audit.jsonl")
        log.append({"type": "x"})
        log.append({"type": "y"})

        assert fake.calls == [
            (fake.calls[0][0], fake.LK_LOCK, 1),
            (fake.calls[0][0], fake.LK_UNLCK, 1),
            (fake.calls[2][0], fake.LK_LOCK, 1),
            (fake.calls[2][0], fake.LK_UNLCK, 1),
        ]
        assert fake.locked is False, "lock left held after append"
        valid, errors = log.verify()
        assert valid is True, errors


def test_msvcrt_lock_released_when_append_body_raises(tmp_path):
    """_exclusive_lock must unlock even if the critical section raises."""
    fake = _FakeMsvcrt()
    with _audit_without_fcntl(fake_msvcrt=fake) as module:
        path = tmp_path / "audit.jsonl"
        with open(path, "a+", encoding="utf-8") as f:
            with pytest.raises(RuntimeError, match="boom"):
                with module._exclusive_lock(f):
                    raise RuntimeError("boom")
        assert fake.locked is False
        assert [mode for _, mode, _ in fake.calls] == [
            fake.LK_LOCK,
            fake.LK_UNLCK,
        ]


def test_threading_fallback_serialises_concurrent_appends(tmp_path):
    """Threads appending without fcntl/msvcrt must not corrupt the chain."""
    with _audit_without_fcntl() as module:
        path = tmp_path / "audit.jsonl"

        def _append_many(worker, count):
            log = module.AuditLog(path)
            for i in range(count):
                log.append({"type": "test", "worker": worker, "i": i})

        threads = [
            threading.Thread(target=_append_many, args=(w, 10))
            for w in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        log = module.AuditLog(path)
        entries = log.read_all()
        assert len(entries) == 40
        assert sorted(e["seq"] for e in entries) == list(range(1, 41))
        valid, errors = log.verify()
        assert valid is True, errors


def test_real_module_restored_after_blocked_imports():
    """Guard for the helpers above: the real fcntl module comes back."""
    assert audit_module.fcntl is not None, (
        "policy.audit lost its real fcntl binding — "
        "a blocked-import test did not restore sys.modules"
    )
    # On Linux msvcrt genuinely does not exist.
    assert audit_module.msvcrt is None
