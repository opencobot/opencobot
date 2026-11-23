"""Tests for list_processes verify() under process churn.

Regression test for the CI failure on main f302c87 (PR #8 merge):
``test_list_processes_and_verify`` failed on the GitHub runner with
``verify(...) is True`` == False, while the same tree passed locally.
Root cause: verify() compared ``/proc/<pid>/comm`` names between the
execute() snapshot and a fresh listing, and treated ANY name change as
a lie. But a process that exec()s a new program keeps its pid and gets
a new comm (``sh`` -> ``sleep``), which happens constantly on a busy CI
runner. A name change is therefore legitimate, not evidence of
fabrication. Identity must be pid + starttime (invariant across exec);
a changed starttime means pid reuse, which must NOT confirm.
"""

import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import tools.definitions as definitions  # noqa: E402
from tools.definitions import get_tool  # noqa: E402


@pytest.fixture()
def ctx(tmp_path):
    workdir = tmp_path / "work"
    workdir.mkdir()
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    return {"state_dir": state_dir, "workdir": workdir, "token": None}


def _verify(args, result, ctx):
    return get_tool("list_processes").verify(args, result, ctx)


def _ok_result(processes):
    return {"ok": True, "data": {"processes": processes, "count": len(processes)}}


class _FakeAdapter:
    """Stand-in for the OS adapter: list_processes() returns a preset list."""

    def __init__(self, fresh):
        self._fresh = fresh

    def list_processes(self, name_filter=None):
        return list(self._fresh)


def _patch_adapter(monkeypatch, fresh):
    monkeypatch.setattr(definitions, "_os_adapter", lambda: _FakeAdapter(fresh))


def test_verify_accepts_exec_rename(monkeypatch, ctx):
    """Same pid + same starttime, new name (exec) -> still the same process."""
    reported = [{"pid": 1234, "name": "sh", "cmdline": "sh -c 'exec sleep 1'",
                 "starttime": 1000}]
    fresh = [{"pid": 1234, "name": "sleep", "cmdline": "sleep 1",
              "starttime": 1000}]
    _patch_adapter(monkeypatch, fresh)
    ok, reason = _verify({}, _ok_result(reported), ctx)
    assert ok is True, reason


def test_verify_rejects_pid_reuse(monkeypatch, ctx):
    """Same pid but a different starttime is a different process, not a confirm."""
    reported = [{"pid": 1234, "name": "sh", "cmdline": "sh", "starttime": 1000}]
    fresh = [{"pid": 1234, "name": "python", "cmdline": "python x.py",
              "starttime": 2000}]
    _patch_adapter(monkeypatch, fresh)
    ok, _reason = _verify({}, _ok_result(reported), ctx)
    assert ok is False


def test_verify_rejects_fabricated_list(monkeypatch, ctx):
    """Reported pids that do not exist at all -> nothing confirmed."""
    reported = [{"pid": 999999, "name": "totally-real", "cmdline": "",
                 "starttime": 1000}]
    _patch_adapter(monkeypatch, [])
    ok, _reason = _verify({}, _ok_result(reported), ctx)
    assert ok is False


def test_verify_no_starttime_name_match(monkeypatch, ctx):
    """Entries without starttime (Windows shape): matching name confirms."""
    reported = [{"pid": 1234, "name": "notepad.exe", "memory_kb": 1234}]
    fresh = [{"pid": 1234, "name": "notepad.exe", "memory_kb": 1234}]
    _patch_adapter(monkeypatch, fresh)
    ok, reason = _verify({}, _ok_result(reported), ctx)
    assert ok is True, reason


def test_verify_no_starttime_name_mismatch(monkeypatch, ctx):
    """Entries without starttime: a changed name confirms nothing."""
    reported = [{"pid": 1234, "name": "notepad.exe", "memory_kb": 1234}]
    fresh = [{"pid": 1234, "name": "calc.exe", "memory_kb": 5678}]
    _patch_adapter(monkeypatch, fresh)
    ok, _reason = _verify({}, _ok_result(reported), ctx)
    assert ok is False


def test_verify_filter_violation_still_rejected(monkeypatch, ctx):
    """A reported entry that does not match the name_filter is still a lie."""
    reported = [{"pid": 1234, "name": "bash", "cmdline": "bash",
                 "starttime": 1000}]
    fresh = [{"pid": 1234, "name": "bash", "cmdline": "bash",
              "starttime": 1000}]
    _patch_adapter(monkeypatch, fresh)
    ok, _reason = _verify({"name_filter": "python"}, _ok_result(reported), ctx)
    assert ok is False


def test_verify_under_exec_churn(ctx):
    """Real adapter: execute()+verify() must hold while shells exec around it.

    A background thread continuously spawns ``sh -c 'exec sleep ...'``:
    each child keeps its pid across the exec but changes comm ``sh`` ->
    ``sleep``. On the old name-equality verify this fails within a few
    iterations; with pid+starttime identity it always passes.
    """
    stop = threading.Event()

    def churn():
        while not stop.is_set():
            try:
                subprocess.run(
                    ["sh", "-c", "exec sleep 0.005"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=5,
                )
            except (OSError, subprocess.SubprocessError):
                pass

    thread = threading.Thread(target=churn, daemon=True)
    thread.start()
    try:
        failures = []
        for i in range(25):
            result = get_tool("list_processes").execute({}, ctx)
            assert result["ok"] is True
            ok, reason = _verify({}, result, ctx)
            if not ok:
                failures.append((i, reason))
        assert not failures, f"verify failed under churn: {failures[:3]}"
    finally:
        stop.set()
        thread.join(timeout=10)
