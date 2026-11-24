"""Tests for ``cli._compat.ensure_policyd`` readiness (BUG-K).

On POSIX readiness is the ``policyd.sock`` file; on Windows policyd
serves on a named pipe and never creates a socket file, so readiness
must be probed with a real ``PolicyClient.status()`` call. The tests
fake the platform, the client and the spawned process — they run on
Linux and on real Windows alike.
"""

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.transport  # noqa: E402
import policy.client  # noqa: E402
from cli._compat import PolicyUnavailable, ensure_policyd  # noqa: E402


class _FakeProc:
    def __init__(self, pid=12345):
        self.pid = pid

    def poll(self):
        return None


def _fake_popen(monkeypatch, proc=None):
    calls = []

    def fake_popen(*args, **kwargs):
        calls.append(args)
        return proc or _FakeProc()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    return calls


def _fake_client(monkeypatch, behaviour):
    """Replace ``PolicyClient`` with a fake whose status() follows
    ``behaviour`` — a list of results (dict) or exceptions to raise
    in order; the last entry repeats."""
    calls = {"n": 0}

    class FakeClient:
        def __init__(self, state_dir):
            self.state_dir = state_dir

        def status(self):
            idx = min(calls["n"], len(behaviour) - 1)
            calls["n"] += 1
            outcome = behaviour[idx]
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

    monkeypatch.setattr(policy.client, "PolicyClient", FakeClient)
    return calls


def test_windows_already_running_does_not_spawn(tmp_path, monkeypatch):
    """BUG-K: an already-listening policyd on Windows must be found
    by the status probe, not missed because policyd.sock is absent —
    otherwise ensure_policyd spawns a duplicate policyd."""
    monkeypatch.setattr(core.transport, "is_windows", lambda: True)
    _fake_client(monkeypatch, [{"killed": False, "socket": "pipe", "audit_entries": 0}])
    popen_calls = _fake_popen(monkeypatch)
    status, proc = ensure_policyd(tmp_path / "state")
    assert (status, proc) == ("running", None)
    assert popen_calls == []


def test_windows_spawns_then_becomes_ready(tmp_path, monkeypatch):
    """BUG-K: after spawning, the wait loop must poll the pipe probe
    (not policyd.sock) and report running once status() succeeds."""
    monkeypatch.setattr(core.transport, "is_windows", lambda: True)
    _fake_client(monkeypatch, [PolicyUnavailable("no pipe yet"),
                               {"killed": False, "socket": "pipe", "audit_entries": 0}])
    popen_calls = _fake_popen(monkeypatch)
    status, proc = ensure_policyd(tmp_path / "state", wait_seconds=5.0)
    assert status == "running"
    assert isinstance(proc, _FakeProc)
    assert len(popen_calls) == 1
    assert "policy.policyd" in popen_calls[0][0]


def test_windows_never_ready_reports_failed(tmp_path, monkeypatch):
    """BUG-K: when the pipe never answers, ensure_policyd must report
    failed (after the deadline) instead of hanging or claiming success."""
    monkeypatch.setattr(core.transport, "is_windows", lambda: True)
    _fake_client(monkeypatch, [PolicyUnavailable("no pipe")])
    _fake_popen(monkeypatch)
    status, proc = ensure_policyd(tmp_path / "state", wait_seconds=0.3)
    assert status == "failed"
    assert isinstance(proc, _FakeProc)


def test_posix_socket_exists_does_not_spawn(tmp_path, monkeypatch):
    """POSIX behaviour unchanged: an existing policyd.sock means
    running, with no spawn and no client probe."""
    monkeypatch.setattr(core.transport, "is_windows", lambda: False)
    state = tmp_path / "state"
    state.mkdir()
    (state / "policyd.sock").touch()
    popen_calls = _fake_popen(monkeypatch)
    status, proc = ensure_policyd(state)
    assert (status, proc) == ("running", None)
    assert popen_calls == []


def test_posix_socket_appears_after_spawn(tmp_path, monkeypatch):
    """POSIX behaviour unchanged: the wait loop watches the socket
    file and reports running once it appears."""
    monkeypatch.setattr(core.transport, "is_windows", lambda: False)
    state = tmp_path / "state"
    state.mkdir()

    def fake_popen(*args, **kwargs):
        (state / "policyd.sock").touch()
        return _FakeProc()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    status, proc = ensure_policyd(state, wait_seconds=5.0)
    assert status == "running"
    assert isinstance(proc, _FakeProc)


def test_raises_when_policyd_module_missing(tmp_path, monkeypatch):
    """No in-process fallback (R-009): a missing policyd module
    raises PolicyUnavailable instead of pretending to run."""
    monkeypatch.setattr(core.transport, "is_windows", lambda: False)
    monkeypatch.setattr("cli._compat._policyd_module_available", lambda: False)
    with pytest.raises(PolicyUnavailable, match="not installed"):
        ensure_policyd(tmp_path / "state")
