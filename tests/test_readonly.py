"""Tests for Phase 2 read-only mode (policy/engine.py, core/daemon.py, CLI).

Read-only is a persistent flag in the state dir (``readonly.json``,
0600, like approvals/taint) plus an ``OPENCOBOT_READONLY`` env var
override. When ON, the policy engine denies level 1+ tools with
reason "read-only mode"; level 0 tools stay allowed; every denial is
audited. The flag survives daemon/policyd restarts because it is read
from disk on every check.
"""

import json
import os
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.daemon import Daemon  # noqa: E402
from core.runtime import Runtime  # noqa: E402
from policy.client import PolicyClient, PolicyUnavailable  # noqa: E402
from policy.engine import PolicyEngine  # noqa: E402
from policy.policyd import _load_or_create_auth, serve  # noqa: E402
from tests.test_policy import _RecordingTransport  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI = [sys.executable, "-m", "cli.opencobot_cli"]


@pytest.fixture()
def state_dir(tmp_path):
    return tmp_path / "state"


@pytest.fixture()
def scope(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    return work


@pytest.fixture()
def engine(state_dir):
    return PolicyEngine(state_dir)


@pytest.fixture()
def token(engine, scope):
    return engine.issue_token(
        [str(scope)], ["read_file", "write_file", "launch_app", "list_dir"]
    )


def _audit_entries(state_dir):
    path = Path(state_dir) / "audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# -- engine: default, persistence, levels -------------------------------

def test_readonly_default_off(engine):
    assert engine.is_readonly() is False
    assert engine.readonly_source() == "file"


def test_readonly_persists_across_engine_restart(state_dir, engine):
    engine.set_readonly(True)
    assert (state_dir / "readonly.json").exists()
    assert stat.S_IMODE((state_dir / "readonly.json").stat().st_mode) == 0o600
    fresh = PolicyEngine(state_dir)  # a new process would do the same
    assert fresh.is_readonly() is True
    fresh.set_readonly(False)
    assert PolicyEngine(state_dir).is_readonly() is False


def test_readonly_denies_level1_plus_allows_level0(engine, token, scope):
    engine.set_readonly(True)
    assert engine.check(token, "read_file", 0, {"path": str(scope)}).allowed is True
    for tool, level in (("launch_app", 1), ("write_file", 2), ("delete_file", 3)):
        decision = engine.check(token, tool, level, {"path": str(scope)})
        assert decision.allowed is False
        assert decision.reason == "read-only mode"


def test_readonly_denial_is_audited(engine, token, state_dir):
    engine.set_readonly(True)
    engine.check(token, "write_file", 2, {})
    denials = [e for e in _audit_entries(state_dir)
               if e.get("type") == "policy_decision"
               and e.get("reason") == "read-only mode"
               and e.get("allowed") is False]
    assert len(denials) == 1
    assert denials[0]["tool"] == "write_file"
    assert denials[0]["level"] == 2


def test_readonly_off_restores_level1_and_2(engine, token, scope):
    engine.set_readonly(True)
    assert engine.check(token, "launch_app", 1).allowed is False
    engine.set_readonly(False)
    assert engine.check(token, "launch_app", 1).allowed is True
    assert engine.check(token, "write_file", 2, {"path": str(scope)}).allowed is True


def test_kill_switch_still_wins_over_readonly(engine, token):
    engine.set_readonly(True)
    engine.set_kill(True)
    decision = engine.check(token, "write_file", 2, {})
    assert decision.allowed is False
    assert decision.reason == "kill switch active"
    engine.set_kill(False)
    assert engine.check(token, "write_file", 2, {}).reason == "read-only mode"


# -- env var override -----------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    ("1", True), ("true", True), ("yes", True), ("on", True),
    ("TRUE", True), ("0", False), ("false", False), ("no", False), ("off", False),
])
def test_env_override_wins_over_persisted_flag(state_dir, engine, value, expected, monkeypatch):
    engine.set_readonly(not expected)  # persisted flag says the opposite
    monkeypatch.setenv("OPENCOBOT_READONLY", value)
    assert PolicyEngine(state_dir).is_readonly() is expected
    assert PolicyEngine(state_dir).readonly_source() == "env"


def test_env_override_invalid_value_falls_back_to_file(state_dir, engine, monkeypatch):
    engine.set_readonly(True)
    monkeypatch.setenv("OPENCOBOT_READONLY", "maybe")
    assert PolicyEngine(state_dir).is_readonly() is True
    assert PolicyEngine(state_dir).readonly_source() == "file"


def test_env_override_on_denies_level1(state_dir, engine, token, monkeypatch):
    monkeypatch.setenv("OPENCOBOT_READONLY", "1")
    decision = PolicyEngine(state_dir).check(token, "launch_app", 1)
    assert decision.allowed is False
    assert decision.reason == "read-only mode"


# -- runtime integration with the real engine + registry ------------------

def test_runtime_readonly_l0_allowed_l1_denied(state_dir, scope):
    engine = PolicyEngine(state_dir)
    token = engine.issue_token([str(scope)], ["*"])
    runtime = Runtime(state_dir, policy=engine)
    engine.set_readonly(True)
    ok = runtime.run_tool(token, "list_dir", {"path": str(scope)})
    assert ok["ok"] is True and ok["verified"] is True
    denied = runtime.run_tool(token, "launch_app", {"app": "true"})
    assert denied["ok"] is False
    assert denied["decision"]["reason"] == "read-only mode"


# -- daemon ops -------------------------------------------------------------

def test_daemon_readonly_ops(state_dir):
    # R-022: daemon writes go through policyd, so policyd must be
    # running for the set to succeed. The daemon itself is created
    # after policyd is up (its PolicyClient is cached on first use).
    state_dir.mkdir(parents=True, exist_ok=True)
    stop = threading.Event()
    thread = threading.Thread(target=serve, args=(state_dir, stop),
                              daemon=True)
    thread.start()
    try:
        deadline = time.time() + 10
        while True:
            try:
                PolicyClient(state_dir).status()
                break
            except (PolicyUnavailable, OSError):
                if time.time() > deadline:
                    raise AssertionError("policyd did not start")
                time.sleep(0.05)
        daemon = Daemon(state_dir=state_dir)
        get = {"auth": daemon.auth_token, "op": "readonly_get"}
        assert daemon.handle_request(get) == {"ok": True, "readonly": False}
        set_on = {"auth": daemon.auth_token, "op": "readonly_set",
                  "enabled": True}
        assert daemon.handle_request(set_on) == {"ok": True, "readonly": True}
        assert daemon.handle_request(get) == {"ok": True, "readonly": True}
        assert daemon.is_readonly() is True
        # Status exposes the flag, and a fresh daemon reads it via policyd.
        status = daemon.handle_request({"auth": daemon.auth_token,
                                        "op": "status"})
        assert status["readonly"] is True
        assert Daemon(state_dir=state_dir).is_readonly() is True
        bad = {"auth": daemon.auth_token, "op": "readonly_set",
               "enabled": "yes"}
        assert daemon.handle_request(bad)["ok"] is False
        daemon.handle_request({"auth": daemon.auth_token, "op": "readonly_set",
                               "enabled": False})
        assert daemon.is_readonly() is False
    finally:
        stop.set()
        thread.join(timeout=5)


def test_daemon_readonly_set_fails_closed_without_policyd(state_dir,
                                                          monkeypatch):
    """Without policyd, daemon writes do nothing (R-022).

    Reads keep the direct file fallback (plus the env override), so the
    daemon still knows the mode it must enforce when policyd is down.
    """
    monkeypatch.delenv("OPENCOBOT_READONLY", raising=False)
    daemon = Daemon(state_dir=state_dir)
    assert daemon.is_readonly() is False
    assert daemon.set_readonly(True) is False
    # No direct write happened: the flag file was never created.
    assert not (state_dir / "readonly.json").exists()
    assert daemon.is_readonly() is False
    # The env override still applies to reads when policyd is down.
    monkeypatch.setenv("OPENCOBOT_READONLY", "1")
    assert daemon.is_readonly() is True
    monkeypatch.setenv("OPENCOBOT_READONLY", "0")
    assert daemon.is_readonly() is False
    # ... and a persisted flag is still read from the file.
    (state_dir / "readonly.json").write_text('{"readonly": true}')
    monkeypatch.delenv("OPENCOBOT_READONLY", raising=False)
    assert Daemon(state_dir=state_dir).is_readonly() is True


def test_daemon_readonly_uses_client_not_engine(state_dir, monkeypatch):
    """is_readonly/set_readonly talk to policyd, never policy.engine.

    The engine import is blocked outright; the client runs over a
    recording fake transport so the exact ops can be asserted.
    """
    state_dir.mkdir(parents=True, exist_ok=True)
    _load_or_create_auth(state_dir)
    fake = _RecordingTransport([
        {"ok": True, "readonly": False, "source": "file"},
        {"ok": True, "readonly": True, "source": "file"},
        {"ok": True, "readonly": True, "source": "file"},
    ])
    client = PolicyClient(state_dir, transport=fake)
    monkeypatch.setattr(Daemon, "_policy_client", lambda self: client)
    monkeypatch.setitem(sys.modules, "policy.engine", None)
    daemon = Daemon(state_dir=state_dir)
    assert daemon.is_readonly() is False
    assert daemon.set_readonly(True) is True
    assert daemon.is_readonly() is True
    assert [r["op"] for r in fake.requests] == ["readonly"] * 3
    assert fake.requests[1]["enabled"] is True
    # The set only happened on the fake policyd: no file was written.
    assert not (state_dir / "readonly.json").exists()


def test_daemon_readonly_requires_auth(state_dir):
    daemon = Daemon(state_dir=state_dir)
    reply = daemon.handle_request({"auth": "wrong", "op": "readonly_set",
                                   "enabled": True})
    assert reply["ok"] is False
    assert daemon.is_readonly() is False


# -- CLI ----------------------------------------------------------------------

def run_cli(state_dir, *args, env=None):
    merged = dict(os.environ)
    merged.pop("OPENCOBOT_READONLY", None)
    if env:
        merged.update(env)
    return subprocess.run(
        CLI + ["--state-dir", str(state_dir), *args],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60, env=merged)


def test_cli_readonly_on_off_status(state_dir):
    proc = run_cli(state_dir, "readonly", "status")
    assert proc.returncode == 0
    assert "OFF" in proc.stdout
    proc = run_cli(state_dir, "readonly", "on")
    assert proc.returncode == 0
    assert "ON" in proc.stdout
    assert (state_dir / "readonly.json").exists()
    assert json.loads((state_dir / "readonly.json").read_text()) == {"readonly": True}
    proc = run_cli(state_dir, "readonly", "status", "--json")
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload == {"readonly": True, "source": "file"}
    assert run_cli(state_dir, "readonly", "off").returncode == 0
    assert PolicyEngine(state_dir).is_readonly() is False


def test_cli_readonly_status_reports_env_override(state_dir):
    run_cli(state_dir, "readonly", "off")
    proc = run_cli(state_dir, "readonly", "status", env={"OPENCOBOT_READONLY": "1"})
    assert proc.returncode == 0
    assert "ON" in proc.stdout
    assert json.loads(run_cli(
        state_dir, "readonly", "status", "--json",
        env={"OPENCOBOT_READONLY": "1"}).stdout) == {"readonly": True, "source": "env"}
