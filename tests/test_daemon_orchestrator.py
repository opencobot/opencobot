"""Tests for the daemon orchestrator ops (ADR-011 (d)).

``Daemon.handle_request`` drives a real Orchestrator over a scripted
(fake) gateway and a real Runtime with an allow-all fake policy
client; no network, no real models, no real policyd. The ops under
test: ``orchestrator_run`` (synchronous), ``orchestrator_status``
(read-only memory read) and ``orchestrator_retry``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from core.daemon import Daemon  # noqa: E402
from core.memory import Memory  # noqa: E402


# ---------------------------------------------------------------- fakes

def _configs(*names):
    return [SimpleNamespace(name=n) for n in names]


class FakeGateway:
    """Duck-typed gateway: scripted complete() per role."""

    def __init__(self, configs, scripts=None):
        self.configs = list(configs)
        self._role_providers: dict[str, str] = {}
        self.calls: list[tuple] = []
        self.scripts = scripts or {}

    def set_role_provider(self, role, name):
        if name not in [c.name for c in self.configs]:
            raise ValueError(f"unknown provider: {name!r}")
        self._role_providers[role] = name

    def role_provider(self, role):
        # Mirror the real Gateway: an assigned provider wins, else the
        # first configured provider (the local-first chain's head).
        if role in self._role_providers:
            return self._role_providers[role]
        return self.configs[0].name if self.configs else None

    def complete(self, role, prompt, sensitivity, **kwargs):
        self.calls.append((role, prompt, sensitivity))
        script = self.scripts.get(role)
        if callable(script):
            return script(role, prompt, sensitivity)
        if isinstance(script, list) and script:
            return script.pop(0)
        return {"text": "{}", "provider": self._role_providers.get(role),
                "role": role, "cost_estimate": 0.0,
                "needs_approval": False, "escalated": False}


def _ok(text="ok", provider="w1"):
    return {"text": text, "provider": provider, "role": "EXECUTOR",
            "cost_estimate": 0.0, "needs_approval": False,
            "escalated": False}


def _plan_json(subtasks):
    return json.dumps({"subtasks": subtasks})


def _file_subtask(path="out.txt", provider="w1"):
    return {
        "title": "write file", "goal": "write the file",
        "context": "some context", "provider": provider,
        "output": {"kind": "file", "path": path},
        "checks": [], "sensitivity": "public", "verify_model": False,
    }


class _AllowPolicy:
    """Policy client double: policyd reachable, everything allowed."""

    def __init__(self):
        self.checks: list[tuple] = []

    def is_killed(self):
        return False

    def status(self):
        return {"reachable": True, "killed": False}

    def ping(self):
        return {"reachable": True}

    def get_readonly(self):
        return False

    def check(self, token, tool_name, level, args, tainted=False,
              network_call=False):
        self.checks.append((tool_name, level, args))
        return {"allowed": True, "reason": "allowed",
                "needs_approval": False}


class _UnreachablePolicy(_AllowPolicy):
    """Policyd is down: every liveness probe says unreachable."""

    def ping(self):
        return {"reachable": False}

    def status(self):
        return {"reachable": False, "killed": False}


# ---------------------------------------------------------------- helpers

@pytest.fixture()
def env(tmp_path, monkeypatch):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    ws = tmp_path / "ws"
    ws.mkdir()
    # Hermetic gateway config: the daemon's Orchestrator reads the
    # "orchestrator" section of gateway.json; point it at a tmp file
    # with no such section so the ambient ~/.config file cannot leak
    # into these tests (architect then falls through to the fake
    # gateway's PLANNER default).
    gw_config = tmp_path / "gateway.json"
    gw_config.write_text(json.dumps({"providers": []}))
    monkeypatch.setenv("OPENCOBOT_GATEWAY_CONFIG", str(gw_config))
    policy = _AllowPolicy()
    monkeypatch.setattr(Daemon, "_policy_client", lambda self: policy)
    return {"state_dir": state_dir, "ws": ws, "policy": policy}


def _daemon(env, gateway):
    return Daemon(state_dir=env["state_dir"], gateway=gateway)


def _run_req(daemon, ws, **extra):
    req = {"auth": daemon.auth_token, "op": "orchestrator_run",
           "task": "build the thing", "workspace": str(ws),
           "token": {"folders": [str(ws)]}}
    req.update(extra)
    return daemon.handle_request(req)


# ---------------------------------------------------------------- run

def test_run_file_subtask_integrates_and_records(env):
    gw = FakeGateway(_configs("arch", "w1"), scripts={
        "PLANNER": [_ok(_plan_json([_file_subtask()]), "arch")],
        "EXECUTOR": [_ok("hello file", "w1")],
    })
    daemon = _daemon(env, gw)
    reply = _run_req(daemon, env["ws"])
    assert reply["ok"] is True
    run = reply["run"]
    assert run["ok"] is True
    assert run["integrated"] == ["write file"]
    assert (env["ws"] / "out.txt").read_text() == "hello file"
    # The run is recorded in memory: status by run_id finds it.
    status = daemon.handle_request(
        {"auth": daemon.auth_token, "op": "orchestrator_status",
         "run_id": run["run_id"]})
    assert status["ok"] is True
    assert status["run"]["run_id"] == run["run_id"]
    assert status["run"]["task"] == "build the thing"
    # ... and the policy client saw the integration tool call
    # (create_file — the file did not exist yet — Level 2, absolute
    # workspace path, worker output as content).
    assert ("create_file", 2,
            {"path": str(env["ws"] / "out.txt"),
             "content": "hello file"}) \
        in [(c[0], c[1], c[2]) for c in env["policy"].checks]


def test_run_text_subtask_done(env):
    gw = FakeGateway(_configs("arch", "w1"), scripts={
        "PLANNER": [_ok(_plan_json([{
            "title": "say hi", "goal": "say hi", "context": "",
            "provider": "w1", "output": {"kind": "text"},
            "checks": [], "sensitivity": "public",
            "verify_model": False}]), "arch")],
        "EXECUTOR": [_ok("hi there", "w1")],
    })
    daemon = _daemon(env, gw)
    reply = _run_req(daemon, env["ws"])
    assert reply["ok"] is True
    assert reply["run"]["ok"] is True
    assert reply["run"]["done"] == ["say hi"]
    assert reply["run"]["integrated"] == []


def test_run_requires_auth(env):
    gw = FakeGateway(_configs("arch", "w1"))
    daemon = _daemon(env, gw)
    reply = daemon.handle_request(
        {"auth": "wrong", "op": "orchestrator_run", "task": "x"})
    assert reply["ok"] is False
    assert reply["error"] == "unauthorized"
    assert gw.calls == []


def test_run_validates_inputs(env):
    gw = FakeGateway(_configs("arch", "w1"))
    daemon = _daemon(env, gw)
    assert _run_req(daemon, env["ws"], task="")["ok"] is False
    assert _run_req(daemon, env["ws"], task=42)["ok"] is False
    assert _run_req(daemon, env["ws"], sensitivity="topsecret")["ok"] is False
    assert _run_req(daemon, env["ws"], architect="nope")["ok"] is False
    assert _run_req(daemon, env["ws"], workers="w1")["ok"] is False
    assert _run_req(daemon, env["ws"], workers=["w1", 7])["ok"] is False
    # No model call was made for any rejected request.
    assert gw.calls == []


def test_run_refuses_without_policyd(env, monkeypatch):
    monkeypatch.setattr(Daemon, "_policy_client",
                        lambda self: _UnreachablePolicy())
    gw = FakeGateway(_configs("arch", "w1"), scripts={
        "PLANNER": [_ok(_plan_json([_file_subtask()]), "arch")],
        "EXECUTOR": [_ok("hello file", "w1")],
    })
    daemon = _daemon(env, gw)
    reply = _run_req(daemon, env["ws"])
    assert reply["ok"] is False
    assert reply["error"] == "policyd unavailable"
    # Fail closed before any model call: nothing was dispatched.
    assert gw.calls == []
    assert not (env["ws"] / "out.txt").exists()


# ---------------------------------------------------------------- status

def test_status_by_run_id_and_project(env):
    gw = FakeGateway(_configs("arch", "w1"), scripts={
        "PLANNER": [_ok(_plan_json([_file_subtask()]), "arch")],
        "EXECUTOR": [_ok("hello file", "w1")],
    })
    daemon = _daemon(env, gw)
    run = _run_req(daemon, env["ws"])["run"]
    by_id = daemon.handle_request(
        {"auth": daemon.auth_token, "op": "orchestrator_status",
         "run_id": run["run_id"]})
    assert by_id["ok"] is True
    assert by_id["run"]["run_id"] == run["run_id"]
    # Project defaults to the workspace name ("ws").
    by_project = daemon.handle_request(
        {"auth": daemon.auth_token, "op": "orchestrator_status",
         "project": "ws"})
    assert by_project["ok"] is True
    assert by_project["run"]["run_id"] == run["run_id"]
    # Unknown run / project / neither: clear errors, no crash.
    assert daemon.handle_request(
        {"auth": daemon.auth_token, "op": "orchestrator_status",
         "run_id": "nope"})["ok"] is False
    assert daemon.handle_request(
        {"auth": daemon.auth_token, "op": "orchestrator_status",
         "project": "nope"})["ok"] is False
    assert daemon.handle_request(
        {"auth": daemon.auth_token,
         "op": "orchestrator_status"})["ok"] is False


def test_status_needs_no_policyd(env, monkeypatch):
    gw = FakeGateway(_configs("arch", "w1"), scripts={
        "PLANNER": [_ok(_plan_json([_file_subtask()]), "arch")],
        "EXECUTOR": [_ok("hello file", "w1")],
    })
    daemon = _daemon(env, gw)
    run = _run_req(daemon, env["ws"])["run"]
    # Policyd goes down; the read-only status op still answers.
    monkeypatch.setattr(Daemon, "_policy_client",
                        lambda self: _UnreachablePolicy())
    status = daemon.handle_request(
        {"auth": daemon.auth_token, "op": "orchestrator_status",
         "run_id": run["run_id"]})
    assert status["ok"] is True
    assert status["run"]["run_id"] == run["run_id"]


# ---------------------------------------------------------------- retry

def test_retry_queued_then_integrates(env):
    calls = {"n": 0}

    def executor(role, prompt, sensitivity):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"text": None, "provider": None, "role": "EXECUTOR",
                    "cost_estimate": 0.0, "needs_approval": False,
                    "escalated": False,
                    "error": "no provider available or budget exceeded"}
        return _ok("hello file", "w1")

    gw = FakeGateway(_configs("arch", "w1"), scripts={
        "PLANNER": [_ok(_plan_json([_file_subtask()]), "arch")],
        "EXECUTOR": executor,
    })
    daemon = _daemon(env, gw)
    first = _run_req(daemon, env["ws"])["run"]
    assert first["queued"] == ["write file"]
    assert not (env["ws"] / "out.txt").exists()
    reply = daemon.handle_request(
        {"auth": daemon.auth_token, "op": "orchestrator_retry",
         "run_id": first["run_id"], "workspace": str(env["ws"]),
         "token": {"folders": [str(env["ws"])]}})
    assert reply["ok"] is True
    assert reply["retry"]["ok"] is True
    assert reply["retry"]["retried"] == ["write file"]
    assert reply["retry"]["still_queued"] == []
    assert (env["ws"] / "out.txt").read_text() == "hello file"


def test_retry_validates_and_refuses(env, monkeypatch):
    gw = FakeGateway(_configs("arch", "w1"))
    daemon = _daemon(env, gw)
    assert daemon.handle_request(
        {"auth": daemon.auth_token, "op": "orchestrator_retry"})["ok"] is False
    # Unknown run_id: the op ran, but the retry payload reports the
    # missing run (op-level ok True, retry-level ok False).
    reply = daemon.handle_request(
        {"auth": daemon.auth_token, "op": "orchestrator_retry",
         "run_id": "nope", "workspace": str(env["ws"]),
         "token": {"folders": [str(env["ws"])]}})
    assert reply["ok"] is True
    assert reply["retry"]["ok"] is False
    assert "no stored run" in reply["retry"]["error"]
    # Policyd down: refused before any model call.
    monkeypatch.setattr(Daemon, "_policy_client",
                        lambda self: _UnreachablePolicy())
    reply = daemon.handle_request(
        {"auth": daemon.auth_token, "op": "orchestrator_retry",
         "run_id": "whatever", "workspace": str(env["ws"]),
         "token": {"folders": [str(env["ws"])]}})
    assert reply["ok"] is False
    assert reply["error"] == "policyd unavailable"
    assert gw.calls == []


def test_run_records_without_output_text(env):
    """Worker output text is never persisted (R-026)."""
    gw = FakeGateway(_configs("arch", "w1"), scripts={
        "PLANNER": [_ok(_plan_json([_file_subtask()]), "arch")],
        "EXECUTOR": [_ok("SECRET-OUTPUT-DO-NOT-STORE", "w1")],
    })
    daemon = _daemon(env, gw)
    run = _run_req(daemon, env["ws"])["run"]
    stored = Memory(env["state_dir"]).get(f"orchestrator:run:{run['run_id']}")
    assert stored is not None
    assert "SECRET-OUTPUT-DO-NOT-STORE" not in json.dumps(stored)
