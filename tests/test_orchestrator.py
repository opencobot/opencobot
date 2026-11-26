"""Tests for core.orchestrator (ADR-011, Phase 3).

Mock gateway + fake runtime; no network, no real models. One test
uses the real Runtime + real tools registry to prove the integration
wiring writes a verified file.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from core.memory import Memory  # noqa: E402
from core.orchestrator import (  # noqa: E402
    Orchestrator,
    clamp_sensitivity,
    load_orchestrator_config,
    sensitivity_strictness,
)
from core.runtime import Runtime  # noqa: E402


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
        return self._role_providers.get(role)

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


class FakeRuntime:
    """Records run_tool calls; per-tool results configurable."""

    def __init__(self, results=None):
        self.calls: list[tuple] = []
        self.results = results or {}

    def run_tool(self, token, tool_name, args, tainted=False):
        self.calls.append((token, tool_name, args, tainted))
        result = self.results.get(tool_name)
        if callable(result):
            return result(token, tool_name, args, tainted)
        if isinstance(result, dict):
            return dict(result)
        return {"ok": True, "verified": True,
                "decision": {"allowed": True, "reason": "allowed"},
                "result": {}, "evidence": "fake ok"}


def _make(tmp_path, gateway, runtime=None, **kwargs):
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    kwargs.setdefault("config", {"architect": "arch", "workers": ["w1"]})
    return Orchestrator(gateway, runtime=runtime, workspace=ws,
                        token={"folders": [str(ws)]}, **kwargs)


def _file_subtask(path="out.txt", provider="w1", **extra):
    subtask = {
        "title": "write file", "goal": "write the file",
        "context": "some context", "provider": provider,
        "output": {"kind": "file", "path": path},
        "checks": [], "sensitivity": "public", "verify_model": False,
        "task": "build the thing",
    }
    subtask.update(extra)
    return subtask


# ---------------------------------------------------------------- config

def test_architect_selection_from_config(tmp_path):
    gw = FakeGateway(_configs("arch", "w1"))
    orch = _make(tmp_path, gw, config={"architect": "arch", "workers": ["w1"]})
    assert orch.architect == "arch"
    assert gw.role_provider("PLANNER") == "arch"


def test_architect_unknown_provider_raises(tmp_path):
    gw = FakeGateway(_configs("arch", "w1"))
    with pytest.raises(ValueError, match="unknown architect provider"):
        _make(tmp_path, gw, config={"architect": "nope", "workers": []})


def test_architect_defaults_to_planner_role(tmp_path):
    gw = FakeGateway(_configs("arch", "w1", "local"))
    gw.set_role_provider("PLANNER", "local")
    orch = _make(tmp_path, gw, config={"architect": None, "workers": []})
    assert orch.architect == "local"


def test_load_orchestrator_config_file(tmp_path):
    cfg = tmp_path / "gateway.json"
    cfg.write_text(json.dumps({
        "providers": [],
        "orchestrator": {"architect": "arch", "workers": ["w1", "w2"]},
    }), encoding="utf-8")
    loaded = load_orchestrator_config(str(cfg))
    assert loaded == {"architect": "arch", "workers": ["w1", "w2"]}


def test_load_orchestrator_config_missing_file_defaults(tmp_path):
    assert load_orchestrator_config(str(tmp_path / "nope.json")) == {
        "architect": None, "workers": []}


def test_load_orchestrator_config_bad_types_raise(tmp_path):
    cfg = tmp_path / "gateway.json"
    cfg.write_text(json.dumps({
        "providers": [],
        "orchestrator": {"architect": 42},
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="architect"):
        load_orchestrator_config(str(cfg))


def test_sensitivity_clamp_only_tightens():
    assert sensitivity_strictness("secret") == 3
    assert sensitivity_strictness("bogus-label") == 3  # fail closed
    assert clamp_sensitivity("public", "secret") == "secret"
    assert clamp_sensitivity("secret", "public") == "secret"
    assert clamp_sensitivity("personal", "public") == "personal"


# ---------------------------------------------------------------- decompose

def test_decompose_scoped_subtasks(tmp_path):
    plan = _plan_json([
        {"title": "A", "goal": "do A", "context": "CONTEXT-A",
         "provider": "w1", "output": {"kind": "text"}},
        {"title": "B", "goal": "do B", "context": "CONTEXT-B",
         "provider": "w1", "output": {"kind": "text"}},
    ])
    gw = FakeGateway(_configs("arch", "w1"), scripts={
        "PLANNER": [_ok(plan, "arch")],
        "EXECUTOR": [_ok("out-A", "w1"), _ok("out-B", "w1")],
    })
    orch = _make(tmp_path, gw)
    subtasks = orch.decompose("build the thing")
    assert [s["title"] for s in subtasks] == ["A", "B"]
    for subtask in subtasks:
        orch.dispatch(subtask)
    prompts = [c[1] for c in gw.calls if c[0] == "EXECUTOR"]
    assert len(prompts) == 2
    assert "CONTEXT-A" in prompts[0] and "CONTEXT-B" not in prompts[0]
    assert "CONTEXT-B" in prompts[1] and "CONTEXT-A" not in prompts[1]


def test_decompose_retry_then_fallback(tmp_path):
    gw = FakeGateway(_configs("arch", "w1"), scripts={
        "PLANNER": [_ok("not json at all", "arch"),
                    _ok("still not json", "arch")],
    })
    orch = _make(tmp_path, gw)
    subtasks = orch.decompose("build the thing")
    assert len(subtasks) == 1
    assert subtasks[0]["goal"] == "build the thing"
    assert subtasks[0]["output"]["kind"] == "text"


def test_decompose_needs_approval_falls_back(tmp_path):
    gw = FakeGateway(_configs("arch", "w1"), scripts={
        "PLANNER": [{"text": None, "provider": "arch", "role": "PLANNER",
                     "cost_estimate": 1.0, "needs_approval": True,
                     "escalated": False}],
    })
    orch = _make(tmp_path, gw)
    subtasks = orch.decompose("build the thing")
    assert len(subtasks) == 1
    assert subtasks[0].get("decompose_note") == "architect call needs approval"


# ---------------------------------------------------------------- dispatch

def test_dispatch_unknown_hint_recorded_and_role_default_used(tmp_path):
    gw = FakeGateway(_configs("arch", "w1"), scripts={
        "EXECUTOR": [_ok("done", "w1")],
    })
    gw.set_role_provider("EXECUTOR", "w1")
    orch = _make(tmp_path, gw)
    result = orch.dispatch(_file_subtask(provider="ghost"))
    assert result["status"] == "done"
    assert "unknown worker provider hint" in result["hint_note"]
    assert result["worker"] == "w1"


def test_dispatch_needs_approval_not_called(tmp_path):
    gw = FakeGateway(_configs("arch", "w1"), scripts={
        "EXECUTOR": [{"text": None, "provider": "w1", "role": "EXECUTOR",
                      "cost_estimate": 2.5, "needs_approval": True,
                      "escalated": False}],
    })
    orch = _make(tmp_path, gw)
    result = orch.dispatch(_file_subtask())
    assert result["status"] == "needs_approval"
    assert result["cost_estimate"] == 2.5


def test_dispatch_budget_exhaustion_queues(tmp_path):
    gw = FakeGateway(_configs("arch", "w1"), scripts={
        "EXECUTOR": [{"text": None, "provider": None, "role": "EXECUTOR",
                      "cost_estimate": 0.0, "needs_approval": False,
                      "escalated": False,
                      "error": "no provider available or budget exceeded"}],
    })
    orch = _make(tmp_path, gw)
    result = orch.dispatch(_file_subtask())
    assert result["status"] == "queued"
    assert "budget exceeded" in result["reason"]


def test_dispatch_other_error_fails(tmp_path):
    gw = FakeGateway(_configs("arch", "w1"), scripts={
        "EXECUTOR": [{"text": None, "provider": None, "role": "EXECUTOR",
                      "cost_estimate": 0.0, "needs_approval": False,
                      "escalated": False, "error": "model exploded"}],
    })
    orch = _make(tmp_path, gw)
    result = orch.dispatch(_file_subtask())
    assert result["status"] == "failed"
    assert "model exploded" in result["error"]


# ---------------------------------------------------------------- verify

def test_failed_verification_never_integrated(tmp_path):
    plan = _plan_json([{
        "title": "write file", "goal": "write it", "context": "",
        "provider": "w1", "output": {"kind": "file", "path": "out.txt"},
        "checks": [{"tool": "run_command",
                    "args": {"command": ["true"]}}],
    }])
    gw = FakeGateway(_configs("arch", "w1"), scripts={
        "PLANNER": [_ok(plan, "arch")],
        "EXECUTOR": [_ok("file content here", "w1")],
    })
    runtime = FakeRuntime(results={
        "run_command": {"ok": False, "verified": False,
                        "decision": {"allowed": True},
                        "result": {"error": "check failed"},
                        "evidence": "check failed"},
    })
    orch = _make(tmp_path, gw, runtime=runtime)
    summary = orch.run("build the thing")
    assert summary["failed"] == ["write file"]
    assert summary["integrated"] == []
    assert not [c for c in runtime.calls if c[1] in ("write_file", "create_file")]


def test_verify_model_review_rejects(tmp_path):
    gw = FakeGateway(_configs("arch", "w1"), scripts={
        "VERIFIER": [_ok(json.dumps({"verdict": "fail",
                                     "reason": "looks wrong"}), "arch")],
    })
    orch = _make(tmp_path, gw)
    verdict = orch.verify(
        _file_subtask(verify_model=True), "some content")
    assert verdict["passed"] is False
    assert "verifier rejected" in verdict["evidence"]


def test_verify_model_review_accepts(tmp_path):
    gw = FakeGateway(_configs("arch", "w1"), scripts={
        "VERIFIER": [_ok(json.dumps({"verdict": "pass"}), "arch")],
    })
    orch = _make(tmp_path, gw)
    verdict = orch.verify(
        _file_subtask(verify_model=True), "some content")
    assert verdict["passed"] is True
    assert "model-review" in verdict["method"]


def test_verify_rejects_empty_output_and_absolute_path(tmp_path):
    gw = FakeGateway(_configs("arch", "w1"))
    orch = _make(tmp_path, gw)
    assert orch.verify(_file_subtask(), "")["passed"] is False
    assert orch.verify(_file_subtask(path="/etc/passwd"),
                        "x")["passed"] is False


def test_verify_rejects_dotdot_escape_path(tmp_path):
    # Same gap as the Windows "/etc/passwd" case, on the Linux side:
    # "../escape.txt" is relative, so the old is_absolute()-only
    # check passed it while integrate() refused it.
    gw = FakeGateway(_configs("arch", "w1"))
    orch = _make(tmp_path, gw)
    verdict = orch.verify(_file_subtask(path="../escape.txt"), "x")
    assert verdict["passed"] is False
    assert "escapes the workspace" in verdict["evidence"]
    verdict = orch.verify(_file_subtask(path="sub/../../escape.txt"), "x")
    assert verdict["passed"] is False


def test_resolve_in_workspace_accepts_and_rejects(tmp_path):
    gw = FakeGateway(_configs("arch", "w1"))
    orch = _make(tmp_path, gw)
    target = orch._resolve_in_workspace("sub/file.txt")
    assert target is not None
    assert target.relative_to(orch.workspace) == Path("sub/file.txt")
    assert orch._resolve_in_workspace("out.txt") is not None
    assert orch._resolve_in_workspace("/etc/passwd") is None
    assert orch._resolve_in_workspace("../escape.txt") is None
    assert orch._resolve_in_workspace("sub/../../escape.txt") is None
    assert orch._resolve_in_workspace("") is None
    assert orch._resolve_in_workspace("   ") is None
    assert orch._resolve_in_workspace(None) is None


# ---------------------------------------------------------------- integrate

def test_integrate_refuses_without_passing_verdict(tmp_path):
    runtime = FakeRuntime()
    gw = FakeGateway(_configs("arch", "w1"))
    orch = _make(tmp_path, gw, runtime=runtime)
    out = orch.integrate(_file_subtask(), "content",
                         {"passed": False, "method": "shape",
                          "evidence": "bad"})
    assert out["ok"] is False
    assert runtime.calls == []


def test_integrate_refuses_outside_workspace(tmp_path):
    runtime = FakeRuntime()
    gw = FakeGateway(_configs("arch", "w1"))
    orch = _make(tmp_path, gw, runtime=runtime)
    verdict = {"passed": True, "method": "shape", "evidence": "ok"}
    for bad in ("../evil.txt", "/abs/evil.txt", "sub/../../evil.txt"):
        out = orch.integrate(_file_subtask(path=bad), "content", verdict)
        assert out["ok"] is False, bad
    assert runtime.calls == []


def test_integrate_refuses_without_runtime(tmp_path):
    gw = FakeGateway(_configs("arch", "w1"))
    orch = _make(tmp_path, gw, runtime=None)
    out = orch.integrate(_file_subtask(), "content",
                         {"passed": True, "method": "shape",
                          "evidence": "ok"})
    assert out["ok"] is False
    assert "no runtime" in out["error"]


def test_integrate_marks_worker_output_tainted(tmp_path):
    runtime = FakeRuntime()
    gw = FakeGateway(_configs("arch", "w1"))
    orch = _make(tmp_path, gw, runtime=runtime)
    out = orch.integrate(_file_subtask(), "content",
                         {"passed": True, "method": "shape",
                          "evidence": "ok"})
    assert out["ok"] is True
    assert out["integrated"] is True
    assert out["tool"] == "create_file"  # file does not exist yet
    assert runtime.calls[0][3] is True  # tainted=True (R-026)


# ---------------------------------------------------------------- run / conflicts

def test_conflict_resolution_picks_winner(tmp_path):
    plan = _plan_json([
        {"title": "A", "goal": "a", "context": "", "provider": "w1",
         "output": {"kind": "file", "path": "same.txt"}},
        {"title": "B", "goal": "b", "context": "", "provider": "w1",
         "output": {"kind": "file", "path": "same.txt"}},
    ])
    gw = FakeGateway(_configs("arch", "w1"), scripts={
        "PLANNER": [_ok(plan, "arch"),
                    _ok(json.dumps({"winner": 1, "reason": "B better"}),
                        "arch")],
        "EXECUTOR": [_ok("content-A", "w1"), _ok("content-B", "w1")],
    })
    runtime = FakeRuntime()
    orch = _make(tmp_path, gw, runtime=runtime)
    summary = orch.run("build the thing")
    assert summary["integrated"] == ["B"]
    assert summary["conflict_lost"] == ["A"]
    writes = [c for c in runtime.calls if c[1] in ("write_file", "create_file")]
    assert len(writes) == 1
    assert writes[0][2]["content"] == "content-B"


def test_conflict_unresolved_integrates_nothing(tmp_path):
    plan = _plan_json([
        {"title": "A", "goal": "a", "context": "", "provider": "w1",
         "output": {"kind": "file", "path": "same.txt"}},
        {"title": "B", "goal": "b", "context": "", "provider": "w1",
         "output": {"kind": "file", "path": "same.txt"}},
    ])
    gw = FakeGateway(_configs("arch", "w1"), scripts={
        "PLANNER": [_ok(plan, "arch"), _ok("not json", "arch")],
        "EXECUTOR": [_ok("content-A", "w1"), _ok("content-B", "w1")],
    })
    runtime = FakeRuntime()
    orch = _make(tmp_path, gw, runtime=runtime)
    summary = orch.run("build the thing")
    assert summary["integrated"] == []
    assert sorted(summary["failed"]) == ["A", "B"]
    assert not [c for c in runtime.calls if c[1] in ("write_file", "create_file")]


def test_sensitivity_clamped_to_parent(tmp_path):
    plan = _plan_json([{
        "title": "A", "goal": "a", "context": "", "provider": "w1",
        "output": {"kind": "text"}, "sensitivity": "public",
    }])
    gw = FakeGateway(_configs("arch", "w1"), scripts={
        "PLANNER": [_ok(plan, "arch")],
        "EXECUTOR": [_ok("done", "w1")],
    })
    orch = _make(tmp_path, gw)
    orch.run("secret task", sensitivity="secret")
    exec_calls = [c for c in gw.calls if c[0] == "EXECUTOR"]
    assert exec_calls and exec_calls[0][2] == "secret"


# ---------------------------------------------------------------- queue / memory

def test_budget_queue_and_retry(tmp_path):
    plan = _plan_json([{
        "title": "write file", "goal": "write it", "context": "",
        "provider": "w1", "output": {"kind": "file", "path": "out.txt"},
    }])
    budget_error = {"text": None, "provider": None, "role": "EXECUTOR",
                    "cost_estimate": 0.0, "needs_approval": False,
                    "escalated": False,
                    "error": "no provider available or budget exceeded"}
    gw = FakeGateway(_configs("arch", "w1"), scripts={
        "PLANNER": [_ok(plan, "arch")],
        "EXECUTOR": [budget_error, _ok("file content", "w1")],
    })
    memory = Memory(tmp_path / "state")
    runtime = FakeRuntime()
    orch = _make(tmp_path, gw, runtime=runtime, memory=memory)
    summary = orch.run("build the thing")
    assert summary["queued"] == ["write file"]
    assert summary["ok"] is False
    retry = orch.retry_queued(summary["run_id"])
    assert retry["ok"] is True
    assert retry["retried"] == ["write file"]
    assert retry["still_queued"] == []
    writes = [c for c in runtime.calls if c[1] in ("write_file", "create_file")]
    assert len(writes) == 1
    assert writes[0][2]["content"] == "file content"


def test_memory_records_run_without_output_text(tmp_path):
    plan = _plan_json([{
        "title": "write file", "goal": "write it", "context": "",
        "provider": "w1", "output": {"kind": "file", "path": "out.txt"},
    }])
    gw = FakeGateway(_configs("arch", "w1"), scripts={
        "PLANNER": [_ok(plan, "arch")],
        "EXECUTOR": [_ok("SECRET-OUTPUT-TEXT", "w1")],
    })
    memory = Memory(tmp_path / "state")
    orch = _make(tmp_path, gw, runtime=FakeRuntime(), memory=memory)
    summary = orch.run("build the thing")
    assert summary["ok"] is True
    stored = memory.get(f"orchestrator:run:{summary['run_id']}")
    assert stored is not None
    assert "SECRET-OUTPUT-TEXT" not in json.dumps(stored)
    recalled = orch.recall()
    assert recalled and recalled[0]["run_id"] == summary["run_id"]


def test_retry_queued_without_memory_errors(tmp_path):
    gw = FakeGateway(_configs("arch", "w1"))
    orch = _make(tmp_path, gw, memory=None)
    out = orch.retry_queued("deadbeef")
    assert out["ok"] is False
    assert "no memory" in out["error"]


# ---------------------------------------------------------------- real runtime

class _AllowPolicy:
    """L0-L2 allowed; mirrors tests/test_runtime.py StubPolicy."""

    def is_killed(self):
        return False

    def check(self, token, tool_name, level, args, tainted=False, **kwargs):
        if level >= 3:
            return {"allowed": False, "reason": "approval required",
                    "needs_approval": True}
        return {"allowed": True, "reason": "allowed",
                "needs_approval": False}


def test_real_runtime_integration_writes_verified_file(tmp_path):
    plan = _plan_json([{
        "title": "write file", "goal": "write it", "context": "",
        "provider": "w1", "output": {"kind": "file", "path": "out.txt"},
    }])
    gw = FakeGateway(_configs("arch", "w1"), scripts={
        "PLANNER": [_ok(plan, "arch")],
        "EXECUTOR": [_ok("hello from worker", "w1")],
    })
    ws = tmp_path / "ws"
    ws.mkdir()
    state = tmp_path / "state"
    runtime = Runtime(state_dir=state, policy=_AllowPolicy())
    memory = Memory(state)
    orch = Orchestrator(gw, runtime=runtime, memory=memory, workspace=ws,
                        token={"folders": [str(ws)]},
                        config={"architect": "arch", "workers": ["w1"]})
    summary = orch.run("build the thing")
    assert summary["ok"] is True
    assert summary["integrated"] == ["write file"]
    assert (ws / "out.txt").read_text(encoding="utf-8") == "hello from worker"
