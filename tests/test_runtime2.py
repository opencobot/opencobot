"""Tests for Phase 2 runtime/gateway integration (core/runtime.py).

No live model: all gateways here are mocks implementing either the
Phase 2 contract (``complete``/``escalate``) or the Phase 1 shape
(``chat`` only). Covers: direct execution with no gateway, gateway
planning, verification failure -> escalate once -> retry, escalation
needing approval (no retry), unusable plans, and the honest failure
of escalation on a Phase 1 gateway.
"""

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.runtime import Runtime  # noqa: E402


# -- fakes ------------------------------------------------------------------

class AllowAllPolicy:
    def __init__(self):
        self.killed = False

    def is_killed(self):
        return self.killed

    def check(self, token, tool_name, level, args, tainted):
        return {"allowed": True, "reason": "allowed", "needs_approval": False}


def make_echo_tool():
    return SimpleNamespace(
        level=0,
        schema={"type": "object", "properties": {"text": {"type": "string"}},
                "required": ["text"]},
        description="Echo text back",
        execute=lambda args, ctx: {"ok": True, "echo": args["text"]},
        verify=lambda args, result, ctx: (True, "echo verified"),
    )


class FlakyTool:
    """Fails verification the first time, passes from the second verify on."""

    def __init__(self):
        self.executions = 0
        self.verifications = 0

    def spec(self):
        tool = self

        def execute(args, ctx):
            tool.executions += 1
            return {"ok": True, "value": args.get("text", "")}

        def verify(args, result, ctx):
            tool.verifications += 1
            if tool.verifications == 1:
                return False, "first verification failed"
            return True, "verified on retry"

        return SimpleNamespace(
            level=1,
            schema={"type": "object",
                    "properties": {"text": {"type": "string"}},
                    "required": ["text"]},
            description="Flaky by design",
            execute=execute, verify=verify)


class MockGatewayContract:
    """Phase 2 contract gateway: complete() + escalate()."""

    def __init__(self, plan=None, escalate_mode="ok"):
        self.configs = [SimpleNamespace(name="mock-local", kind="ollama"),
                        SimpleNamespace(name="mock-cloud", kind="cloud")]
        self.plan = plan
        self.escalate_mode = escalate_mode  # "ok" | "needs_approval" | "fail"
        self.complete_calls = []
        self.escalate_calls = []

    def role_provider(self, role):
        return "mock-local"

    def fallback_chain(self, role, sensitivity):
        return list(self.configs)

    def complete(self, role, prompt, sensitivity, *, preapproved=False):
        self.complete_calls.append((role, prompt, sensitivity))
        if role == "PLANNER":
            text = self.plan if self.plan is not None else json.dumps(
                [{"tool": "echo", "args": {"text": "planned"}}])
            return {"text": text, "provider": "mock-local", "role": role,
                    "cost_estimate": 0, "needs_approval": False,
                    "escalated": False}
        return {"text": "verifier note", "provider": "mock-local", "role": role,
                "cost_estimate": 0, "needs_approval": False, "escalated": False}

    def escalate(self, role, prompt, sensitivity, reason, *, preapproved=False):
        self.escalate_calls.append((role, prompt, sensitivity, reason))
        if self.escalate_mode == "needs_approval":
            return {"text": None, "provider": "mock-cloud", "role": role,
                    "cost_estimate": 5, "needs_approval": True,
                    "escalated": False}
        if self.escalate_mode == "fail":
            return {"text": None, "provider": "mock-cloud", "role": role,
                    "cost_estimate": 0, "needs_approval": False,
                    "escalated": False, "ok": False, "error": "cloud down"}
        return {"text": "escalated verifier note", "provider": "mock-cloud",
                "role": role, "cost_estimate": 1, "needs_approval": False,
                "escalated": True}


class MockGatewayPhase1:
    """Phase 1 shape: chat() only, no complete()/escalate()."""

    def __init__(self):
        self.configs = [SimpleNamespace(name="ollama-local", kind="ollama"),
                        SimpleNamespace(name="cloud-x", kind="cloud")]
        self.chat_calls = 0
        self.plan_text = json.dumps(
            [{"tool": "echo", "args": {"text": "via chat"}}])

    def fallback_chain(self, role, sensitivity):
        return list(self.configs)

    def route(self, role, sensitivity):
        return self.configs[0]

    def chat(self, role, messages, sensitivity="public"):
        self.chat_calls += 1
        return {"ok": True, "text": self.plan_text,
                "provider": "ollama-local", "error": None}


@pytest.fixture()
def runtime(tmp_path):
    def build(gateway=None, registry=None):
        reg = registry if registry is not None else {"echo": make_echo_tool()}
        return Runtime(tmp_path / "state", policy=AllowAllPolicy(),
                       registry=reg, gateway=gateway)
    return build


# -- no gateway: Phase 1 behaviour unchanged ----------------------------------

def test_run_task_without_gateway_runs_direct_steps(runtime):
    rt = runtime()
    out = rt.run_task("say hi", token=None,
                      steps=[{"tool": "echo", "args": {"text": "hi"}}])
    assert out["ok"] is True and out["verified"] is True
    assert out["plan_source"] == "direct"
    assert out["escalated"] is False
    assert out["steps"][0]["tool"] == "echo"


def test_run_task_without_gateway_and_without_steps_fails_cleanly(runtime):
    rt = runtime()
    out = rt.run_task("do something", token=None)
    assert out["ok"] is False
    assert "no gateway" in out["error"]
    assert out["steps"] == []


def test_run_tool_ignores_gateway(runtime):
    # run_tool never consults the gateway, with or without one.
    gateway = MockGatewayContract()
    rt = runtime(gateway=gateway)
    out = rt.run_tool(None, "echo", {"text": "hi"})
    assert out["ok"] is True
    assert gateway.complete_calls == [] and gateway.escalate_calls == []


# -- gateway planning ---------------------------------------------------------

def test_run_task_with_gateway_uses_planner_plan(runtime):
    gateway = MockGatewayContract()
    rt = runtime(gateway=gateway)
    out = rt.run_task("say hi", token=None)
    assert out["ok"] is True
    assert out["plan_source"] == "gateway"
    assert out["steps"][0]["tool"] == "echo"
    assert gateway.complete_calls[0][0] == "PLANNER"


def test_gateway_plan_unusable_falls_back_to_caller_steps(runtime):
    gateway = MockGatewayContract(plan="this is not json at all")
    rt = runtime(gateway=gateway)
    out = rt.run_task("say hi", token=None,
                      steps=[{"tool": "echo", "args": {"text": "fallback"}}])
    assert out["ok"] is True
    assert out["plan_source"] == "direct (gateway plan unusable)"
    assert out["steps"][0]["tool"] == "echo"


def test_gateway_plan_unusable_without_caller_steps_fails_without_executing(runtime):
    gateway = MockGatewayContract(plan="not json")
    rt = runtime(gateway=gateway)
    out = rt.run_task("say hi", token=None)
    assert out["ok"] is False
    assert "unusable plan" in out["error"]
    assert out["steps"] == []


# -- escalation on verification failure ----------------------------------------

def test_verification_failure_escalates_once_and_retries(runtime):
    flaky = FlakyTool()
    plan = json.dumps([{"tool": "flaky", "args": {"text": "x"}}])
    gateway = MockGatewayContract(plan=plan)
    rt = runtime(gateway=gateway, registry={"flaky": flaky.spec()})
    out = rt.run_task("flaky job", token=None)
    assert out["ok"] is True and out["verified"] is True
    assert out["escalated"] is True
    assert len(gateway.escalate_calls) == 1
    assert gateway.escalate_calls[0][0] == "VERIFIER"
    assert "verification failed" in gateway.escalate_calls[0][3]
    assert flaky.executions == 2  # initial + exactly one retry
    assert out["steps"][0]["escalated"] is True
    assert out["steps"][0]["retry"]["verified"] is True


def test_escalation_needing_approval_does_not_retry(runtime):
    flaky = FlakyTool()
    plan = json.dumps([{"tool": "flaky", "args": {"text": "x"}}])
    gateway = MockGatewayContract(plan=plan, escalate_mode="needs_approval")
    rt = runtime(gateway=gateway, registry={"flaky": flaky.spec()})
    out = rt.run_task("flaky job", token=None)
    assert out["ok"] is False
    assert out["escalated"] is True
    assert flaky.executions == 1  # no retry without approval
    assert out["steps"][0]["escalation"]["needs_approval"] is True
    assert "retry" not in out["steps"][0]


def test_escalation_failure_reports_and_stops(runtime):
    flaky = FlakyTool()
    plan = json.dumps([{"tool": "flaky", "args": {"text": "x"}}])
    gateway = MockGatewayContract(plan=plan, escalate_mode="fail")
    rt = runtime(gateway=gateway, registry={"flaky": flaky.spec()})
    out = rt.run_task("flaky job", token=None)
    assert out["ok"] is False
    assert out["escalated"] is True
    assert flaky.executions == 1
    assert out["error"] is not None


def test_second_failure_after_retry_is_not_escalated_again(runtime):
    """A tool that keeps failing is retried once, never in a loop."""
    calls = {"n": 0}

    def execute(args, ctx):
        calls["n"] += 1
        return {"ok": True}

    spec = SimpleNamespace(
        level=1,
        schema={"type": "object", "properties": {}, "required": []},
        description="always fails verification",
        execute=execute,
        verify=lambda args, result, ctx: (False, "always bad"))
    plan = json.dumps([{"tool": "bad", "args": {}}])
    gateway = MockGatewayContract(plan=plan)
    rt = runtime(gateway=gateway, registry={"bad": spec})
    out = rt.run_task("bad job", token=None)
    assert out["ok"] is False
    assert len(gateway.escalate_calls) == 1
    assert calls["n"] == 2


# -- Phase 1 gateway shape (chat only) -----------------------------------------

def test_phase1_gateway_plans_via_chat(runtime):
    gateway = MockGatewayPhase1()
    rt = runtime(gateway=gateway)
    out = rt.run_task("say hi", token=None)
    assert out["ok"] is True
    assert out["plan_source"] == "gateway"
    assert gateway.chat_calls == 1


def test_phase1_gateway_escalation_fails_honestly_without_retry(runtime):
    flaky = FlakyTool()
    gateway = MockGatewayPhase1()
    gateway.plan_text = "not a plan"  # force the caller-supplied steps
    rt = runtime(gateway=gateway, registry={"flaky": flaky.spec()})
    out = rt.run_task("flaky job", token=None,
                      steps=[{"tool": "flaky", "args": {"text": "x"}}])
    assert out["ok"] is False
    assert flaky.executions == 1  # no silent re-call of the same provider
    assert "escalat" in (out["steps"][0]["escalation"]["error"] or "")
