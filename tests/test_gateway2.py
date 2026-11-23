"""Tests for the Phase 2 gateway: roles, hybrid local/cloud division,
escalation, budgets, circuit breaker, privacy labels, CLI providers.
No network and no real CLIs: mock transports + fake scripts on PATH."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from core.cli_providers import builtin_cli_config  # noqa: E402
from core.model_gateway import (  # noqa: E402
    DEFAULT_ROLE_ASSIGNMENT,
    ROLES,
    ROUTING_TABLE,
    Gateway,
    ProviderConfig,
)
from core.usage import UsageStore  # noqa: E402


def local_config(name="ollama-local"):
    return ProviderConfig(name, "ollama", "http://localhost:11434", "llama3.1")


def cloud_config(name="cloud-x", cost=0.05):
    return ProviderConfig(
        name, "cloud", "https://api.example.invalid/v1", "big-model",
        cost_per_call=cost,
    )


def recording_transport(calls):
    def transport(config, payload, headers):
        calls.append(config.name)
        return {"text": f"{config.name}-reply"}
    return transport


def gateway_with(calls, configs=None, **kwargs):
    configs = configs if configs is not None else [local_config(), cloud_config()]
    return Gateway(configs=configs, transport=recording_transport(calls), **kwargs)


def write_script(bin_dir: Path, name: str, body: str) -> Path:
    path = bin_dir / name
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(0o755)
    return path


@pytest.fixture
def bin_dir(tmp_path, monkeypatch):
    d = tmp_path / "bin"
    d.mkdir()
    monkeypatch.setenv("PATH", str(d) + os.pathsep + os.environ.get("PATH", ""))
    return d


# ---------------------------------------------------------------- roles

def test_roles_and_default_assignment_cover_all_roles():
    assert set(ROLES) == {
        "ROUTER", "PLANNER", "EXECUTOR", "GROUNDER", "VERIFIER", "SUMMARIZER",
    }
    assert set(DEFAULT_ROLE_ASSIGNMENT) == set(ROLES)
    for role, info in DEFAULT_ROLE_ASSIGNMENT.items():
        assert info["provider_class"], role
        assert info["why"], role
        assert info["escalation_trigger"], role
    # The division itself: cheap/local roles never escalate to cloud.
    assert DEFAULT_ROLE_ASSIGNMENT["ROUTER"]["provider_class"] == "local-small"
    assert DEFAULT_ROLE_ASSIGNMENT["SUMMARIZER"]["provider_class"] == "local-small"
    assert DEFAULT_ROLE_ASSIGNMENT["GROUNDER"]["provider_class"] == "local-vision"
    assert DEFAULT_ROLE_ASSIGNMENT["PLANNER"]["provider_class"] == "strongest-available"
    assert "high complexity" in DEFAULT_ROLE_ASSIGNMENT["PLANNER"]["escalation_trigger"]


def test_routing_table_covers_tasks():
    for task in ("classification", "simple_tool_call", "summary",
                 "grounding", "planning", "verification"):
        assert task in ROUTING_TABLE
        assert ROUTING_TABLE[task]["role"] in ROLES
        assert ROUTING_TABLE[task]["default_provider_class"]
        assert ROUTING_TABLE[task]["escalation_trigger"]


def test_set_role_provider_and_role_provider():
    calls = []
    gw = gateway_with(calls)
    assert gw.role_provider("PLANNER") == "ollama-local"  # default: local first
    gw.set_role_provider("PLANNER", "cloud-x")
    assert gw.role_provider("PLANNER") == "cloud-x"
    gw.set_role_provider("planner", "ollama-local")  # case-insensitive
    assert gw.role_provider("PLANNER") == "ollama-local"
    with pytest.raises(ValueError, match="unknown role"):
        gw.set_role_provider("BOSS", "cloud-x")
    with pytest.raises(ValueError, match="unknown provider"):
        gw.set_role_provider("PLANNER", "nope")
    info = gw.role_info("PLANNER")
    assert info["provider"] == "ollama-local"
    assert info["provider_class"] == "strongest-available"


def test_complete_unknown_role_raises():
    gw = gateway_with([])
    with pytest.raises(ValueError, match="unknown role"):
        gw.complete("BOSS", "hi", "public")


# ---------------------------------------------------------------- division: local first

def test_classification_routes_local_even_when_cloud_configured():
    calls = []
    gw = gateway_with(calls)
    out = gw.complete("ROUTER", "classify: open the browser", "public")
    assert out["text"] == "ollama-local-reply"
    assert out["provider"] == "ollama-local"
    assert out["needs_approval"] is False
    assert calls == ["ollama-local"]  # cloud never touched


def test_simple_tool_call_and_summary_and_grounding_stay_local():
    calls = []
    gw = gateway_with(calls)
    for role in ("EXECUTOR", "SUMMARIZER", "GROUNDER"):
        out = gw.complete(role, "do the thing", "public")
        assert out["provider"] == "ollama-local", role
    assert calls == ["ollama-local"] * 3


def test_router_stays_local_even_for_high_complexity():
    calls = []
    gw = gateway_with(calls)
    out = gw.complete("ROUTER", "classify this", "public", complexity="high")
    assert out["provider"] == "ollama-local"
    assert calls == ["ollama-local"]


# ---------------------------------------------------------------- escalation

def test_complex_planning_escalates_needs_approval_without_call():
    calls = []
    gw = gateway_with(calls)
    out = gw.complete("PLANNER", "plan a multi-step migration", "public",
                      complexity="high")
    assert out["needs_approval"] is True
    assert out["provider"] == "cloud-x"
    assert out["cost_estimate"] == 0.05
    assert out["text"] is None
    assert calls == []  # cloud NOT called without pre-approval


def test_complex_planning_escalates_when_preapproved():
    calls = []
    gw = gateway_with(calls)
    out = gw.complete("PLANNER", "plan a multi-step migration", "public",
                      complexity="high", preapproved=True)
    assert out["needs_approval"] is False
    assert out["provider"] == "cloud-x"
    assert out["text"] == "cloud-x-reply"
    assert out["escalated"] is True
    assert calls == ["cloud-x"]


def test_schema_fail_twice_triggers_escalation():
    calls = []
    gw = gateway_with(calls)
    assert gw.record_schema_failure("PLANNER") == 1
    assert gw.should_escalate("PLANNER") is False
    assert gw.record_schema_failure("PLANNER") == 2
    assert gw.should_escalate("PLANNER") is True
    out = gw.escalate("PLANNER", "retry with fixed schema", "public",
                      reason="schema-fail")
    assert out["needs_approval"] is True  # next provider is cloud
    assert out["provider"] == "cloud-x"
    assert out["cost_estimate"] == 0.05
    assert out["reason"] == "schema-fail"
    assert calls == []  # not called without pre-approval
    out2 = gw.escalate("PLANNER", "retry with fixed schema", "public",
                       reason="schema-fail", preapproved=True)
    assert out2["text"] == "cloud-x-reply"
    assert out2["escalated"] is True
    assert gw.schema_failure_count("PLANNER") == 0  # success resets


def test_escalation_loop_and_verification_fail_reasons():
    calls = []
    gw = gateway_with(calls, configs=[local_config(), local_config("ollama-2"),
                                       cloud_config()])
    out = gw.escalate("EXECUTOR", "retry", "public", reason="loop")
    assert out["provider"] == "ollama-2"  # next LOCAL provider, no approval needed
    assert out["text"] == "ollama-2-reply"
    assert out["escalated"] is True
    assert calls == ["ollama-2"]
    out = gw.escalate("VERIFIER", "recheck", "public", reason="verification-fail")
    assert out["provider"] == "ollama-2"


def test_escalation_with_no_further_provider():
    gw = gateway_with([], configs=[local_config()])
    out = gw.escalate("PLANNER", "retry", "public", reason="loop")
    assert out["text"] is None
    assert out["escalated"] is False
    assert "no further provider" in out["error"]


def test_escalate_unknown_reason_still_works_but_empty_rejected():
    gw = gateway_with([], configs=[local_config(), cloud_config()])
    out = gw.escalate("PLANNER", "x", "public", reason="weird-but-named")
    assert out["needs_approval"] is True
    with pytest.raises(ValueError, match="reason"):
        gw.escalate("PLANNER", "x", "public", reason="")


# ---------------------------------------------------------------- privacy

def test_secret_never_reaches_cloud_backed_cli(bin_dir, tmp_path, monkeypatch):
    marker = tmp_path / "q-called"
    monkeypatch.setenv("Q_MARKER", str(marker))
    write_script(bin_dir, "q", 'touch "$Q_MARKER"\necho q-reply\n')
    write_script(bin_dir, "opencode", 'printf "local-cli-reply\\n"\n')
    q_cfg = builtin_cli_config("q")
    local_cli = builtin_cli_config("opencode")
    calls = []
    gw = Gateway(configs=[local_cli, q_cfg, cloud_config()],
                 transport=recording_transport(calls))
    out = gw.complete("PLANNER", "secret plan", "secret")
    assert out["provider"] == "opencode"
    assert out["text"] == "local-cli-reply"
    assert not marker.exists()  # cloud-backed CLI never invoked
    assert "cloud-x" not in calls


def test_secret_with_cloud_only_raises_for_complete():
    gw = gateway_with([], configs=[cloud_config()])
    with pytest.raises(ValueError, match="secret data must not leave the machine"):
        gw.complete("PLANNER", "secret", "secret")


def test_unknown_sensitivity_fails_closed_as_secret():
    calls = []
    gw = gateway_with(calls)
    out = gw.complete("ROUTER", "mystery", "top-secret-xyz")
    assert out["provider"] == "ollama-local"
    assert calls == ["ollama-local"]
    gw_cloud_only = gateway_with([], configs=[cloud_config()])
    with pytest.raises(ValueError, match="secret data must not leave"):
        gw_cloud_only.complete("ROUTER", "mystery", "weird-label")


def test_personal_may_use_cloud_when_role_assigned():
    calls = []
    gw = gateway_with(calls)
    gw.set_role_provider("PLANNER", "cloud-x")
    out = gw.complete("PLANNER", "personal plan", "personal")
    assert out["provider"] == "cloud-x"
    assert out["text"] == "cloud-x-reply"
    assert calls == ["cloud-x"]


def test_local_cli_allowed_for_secret_but_cloud_cli_blocked(bin_dir):
    write_script(bin_dir, "opencode", 'printf "local-ok\\n"\n')
    local_cli = builtin_cli_config("opencode")
    q_cfg = builtin_cli_config("q")
    gw = Gateway(configs=[q_cfg, local_cli])
    out = gw.complete("SUMMARIZER", "summarize secrets", "secret")
    assert out["provider"] == "opencode"
    assert out["text"] == "local-ok"


# ---------------------------------------------------------------- budgets

def test_daily_budget_blocks_before_call():
    calls = []
    gw = gateway_with(calls, configs=[local_config()], budgets={"ollama-local": 1})
    first = gw.complete("ROUTER", "one", "public")
    assert first["text"] == "ollama-local-reply"
    assert gw.check_budget("ollama-local") is False
    second = gw.complete("ROUTER", "two", "public")
    assert second["text"] is None
    assert "budget exceeded" in second["error"]
    assert calls == ["ollama-local"]  # blocked call never reached the model


def test_monthly_budget_blocks_before_call():
    calls = []
    gw = gateway_with(calls, configs=[local_config()],
                      monthly_budgets={"ollama-local": 1})
    assert gw.complete("ROUTER", "one", "public")["text"] == "ollama-local-reply"
    assert gw.check_budget("ollama-local") is False
    assert gw.monthly_budget_usage("ollama-local") == 1
    second = gw.complete("ROUTER", "two", "public")
    assert second["text"] is None
    assert len(calls) == 1


def test_graceful_local_only_fallback_when_budget_hit():
    calls = []
    gw = gateway_with(calls, budgets={"ollama-local": 1})
    gw.complete("ROUTER", "one", "public")
    # Local exhausted: the only remaining provider is cloud, so the
    # gateway asks for approval instead of failing outright.
    out = gw.complete("ROUTER", "two", "public")
    assert out["needs_approval"] is True
    assert out["provider"] == "cloud-x"
    assert calls == ["ollama-local"]


def test_record_usage_and_check_budget_api():
    gw = gateway_with([])
    assert gw.check_budget("ollama-local") is True
    gw.record_usage("ollama-local", 3)
    assert gw.budget_usage("ollama-local") == 3
    assert gw.monthly_budget_usage("ollama-local") == 3


# ---------------------------------------------------------------- circuit breaker

def test_circuit_breaker_skips_failing_provider():
    calls = []
    gw = gateway_with(calls, configs=[local_config(), local_config("ollama-2")])
    assert gw.is_available("ollama-local") is True
    gw.mark_failure("ollama-local")
    assert gw.is_available("ollama-local") is False
    out = gw.complete("ROUTER", "hi", "public")
    assert out["provider"] == "ollama-2"
    assert calls == ["ollama-2"]
    # After the 60s cooldown the provider is available again.
    gw._failures["ollama-local"] = time.monotonic() - 61
    assert gw.is_available("ollama-local") is True


def test_transport_failure_marks_provider_and_falls_back():
    def flaky(config, payload, headers):
        if config.name == "ollama-local":
            raise ConnectionError("down")
        return {"text": "second-reply"}

    gw = Gateway(configs=[local_config(), local_config("ollama-2")],
                 transport=flaky)
    out = gw.complete("ROUTER", "hi", "public")
    assert out["provider"] == "ollama-2"
    assert out["text"] == "second-reply"
    assert out["escalated"] is True
    assert gw.is_available("ollama-local") is False


# ---------------------------------------------------------------- usage store

def test_usage_store_daily_and_monthly(tmp_path):
    store = UsageStore(tmp_path / "state")
    assert store.daily("ollama-local") == 0
    assert store.monthly("ollama-local") == 0
    store.record("ollama-local", 2)
    assert store.daily("ollama-local") == 2
    assert store.monthly("ollama-local") == 2
    store.record("ollama-local")
    assert store.daily("ollama-local") == 3
    assert store.providers() == ["ollama-local"]
    with pytest.raises(ValueError):
        store.record("", 1)
    with pytest.raises(ValueError):
        store.record("x", -1)


def test_usage_store_persists_across_instances(tmp_path):
    state = tmp_path / "state"
    UsageStore(state).record("cloud-x", 5)
    assert UsageStore(state).daily("cloud-x") == 5
    assert UsageStore(state).monthly("cloud-x") == 5


def test_gateway_with_usage_store_enforces_persisted_budget(tmp_path):
    state = tmp_path / "state"
    UsageStore(state).record("ollama-local", 1)
    calls = []
    gw = Gateway(configs=[local_config()],
                 transport=recording_transport(calls),
                 budgets={"ollama-local": 1},
                 usage_store=UsageStore(state))
    assert gw.check_budget("ollama-local") is False
    out = gw.complete("ROUTER", "hi", "public")
    assert out["text"] is None
    assert calls == []


# ---------------------------------------------------------------- CLI via gateway

def test_complete_with_fake_opencode_cli(bin_dir):
    write_script(bin_dir, "opencode", 'printf "cli-says: %s\\n" "$*"\n')
    gw = Gateway(configs=[builtin_cli_config("opencode")])
    out = gw.complete("EXECUTOR", "list files", "public")
    assert out["text"] == "cli-says: run list files"
    assert out["provider"] == "opencode"
    assert out["needs_approval"] is False


def test_complete_result_shape():
    gw = gateway_with([])
    out = gw.complete("ROUTER", "hi", "public")
    assert set(out) >= {"text", "provider", "role", "cost_estimate",
                        "needs_approval", "escalated"}
    assert out["role"] == "ROUTER"
    assert out["cost_estimate"] == 0.0


def test_verifier_uses_separate_provider_from_planner():
    calls = []
    gw = gateway_with(calls, configs=[local_config(), local_config("ollama-2"),
                                       cloud_config()])
    gw.set_role_provider("PLANNER", "ollama-local")
    gw.set_role_provider("VERIFIER", "ollama-2")
    assert gw.complete("PLANNER", "plan", "public")["provider"] == "ollama-local"
    assert gw.complete("VERIFIER", "check", "public")["provider"] == "ollama-2"
    assert calls == ["ollama-local", "ollama-2"]
