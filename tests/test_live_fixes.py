"""Tests for the three live-model-testing findings (2026-11-23).

1. A failed runtime step reported "step 'list_dir' failed: allowed" --
   the decision reason was preferred over the tool's own error.
2. The CLI benchmark with a missing model scored 0.00 on all 7 tests
   with empty outputs -- the gateway swallowed the model error.
3. The gateway had no config-file override for the default model.

No network and no real models: fake transports, fake gateways, temp
config files.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from core.model_gateway import (  # noqa: E402
    GATEWAY_CONFIG_ENV,
    Gateway,
    ProviderConfig,
    load_gateway_configs,
)
from core.runtime import Runtime  # noqa: E402


# ---------------------------------------------------------------- fakes

class StubPolicy:
    """L0-L2 allowed; L3+ needs an explicit approval for the tool."""

    def __init__(self):
        self.killed = False
        self.approved: set[str] = set()

    def is_killed(self):
        return self.killed

    def check(self, token, tool_name, level, args, tainted):
        if level >= 3 and tool_name not in self.approved:
            return {"allowed": False, "reason": "approval required",
                    "needs_approval": True}
        return {"allowed": True, "reason": "allowed", "needs_approval": False}


def make_scope_failing_tool():
    """Allowed by policy, but execute() fails like the live /tmp scope
    failure: the tool reports its own error, the decision stays allowed."""

    def execute(args, ctx):
        return {"ok": False, "error": "path /tmp is outside token scope"}

    return SimpleNamespace(
        level=0,
        schema={"type": "object", "properties": {}, "required": []},
        description="Fails in execute() with its own error",
        execute=execute,
        verify=lambda args, result, ctx: (True, ""),
    )


def make_sensitive_tool():
    return SimpleNamespace(
        level=3,
        schema={"type": "object", "properties": {}, "required": []},
        description="L3 tool, needs approval",
        execute=lambda args, ctx: {"ok": True},
        verify=lambda args, result, ctx: (True, ""),
    )


def local_config(model="llama3.1"):
    return ProviderConfig("ollama-local", "ollama",
                          "http://localhost:11434", model)


def error_dict_transport(error="model error: HTTP 404"):
    def transport(config, payload, headers):
        return {"ok": False, "error": error}
    return transport


# ------------------------------------------------------- finding 1: runtime

def test_run_task_reports_tool_error_not_allowed(tmp_path):
    registry = {"scoped": make_scope_failing_tool()}
    runtime = Runtime(tmp_path, StubPolicy(), registry)
    out = runtime.run_task("list /tmp",
                           token=None,
                           steps=[{"tool": "scoped", "args": {}}])
    assert out["ok"] is False
    assert "outside token scope" in (out["error"] or "")
    assert out["error"] != "step 'scoped' failed: allowed"
    assert "allowed" not in (out["error"] or "")


def test_run_task_reports_decision_reason_when_denied(tmp_path):
    registry = {"sensitive": make_sensitive_tool()}
    runtime = Runtime(tmp_path, StubPolicy(), registry)
    out = runtime.run_task("do the sensitive thing",
                           token=None,
                           steps=[{"tool": "sensitive", "args": {}}])
    assert out["ok"] is False
    assert "approval required" in (out["error"] or "")


def test_run_tool_evidence_carries_execute_error(tmp_path):
    registry = {"scoped": make_scope_failing_tool()}
    runtime = Runtime(tmp_path, StubPolicy(), registry)
    out = runtime.run_tool(None, "scoped", {})
    assert out["ok"] is False
    assert "outside token scope" in (out["evidence"] or "")


# ------------------------------------------- finding 2: swallowed model error

def test_call_provider_surfaces_http_error_dict():
    gw = Gateway(configs=[local_config()],
                 transport=error_dict_transport())
    with pytest.raises(RuntimeError, match="HTTP 404"):
        gw._call_provider(local_config(), "hi")


def test_chat_surfaces_http_error_dict():
    gw = Gateway(configs=[local_config()],
                 transport=error_dict_transport())
    out = gw.chat("EXECUTOR", [{"role": "user", "content": "hi"}], "public")
    assert out["ok"] is False
    assert "HTTP 404" in (out["error"] or "")


def test_complete_keeps_last_provider_error():
    gw = Gateway(configs=[local_config()],
                 transport=error_dict_transport(
                     "model error: HTTP 404"))
    out = gw.complete("ROUTER", "classify this", "public")
    assert out["text"] is None
    assert "HTTP 404" in (out["error"] or "")
    assert "ollama-local" in (out["error"] or "")


def test_benchmark_probe_reports_dead_provider():
    from cli.opencobot_cli import _benchmark_probe

    class DeadGateway:
        def complete(self, role, prompt, sensitivity):
            return {"text": None, "provider": "ollama-local",
                    "error": "no provider available or budget exceeded "
                             "(last error: provider ollama-local: "
                             "model error: HTTP 404)",
                    "needs_approval": False, "escalated": False}

    error = _benchmark_probe(DeadGateway(), "ollama-local")
    assert error is not None
    assert "HTTP 404" in error


def test_benchmark_probe_passes_live_provider():
    from cli.opencobot_cli import _benchmark_probe

    class LiveGateway:
        def complete(self, role, prompt, sensitivity):
            return {"text": "PING", "provider": "ollama-local",
                    "error": None, "needs_approval": False,
                    "escalated": False}

    assert _benchmark_probe(LiveGateway(), "ollama-local") is None


def test_benchmark_aborts_when_probe_fails(monkeypatch, tmp_path):
    """cmd_benchmark returns 2 with a clear error instead of running
    7 tests against a dead provider."""
    import cli.opencobot_cli as cli_mod

    monkeypatch.setenv(GATEWAY_CONFIG_ENV, str(tmp_path / "no-such.json"))

    class DeadGateway:
        def __init__(self, configs=None, **kwargs):
            self.configs = configs or []

        def complete(self, role, prompt, sensitivity):
            return {"text": None, "provider": "ollama-local",
                    "error": "no provider available or budget exceeded "
                             "(last error: provider ollama-local: "
                             "model error: HTTP 404)",
                    "needs_approval": False, "escalated": False}

        def ping(self, config=None, timeout=2):
            return False

    monkeypatch.setattr("core.model_gateway.Gateway", DeadGateway)
    args = SimpleNamespace(provider="ollama-local", model=None, json=False)
    assert cli_mod.cmd_benchmark(args) == 2


def test_benchmark_model_override_reaches_gateway(monkeypatch, tmp_path):
    """--model overrides the provider model for this run only."""
    import cli.opencobot_cli as cli_mod

    monkeypatch.setenv(GATEWAY_CONFIG_ENV, str(tmp_path / "no-such.json"))
    seen: dict = {}

    class LiveGateway:
        def __init__(self, configs=None, **kwargs):
            seen["models"] = {c.name: c.model for c in (configs or [])}
            self.configs = configs or []

        def complete(self, role, prompt, sensitivity):
            return {"text": "PING", "provider": "ollama-local",
                    "error": None, "needs_approval": False,
                    "escalated": False}

        def ping(self, config=None, timeout=2):
            return True

    monkeypatch.setattr("core.model_gateway.Gateway", LiveGateway)
    args = SimpleNamespace(provider="ollama-local",
                           model="qwen2.5:0.5b", json=True)
    assert cli_mod.cmd_benchmark(args) == 0
    assert seen["models"]["ollama-local"] == "qwen2.5:0.5b"


# -------------------------------------------- finding 3: gateway config file

def test_config_file_overrides_default_model(tmp_path, monkeypatch):
    path = tmp_path / "gateway.json"
    path.write_text(json.dumps(
        {"providers": [{"name": "ollama-local", "model": "qwen2.5:0.5b"}]}),
        encoding="utf-8")
    configs = load_gateway_configs(str(path))
    assert configs[0].name == "ollama-local"
    assert configs[0].model == "qwen2.5:0.5b"
    # Other defaults are untouched.
    assert configs[1].name == "openai-compatible"


def test_config_file_utf8_bom_loads(tmp_path):
    # Windows editors and PowerShell Set-Content -Encoding UTF8 write a
    # UTF-8 BOM; the loader must accept it (llama3.1:8b laptop run failed
    # on "Unexpected UTF-8 BOM" before this fix).
    path = tmp_path / "gateway.json"
    payload = json.dumps(
        {"providers": [{"name": "ollama-local", "model": "llama3.1:8b",
                        "timeout": 120}]}).encode("utf-8")
    path.write_bytes(b"\xef\xbb\xbf" + payload)
    configs = load_gateway_configs(str(path))
    assert configs[0].name == "ollama-local"
    assert configs[0].model == "llama3.1:8b"
    assert configs[0].timeout == 120


def test_config_file_env_var(monkeypatch, tmp_path):
    path = tmp_path / "gateway.json"
    path.write_text(json.dumps(
        {"providers": [{"name": "ollama-local", "model": "qwen2.5:0.5b"}]}),
        encoding="utf-8")
    monkeypatch.setenv(GATEWAY_CONFIG_ENV, str(path))
    assert load_gateway_configs()[0].model == "qwen2.5:0.5b"


def test_config_file_can_add_provider(tmp_path):
    path = tmp_path / "gateway.json"
    path.write_text(json.dumps(
        {"providers": [{"name": "my-local", "kind": "ollama",
                        "base_url": "http://localhost:11434",
                        "model": "llama3.1:8b"}]}),
        encoding="utf-8")
    configs = load_gateway_configs(str(path))
    added = [c for c in configs if c.name == "my-local"]
    assert len(added) == 1
    assert added[0].model == "llama3.1:8b"


def test_config_file_unknown_name_without_kind_fails(tmp_path):
    path = tmp_path / "gateway.json"
    path.write_text(json.dumps(
        {"providers": [{"name": "ollama-locla", "model": "qwen2.5:0.5b"}]}),
        encoding="utf-8")
    with pytest.raises(ValueError, match="ollama-locla"):
        load_gateway_configs(str(path))


def test_config_file_invalid_json_fails(tmp_path):
    path = tmp_path / "gateway.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        load_gateway_configs(str(path))


def test_no_config_file_means_defaults(monkeypatch, tmp_path):
    monkeypatch.setenv(GATEWAY_CONFIG_ENV, str(tmp_path / "no-such.json"))
    configs = load_gateway_configs()
    assert configs[0].model == "llama3.1"
    assert Gateway().configs[0].model == "llama3.1"


def test_gateway_default_uses_config_file(monkeypatch, tmp_path):
    path = tmp_path / "gateway.json"
    path.write_text(json.dumps(
        {"providers": [{"name": "ollama-local", "model": "qwen2.5:0.5b"}]}),
        encoding="utf-8")
    monkeypatch.setenv(GATEWAY_CONFIG_ENV, str(path))
    assert Gateway().configs[0].model == "qwen2.5:0.5b"


# --------------------------------- finding 4: cli_binary_dirs in gateway.json

def test_config_file_cli_binary_dirs_for_new_cli_provider(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    path = tmp_path / "gateway.json"
    path.write_text(json.dumps(
        {"providers": [{"name": "opencode", "kind": "cli",
                        "cli_binary": "opencode",
                        "cli_argv_template": ["run", "{prompt}"],
                        "cli_binary_dirs": [str(bin_dir)]}]}),
        encoding="utf-8")
    configs = load_gateway_configs(str(path))
    added = [c for c in configs if c.name == "opencode"]
    assert len(added) == 1
    assert added[0].kind == "cli"
    assert added[0].cli_binary == "opencode"
    assert added[0].cli_binary_dirs == [str(bin_dir)]


def test_config_file_cli_binary_dirs_overrides_existing(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    path = tmp_path / "gateway.json"
    path.write_text(json.dumps(
        {"providers": [{"name": "ollama-local",
                        "cli_binary_dirs": [str(bin_dir)]}]}),
        encoding="utf-8")
    configs = load_gateway_configs(str(path))
    assert configs[0].cli_binary_dirs == [str(bin_dir)]


def test_config_file_cli_binary_dirs_must_be_a_list(tmp_path):
    path = tmp_path / "gateway.json"
    path.write_text(json.dumps(
        {"providers": [{"name": "ollama-local",
                        "cli_binary_dirs": "/tmp"}]}),
        encoding="utf-8")
    with pytest.raises(ValueError, match="must be a list"):
        load_gateway_configs(str(path))


def test_config_file_cli_binary_dirs_must_exist(tmp_path):
    path = tmp_path / "gateway.json"
    path.write_text(json.dumps(
        {"providers": [{"name": "ollama-local",
                        "cli_binary_dirs": [str(tmp_path / "no-such-dir")]}]}),
        encoding="utf-8")
    with pytest.raises(ValueError, match="non-existent directories"):
        load_gateway_configs(str(path))


def test_config_file_cli_binary_dirs_empty_list_means_defaults(tmp_path):
    # An empty list is valid (vacuously a list of existing dirs) and
    # leaves resolution to the env var / built-in defaults.
    path = tmp_path / "gateway.json"
    path.write_text(json.dumps(
        {"providers": [{"name": "ollama-local", "cli_binary_dirs": []}]}),
        encoding="utf-8")
    configs = load_gateway_configs(str(path))
    assert configs[0].cli_binary_dirs == []


def test_config_file_new_cli_provider_bad_prompt_via_fails(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    path = tmp_path / "gateway.json"
    path.write_text(json.dumps(
        {"providers": [{"name": "opencode", "kind": "cli",
                        "cli_binary": "opencode",
                        "cli_prompt_via": "telepathy",
                        "cli_binary_dirs": [str(bin_dir)]}]}),
        encoding="utf-8")
    with pytest.raises(ValueError, match="cli_prompt_via"):
        load_gateway_configs(str(path))
