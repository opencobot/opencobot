"""Tests for the OmniRouter provider config (ADR-011).

Mock transport only — no network, no API key. The endpoint is
documented from docs.omrouter.com, not live-tested here.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from core.model_gateway import (  # noqa: E402
    Gateway,
    ProviderConfig,
    load_gateway_configs,
    omnirouter_config,
)


def _local():
    return ProviderConfig("ollama-local", "ollama",
                          "http://localhost:11434", "llama3.1")


def test_helper_returns_cloud_backed_openai_compatible_config():
    cfg = omnirouter_config("openai/gpt-4o-mini")
    assert cfg.name == "omnirouter"
    assert cfg.kind == "openai-compatible"
    assert cfg.base_url == "https://api.omrouter.com/v1"
    assert cfg.model == "openai/gpt-4o-mini"
    assert cfg.api_key_env == "OMNIROUTER_API_KEY"
    assert cfg.egress == "cloud-backed"
    assert cfg.is_cloud_backed is True
    assert cfg.is_local_only is False


def test_helper_accepts_custom_base_url_and_key_env():
    cfg = omnirouter_config("some/model", base_url="https://example.invalid/v1",
                            api_key_env="MY_OMNI_KEY")
    assert cfg.base_url == "https://example.invalid/v1"
    assert cfg.api_key_env == "MY_OMNI_KEY"


def test_helper_requires_a_model():
    with pytest.raises(ValueError, match="needs a model"):
        omnirouter_config("")
    with pytest.raises(ValueError, match="needs a model"):
        omnirouter_config(None)  # type: ignore[arg-type]


def test_gateway_routes_public_data_to_it_via_mock_transport():
    seen = []

    def transport(config, payload, headers):
        seen.append((config, payload, headers))
        return {"text": "hello from omnirouter"}

    gw = Gateway(configs=[_local(), omnirouter_config("openai/gpt-4o-mini")],
                 transport=transport)
    gw.set_role_provider("EXECUTOR", "omnirouter")
    out = gw.complete("EXECUTOR", "hello", "public")
    assert out["text"] == "hello from omnirouter"
    assert out["provider"] == "omnirouter"
    assert seen and seen[0][0].name == "omnirouter"
    assert seen[0][0].base_url == "https://api.omrouter.com/v1"
    assert seen[0][1]["model"] == "openai/gpt-4o-mini"


def test_secret_data_never_routes_to_it():
    gw = Gateway(configs=[_local(), omnirouter_config("openai/gpt-4o-mini")])
    chain = gw.fallback_chain("EXECUTOR", "secret")
    assert all(c.name != "omnirouter" for c in chain)
    assert all(c.is_local_only for c in chain)
    cloud_only = Gateway(configs=[omnirouter_config("openai/gpt-4o-mini")])
    with pytest.raises(ValueError, match="secret data must not leave"):
        cloud_only.route("EXECUTOR", "secret")


def test_budget_checks_apply():
    gw = Gateway(configs=[omnirouter_config("openai/gpt-4o-mini")],
                 transport=lambda *a: {"text": "x"},
                 budgets={"omnirouter": 0})
    gw.set_role_provider("EXECUTOR", "omnirouter")
    assert gw.check_budget("omnirouter") is False
    out = gw.complete("EXECUTOR", "hello", "public")
    assert out["text"] is None
    assert out["error"] and "budget exceeded" in out["error"]


def test_equivalent_config_file_entry_loads(tmp_path, monkeypatch):
    cfg_file = tmp_path / "gateway.json"
    cfg_file.write_text(json.dumps({"providers": [{
        "name": "omnirouter", "kind": "openai-compatible",
        "base_url": "https://api.omrouter.com/v1",
        "model": "openai/gpt-4o-mini",
        "api_key_env": "OMNIROUTER_API_KEY",
        "egress": "cloud-backed",
    }]}), encoding="utf-8")
    monkeypatch.setenv("OPENCOBOT_GATEWAY_CONFIG", str(cfg_file))
    configs = load_gateway_configs()
    omni = [c for c in configs if c.name == "omnirouter"]
    assert len(omni) == 1
    assert omni[0].kind == "openai-compatible"
    assert omni[0].base_url == "https://api.omrouter.com/v1"
    assert omni[0].model == "openai/gpt-4o-mini"
    assert omni[0].api_key_env == "OMNIROUTER_API_KEY"
    assert omni[0].is_cloud_backed is True


# ---------------------------------------------------------------- egress loader fix
# "egress" used to be silently dropped by load_gateway_configs for
# every provider except kind "cli" — a cloud-backed openai-compatible
# provider defined in the file came out local-only, and secret data
# could have been routed to it. These tests pin the fix.

def test_config_file_egress_applies_to_override(tmp_path, monkeypatch):
    cfg_file = tmp_path / "gateway.json"
    cfg_file.write_text(json.dumps({"providers": [{
        "name": "ollama-local", "egress": "cloud-backed",
    }]}), encoding="utf-8")
    monkeypatch.setenv("OPENCOBOT_GATEWAY_CONFIG", str(cfg_file))
    configs = load_gateway_configs()
    local = [c for c in configs if c.name == "ollama-local"]
    assert len(local) == 1
    assert local[0].is_cloud_backed is True


def test_config_file_bad_egress_fails_loudly(tmp_path, monkeypatch):
    cfg_file = tmp_path / "gateway.json"
    cfg_file.write_text(json.dumps({"providers": [{
        "name": "omnirouter", "kind": "openai-compatible",
        "base_url": "https://api.omrouter.com/v1",
        "model": "openai/gpt-4o-mini", "egress": "bogus",
    }]}), encoding="utf-8")
    monkeypatch.setenv("OPENCOBOT_GATEWAY_CONFIG", str(cfg_file))
    with pytest.raises(ValueError, match="egress"):
        load_gateway_configs()


def test_config_file_cli_egress_still_works(tmp_path, monkeypatch):
    cfg_file = tmp_path / "gateway.json"
    cfg_file.write_text(json.dumps({"providers": [{
        "name": "q", "kind": "cli", "cli_binary": "q",
        "cli_argv_template": ["{prompt}"],
        "egress": "cloud-backed",
    }]}), encoding="utf-8")
    monkeypatch.setenv("OPENCOBOT_GATEWAY_CONFIG", str(cfg_file))
    configs = load_gateway_configs()
    q = [c for c in configs if c.name == "q"]
    assert len(q) == 1
    assert q[0].is_cloud_backed is True
