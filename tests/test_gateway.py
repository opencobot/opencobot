"""Tests for core.model_gateway. No network: injected mock transports or a
monkeypatched urllib.request.urlopen stand in for real providers."""

from __future__ import annotations

import json
import sys
import urllib.error
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from core.model_gateway import Gateway, ProviderConfig  # noqa: E402

MESSAGES = [{"role": "user", "content": "hello"}]


def cloud_config():
    return ProviderConfig("cloud-x", "cloud", "https://api.example.invalid/v1",
                          "big-model", api_key_env="OPENCOBOT_TEST_CLOUD_KEY")


def local_config():
    return ProviderConfig("ollama-local", "ollama", "http://localhost:11434",
                          "llama3.1")


# ---------------------------------------------------------------- routing

def test_default_configs_ollama_first():
    gw = Gateway()
    assert gw.configs[0].name == "ollama-local"
    assert gw.configs[0].kind == "ollama"
    assert gw.configs[0].base_url == "http://localhost:11434"
    assert gw.configs[0].model == "llama3.1"
    assert gw.configs[1].kind == "openai-compatible"
    assert gw.configs[1].base_url == "http://localhost:1234/v1"


def test_secret_never_routes_to_cloud_even_when_cloud_is_first():
    gw = Gateway(configs=[cloud_config(), local_config()])
    chosen = gw.route("planner", "secret")
    assert chosen.kind == "ollama"
    assert chosen.name == "ollama-local"
    chain = gw.fallback_chain("planner", "secret")
    assert all(c.kind != "cloud" for c in chain)


def test_secret_with_cloud_only_raises():
    gw = Gateway(configs=[cloud_config()])
    with pytest.raises(ValueError, match="secret data must not leave the machine"):
        gw.route("planner", "secret")
    with pytest.raises(ValueError, match="secret data must not leave the machine"):
        gw.chat("planner", MESSAGES, sensitivity="secret")


def test_fallback_chain_local_first_then_cloud_for_public():
    gw = Gateway(configs=[cloud_config(), local_config()])
    chain = gw.fallback_chain("planner", "public")
    assert chain[0].kind == "ollama"
    assert chain[-1].kind == "cloud"


# ---------------------------------------------------------------- chat

def test_chat_with_mock_transport_returns_text():
    calls = []

    def transport(config, payload, headers):
        calls.append((config, payload, headers))
        return {"text": "hello back"}

    gw = Gateway(configs=[local_config()], transport=transport)
    out = gw.chat("executor", MESSAGES, sensitivity="public")
    assert out == {"ok": True, "text": "hello back",
                   "provider": "ollama-local", "error": None}
    assert len(calls) == 1
    assert calls[0][1]["model"] == "llama3.1"
    assert calls[0][1]["messages"] == MESSAGES


def test_chat_accepts_two_arg_transport():
    gw = Gateway(configs=[local_config()],
                 transport=lambda config, payload: {"text": "two-arg ok"})
    assert gw.chat("executor", MESSAGES)["text"] == "two-arg ok"


def test_chat_parses_openai_style_response():
    gw = Gateway(
        configs=[ProviderConfig("lm-studio", "openai-compatible",
                                "http://localhost:1234/v1", "local-model")],
        transport=lambda c, p: {"choices": [{"message": {"content": "parsed"}}]},
    )
    out = gw.chat("executor", MESSAGES)
    assert out["ok"] is True and out["text"] == "parsed"


def test_chat_transport_connection_error_returns_ok_false():
    def transport(config, payload, headers):
        raise ConnectionError("connection refused")

    gw = Gateway(configs=[local_config()], transport=transport)
    out = gw.chat("executor", MESSAGES)
    assert out["ok"] is False
    assert out["text"] is None
    assert out["provider"] == "ollama-local"
    assert out["error"].startswith("model unavailable")


def test_budget_exceeded_blocks_second_call_without_transport():
    calls = []

    def transport(config, payload, headers):
        calls.append(1)
        return {"text": "ok"}

    gw = Gateway(configs=[local_config()], transport=transport,
                 budgets={"ollama-local": 1})
    assert gw.chat("executor", MESSAGES)["ok"] is True
    second = gw.chat("executor", MESSAGES)
    assert second["ok"] is False
    assert second["error"] == "budget exceeded"
    assert len(calls) == 1  # transport never called for the blocked request


def test_api_key_read_from_env_at_call_time_and_sent_as_bearer(monkeypatch):
    seen = {}

    def transport(config, payload, headers):
        seen.update(headers)
        return {"text": "ok"}

    config = ProviderConfig("cloud-x", "cloud", "https://api.example.invalid/v1",
                            "big-model", api_key_env="OPENCOBOT_TEST_KEY_XYZ")
    gw = Gateway(configs=[config], transport=transport)
    monkeypatch.setenv("OPENCOBOT_TEST_KEY_XYZ", "test-key-123")
    assert gw.chat("executor", MESSAGES)["ok"] is True
    assert seen.get("Authorization") == "Bearer test-key-123"

    monkeypatch.delenv("OPENCOBOT_TEST_KEY_XYZ")
    seen.clear()
    assert gw.chat("executor", MESSAGES)["ok"] is True
    assert "Authorization" not in seen


def test_http_path_builds_correct_ollama_url(monkeypatch):
    captured = {}

    class FakeResponse:
        status = 200

        def read(self):
            return json.dumps({"message": {"content": "via http"}}).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(request, timeout=None):
        captured["url"] = request.full_url
        captured["body"] = json.loads(request.data.decode("utf-8"))
        return FakeResponse()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    gw = Gateway()  # defaults: ollama first
    out = gw.chat("executor", MESSAGES)
    assert out == {"ok": True, "text": "via http",
                   "provider": "ollama-local", "error": None}
    assert captured["url"] == "http://localhost:11434/api/chat"
    assert captured["body"]["model"] == "llama3.1"
    assert captured["body"]["stream"] is False


def test_http_path_builds_openai_compatible_url(monkeypatch):
    captured = {}

    class FakeResponse:
        status = 200

        def read(self):
            return json.dumps(
                {"choices": [{"message": {"content": "oaic"}}]}).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(request, timeout=None):
        captured["url"] = request.full_url
        return FakeResponse()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    gw = Gateway(configs=[ProviderConfig("lm-studio", "openai-compatible",
                                         "http://localhost:1234/v1", "local-model")])
    assert gw.chat("executor", MESSAGES)["text"] == "oaic"
    assert captured["url"] == "http://localhost:1234/v1/chat/completions"


def test_http_connection_failure_returns_ok_false(monkeypatch):
    def fake_urlopen(request, timeout=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    out = Gateway().chat("executor", MESSAGES)
    assert out["ok"] is False
    assert out["error"].startswith("model unavailable")
