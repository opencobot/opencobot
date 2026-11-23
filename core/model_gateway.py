"""Policy-aware model gateway (ARCHITECTURE.md section 6, SPEC.md section 8).

Routing rules:
  * Local first (Ollama / OpenAI-compatible local endpoints).
  * Secret data never leaves the machine: for sensitivity "secret" only
    local providers are eligible, and if none is configured routing raises
    ValueError instead of silently escalating to cloud.
  * Daily per-provider budgets; exceeding a budget blocks the call without
    touching the model.

API keys are never stored in code and never logged: a key is read from the
named environment variable at call time only, and attached by the gateway.
No network is used in tests -- pass a ``transport`` callable instead.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import date
from typing import Any, Callable

_LOCAL_KINDS = ("ollama", "openai-compatible")
_DEFAULT_BUDGET = 1000


@dataclass
class ProviderConfig:
    name: str
    kind: str  # "ollama" | "openai-compatible" | "cloud"
    base_url: str
    model: str
    api_key_env: str | None = None
    timeout: int = 30


def _default_configs() -> list[ProviderConfig]:
    return [
        ProviderConfig("ollama-local", "ollama", "http://localhost:11434", "llama3.1"),
        ProviderConfig(
            "openai-compatible",
            "openai-compatible",
            "http://localhost:1234/v1",
            "local-model",
        ),
    ]


def _extract_text(response: Any) -> str | None:
    """Pull generated text out of a transport/HTTP response body."""
    if isinstance(response, str):
        return response
    if not isinstance(response, dict):
        return None
    text = response.get("text")
    if isinstance(text, str):
        return text
    choices = response.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, dict):
            message = first.get("message")
            if isinstance(message, dict) and isinstance(message.get("content"), str):
                return message["content"]
            if isinstance(first.get("text"), str):
                return first["text"]
    message = response.get("message")
    if isinstance(message, dict) and isinstance(message.get("content"), str):
        return message["content"]
    if isinstance(response.get("response"), str):
        return response["response"]
    return None


class Gateway:
    """Route chat requests to local-first providers with budgets."""

    def __init__(
        self,
        configs: list[ProviderConfig] | None = None,
        transport: Callable[..., Any] | None = None,
        budgets: dict | None = None,
    ):
        self.configs: list[ProviderConfig] = (
            list(configs) if configs is not None else _default_configs()
        )
        self._transport = transport
        self._budgets: dict = dict(budgets) if budgets else {}
        self._counts: dict[tuple[str, str], int] = {}

    # -- routing ---------------------------------------------------------

    def fallback_chain(self, role: str, sensitivity: str) -> list[ProviderConfig]:
        """Local providers first, then cloud -- never cloud for secret data.

        ``role`` is accepted for future role-based preference (SPEC 8.2);
        ordering today is local-first for every role. Any sensitivity value
        other than "public"/"personal" is treated as secret (fail closed).
        """
        local = [c for c in self.configs if c.kind in _LOCAL_KINDS]
        cloud = [c for c in self.configs if c.kind not in _LOCAL_KINDS]
        if sensitivity not in ("public", "personal"):
            return local
        return local + cloud

    def route(self, role: str, sensitivity: str) -> ProviderConfig:
        chain = self.fallback_chain(role, sensitivity)
        if not chain:
            raise ValueError("secret data must not leave the machine")
        return chain[0]

    # -- budgets --------------------------------------------------------

    def budget_limit(self, provider_name: str) -> int:
        return int(self._budgets.get(provider_name, _DEFAULT_BUDGET))

    def budget_usage(self, provider_name: str) -> int:
        return self._counts.get((provider_name, date.today().isoformat()), 0)

    def _budget_exceeded(self, provider_name: str) -> bool:
        return self.budget_usage(provider_name) >= self.budget_limit(provider_name)

    def _count_use(self, provider_name: str) -> None:
        key = (provider_name, date.today().isoformat())
        self._counts[key] = self._counts.get(key, 0) + 1

    # -- availability probe (no chat, no budget consumed) -----------------

    def ping(self, config: ProviderConfig | None = None, timeout: int = 2) -> bool:
        """True if a provider answers a lightweight list-models request."""
        config = config or (self.configs[0] if self.configs else None)
        if config is None:
            return False
        path = "/api/tags" if config.kind == "ollama" else "/models"
        url = config.base_url.rstrip("/") + path
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return 200 <= resp.status < 300
        except Exception:
            return False

    # -- chat ------------------------------------------------------------

    def _headers(self, config: ProviderConfig) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if config.api_key_env:
            # Read from the environment at call time only; never logged.
            api_key = os.environ.get(config.api_key_env)
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
        return headers

    def _payload(self, config: ProviderConfig, messages: list[dict]) -> tuple[str, dict]:
        if config.kind == "ollama":
            url = config.base_url.rstrip("/") + "/api/chat"
            payload = {"model": config.model, "messages": messages, "stream": False}
        else:
            url = config.base_url.rstrip("/") + "/chat/completions"
            payload = {"model": config.model, "messages": messages}
        return url, payload

    def _call_transport(
        self, config: ProviderConfig, url: str, payload: dict, headers: dict
    ) -> Any:
        """Invoke the injected transport.

        Primary shape: transport(config, payload, headers). Also accepts
        transport(config, payload) and transport(url, payload) mocks;
        arity mismatches fall through to the next shape.
        """
        transport = self._transport
        assert transport is not None
        last_error: TypeError | None = None
        for args in (
            (config, payload, headers),
            (config, payload),
            (url, payload),
            (payload,),
        ):
            try:
                return transport(*args)
            except TypeError as exc:
                last_error = exc
                continue
        raise last_error  # type: ignore[misc]

    def _call_http(
        self, config: ProviderConfig, url: str, payload: dict, headers: dict
    ) -> Any:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=config.timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def chat(
        self,
        role: str,
        messages: list[dict],
        sensitivity: str = "public",
    ) -> dict:
        """Send messages to the routed provider.

        Returns {"ok", "text", "provider", "error"}. Connection failures
        and malformed responses return ok False, never raise. A secret
        routing failure (no local provider) raises ValueError by design.
        """
        config = self.route(role, sensitivity)
        if self._budget_exceeded(config.name):
            return {
                "ok": False,
                "text": None,
                "provider": config.name,
                "error": "budget exceeded",
            }
        self._count_use(config.name)
        url, payload = self._payload(config, messages)
        headers = self._headers(config)
        try:
            if self._transport is not None:
                raw = self._call_transport(config, url, payload, headers)
            else:
                raw = self._call_http(config, url, payload, headers)
        except urllib.error.HTTPError as exc:
            return {
                "ok": False,
                "text": None,
                "provider": config.name,
                "error": f"model error: HTTP {exc.code}",
            }
        except (ConnectionError, OSError, urllib.error.URLError) as exc:
            return {
                "ok": False,
                "text": None,
                "provider": config.name,
                "error": f"model unavailable: {exc}",
            }
        except Exception as exc:
            return {
                "ok": False,
                "text": None,
                "provider": config.name,
                "error": f"model error: {type(exc).__name__}: {exc}",
            }
        text = _extract_text(raw)
        if text is None:
            return {
                "ok": False,
                "text": None,
                "provider": config.name,
                "error": "model error: unexpected response",
            }
        return {"ok": True, "text": text, "provider": config.name, "error": None}
