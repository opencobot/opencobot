"""Policy-aware model gateway (ARCHITECTURE.md section 6, SPEC.md section 8).

Routing rules (SPEC.md 8.2/8.4, Phase 2 hybrid division):
  * Local first (Ollama / OpenAI-compatible local endpoints / local-only
    CLI models) for classification, simple tool calls, summaries,
    grounding, and ALL secret data.
  * Per-role assignment (see DEFAULT_ROLE_ASSIGNMENT / ROUTING_TABLE):
    router/classifier = small local; planner = strongest available;
    executor = reliable tool-caller; grounder = vision/local;
    verifier = separate model or pure code check; summarizer = small
    local. Each role may point at a different provider (HTTP or CLI).
  * Escalate to cloud -- only if a cloud provider is configured, only
    for public/personal data, NEVER secret -- when: JSON/schema fails
    twice, the agent loops, verification fails, task complexity is high,
    or model confidence is low. A cloud escalation shows a cost
    estimate and needs pre-approval unless pre-approved in config.
  * Sensitivity labels decide eligibility: secret = local-only always;
    personal = user-approved (configured) cloud allowed; public = any
    configured provider. Any unknown label fails closed as secret.
  * Daily AND monthly per-provider budgets are checked BEFORE the call;
    when caps are hit the gateway falls back gracefully to local-only
    mode. Circuit breakers skip a failing provider for 60s.
  * Compiled/deterministic workflows (no LLM on repeat runs) stay the
    token saver; the gateway is only called when a step breaks.

API keys are never stored in code and never logged: a key is read from the
named environment variable at call time only, and attached by the gateway.
No network is used in tests -- pass a ``transport`` callable instead.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import date
from typing import Any, Callable

from .usage import UsageStore

_DEFAULT_BUDGET = 1000
_CIRCUIT_BREAKER_COOLDOWN_SECONDS = 60
_SCHEMA_FAILURES_BEFORE_ESCALATION = 2

# -- roles (SPEC.md 8.2) ---------------------------------------------------
ROLES = ("ROUTER", "PLANNER", "EXECUTOR", "GROUNDER", "VERIFIER", "SUMMARIZER")

#: Default division of work between local and cloud providers, per role.
#: ``provider_class`` is the class of provider the role uses by default;
#: ``escalation_trigger`` names when the role may escalate to cloud
#: (public/personal data only, pre-approval / cost estimate required).
#: Overridable per role with ``Gateway.set_role_provider`` and per
#: deployment by passing explicit configs.
DEFAULT_ROLE_ASSIGNMENT: dict[str, dict[str, str]] = {
    "ROUTER": {
        "provider_class": "local-small",
        "why": "Classification is cheap and latency-sensitive; a small "
        "local model is fast and keeps prompts on-machine.",
        "escalation_trigger": "none -- on failure fall back to another "
        "local provider; classification never escalates to cloud",
    },
    "PLANNER": {
        "provider_class": "strongest-available",
        "why": "Planning is the hardest reasoning step, so it gets the "
        "strongest model available -- local first, cloud when the task "
        "demands it and the user approved.",
        "escalation_trigger": "high complexity, low confidence, "
        "schema failure x2, verification failure, agent loop",
    },
    "EXECUTOR": {
        "provider_class": "local-reliable-tool-caller",
        "why": "Tool calls must be reliable and cheap; a local model "
        "that calls tools well beats a stronger remote one.",
        "escalation_trigger": "schema failure x2, agent loop",
    },
    "GROUNDER": {
        "provider_class": "local-vision",
        "why": "Grounding consumes screenshots / UI trees; keeping "
        "images on-machine protects what is on screen.",
        "escalation_trigger": "none -- grounding stays local",
    },
    "VERIFIER": {
        "provider_class": "separate-model-or-code",
        "why": "Verification must be independent of the model being "
        "checked: prefer a pure code check, else a different local model.",
        "escalation_trigger": "a verification failure escalates the "
        "task (planner), not the verifier itself",
    },
    "SUMMARIZER": {
        "provider_class": "local-small",
        "why": "Summaries are cheap and often contain personal context; "
        "a small local model keeps them on-machine.",
        "escalation_trigger": "none -- summaries stay local",
    },
}

#: Task -> default routing. The gateway's ``complete()`` takes a role;
#: this table documents which role (and provider class) each kind of
#: work uses by default, and what triggers an escalation.
ROUTING_TABLE: dict[str, dict[str, str]] = {
    "classification": {
        "role": "ROUTER",
        "default_provider_class": "local-small",
        "sensitivity": "secret stays local; public/personal local first",
        "escalation_trigger": "none",
    },
    "simple_tool_call": {
        "role": "EXECUTOR",
        "default_provider_class": "local-reliable-tool-caller",
        "sensitivity": "secret stays local; public/personal local first",
        "escalation_trigger": "schema failure x2, agent loop",
    },
    "summary": {
        "role": "SUMMARIZER",
        "default_provider_class": "local-small",
        "sensitivity": "secret stays local; public/personal local first",
        "escalation_trigger": "none",
    },
    "grounding": {
        "role": "GROUNDER",
        "default_provider_class": "local-vision",
        "sensitivity": "secret stays local; public/personal local first",
        "escalation_trigger": "none",
    },
    "planning": {
        "role": "PLANNER",
        "default_provider_class": "strongest-available",
        "sensitivity": "secret stays local; public/personal may escalate",
        "escalation_trigger": "high complexity, low confidence, "
        "schema failure x2, verification failure, agent loop",
    },
    "verification": {
        "role": "VERIFIER",
        "default_provider_class": "separate-model-or-code",
        "sensitivity": "secret stays local; public/personal local first",
        "escalation_trigger": "verification failure escalates the task",
    },
}

#: Reasons ``Gateway.escalate`` accepts (SPEC.md 8.4). Any other
#: non-empty string is accepted too, but these are the defined triggers.
ESCALATION_REASONS = (
    "schema-fail",
    "loop",
    "verification-fail",
    "high-complexity",
    "low-confidence",
)


@dataclass
class ProviderConfig:
    name: str
    kind: str  # "ollama" | "openai-compatible" | "cloud" | "cli"
    base_url: str
    model: str
    api_key_env: str | None = None
    timeout: int = 30
    # -- Phase 2: egress, budgets, cost, CLI fields ----------------------
    # egress: "local-only" | "cloud-backed". None derives from kind:
    # "cloud" -> "cloud-backed", every other kind -> "local-only".
    # A CLI whose binary calls a cloud service (e.g. Amazon Q) must be
    # configured "cloud-backed" so secret data is never routed to it.
    egress: str | None = None
    cost_per_call: float = 0.0  # estimated cost of one call, for escalation prompts
    daily_budget: int | None = None  # overrides Gateway budgets dict / default
    monthly_budget: int | None = None  # overrides Gateway monthly budgets / 30x daily
    # CLI providers (kind == "cli"): binary from the allowlist in
    # core/cli_providers.py, argv template with a "{prompt}" placeholder,
    # prompt delivery ("stdin" | "arg" | "file") and output extraction
    # ("stdout" | "json-field", field name in cli_output_field).
    cli_binary: str | None = None
    cli_argv_template: list[str] | None = None
    cli_prompt_via: str = "arg"
    cli_output: str = "stdout"
    cli_output_field: str = "text"

    def __post_init__(self) -> None:
        if self.kind not in ("ollama", "openai-compatible", "cloud", "cli"):
            raise ValueError(f"unknown provider kind: {self.kind!r}")
        if self.egress is None:
            self.egress = "cloud-backed" if self.kind == "cloud" else "local-only"
        elif self.egress not in ("local-only", "cloud-backed"):
            raise ValueError(f"unknown egress: {self.egress!r}")
        if self.cli_prompt_via not in ("stdin", "arg", "file"):
            raise ValueError(f"unknown cli_prompt_via: {self.cli_prompt_via!r}")
        if self.cli_output not in ("stdout", "json-field"):
            raise ValueError(f"unknown cli_output: {self.cli_output!r}")
        if self.cli_argv_template is None:
            self.cli_argv_template = ["{prompt}"]
        if self.cost_per_call < 0:
            raise ValueError("cost_per_call must be non-negative")

    @property
    def is_cloud_backed(self) -> bool:
        """True if this provider sends data off the machine."""
        return self.egress == "cloud-backed"

    @property
    def is_local_only(self) -> bool:
        return self.egress == "local-only"


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
        monthly_budgets: dict | None = None,
        usage_store: UsageStore | None = None,
        state_dir: str | None = None,
        role_providers: dict | None = None,
    ):
        self.configs: list[ProviderConfig] = (
            list(configs) if configs is not None else _default_configs()
        )
        self._transport = transport
        self._budgets: dict = dict(budgets) if budgets else {}
        self._monthly_budgets: dict = dict(monthly_budgets) if monthly_budgets else {}
        self._counts: dict[tuple[str, str], int] = {}
        self._counts_monthly: dict[tuple[str, str], int] = {}
        if usage_store is not None:
            self.usage_store = usage_store
        elif state_dir is not None:
            self.usage_store = UsageStore(state_dir)
        else:
            self.usage_store = None
        # Per-role provider assignment (config-overridable division).
        self._role_providers: dict[str, str] = {}
        for role, name in (role_providers or {}).items():
            self.set_role_provider(role, name)
        # Circuit breaker: provider name -> monotonic time of last failure.
        self._failures: dict[str, float] = {}
        # Consecutive JSON/schema failures per role (escalate at 2).
        self._schema_failures: dict[str, int] = {}

    # -- roles -----------------------------------------------------------

    @staticmethod
    def _normalize_role(role: str) -> str:
        normalized = str(role).upper()
        if normalized not in ROLES:
            raise ValueError(f"unknown role: {role!r} (expected one of {ROLES})")
        return normalized

    def set_role_provider(self, role: str, name: str) -> None:
        """Assign ``role`` to provider ``name`` (HTTP or CLI)."""
        role = self._normalize_role(role)
        if not any(c.name == name for c in self.configs):
            raise ValueError(f"unknown provider: {name!r}")
        self._role_providers[role] = name

    def role_provider(self, role: str) -> str | None:
        """Provider name assigned to ``role``, or the default (first in
        the role's local-first chain) when nothing was assigned."""
        role = self._normalize_role(role)
        if role in self._role_providers:
            return self._role_providers[role]
        chain = self.fallback_chain(role, "public")
        return chain[0].name if chain else None

    def role_info(self, role: str) -> dict[str, Any]:
        """The documented default division for ``role`` plus its current
        provider assignment (for status / UI display)."""
        role = self._normalize_role(role)
        info = dict(DEFAULT_ROLE_ASSIGNMENT[role])
        info["role"] = role
        info["provider"] = self.role_provider(role)
        return info

    # -- circuit breaker ---------------------------------------------------

    def mark_failure(self, name: str) -> None:
        """Record a failure for ``name``; it is skipped for 60s."""
        self._failures[name] = time.monotonic()

    def is_available(self, name: str) -> bool:
        """False while ``name`` is inside its 60s post-failure cooldown."""
        failed_at = self._failures.get(name)
        if failed_at is None:
            return True
        return (time.monotonic() - failed_at) >= _CIRCUIT_BREAKER_COOLDOWN_SECONDS

    # -- schema-failure escalation trigger ---------------------------------

    def record_schema_failure(self, role: str) -> int:
        """Record one JSON/schema failure for ``role``; returns the new
        consecutive count. Escalation is triggered at 2 (SPEC.md 8.4)."""
        role = self._normalize_role(role)
        count = self._schema_failures.get(role, 0) + 1
        self._schema_failures[role] = count
        return count

    def schema_failure_count(self, role: str) -> int:
        return self._schema_failures.get(self._normalize_role(role), 0)

    def should_escalate(self, role: str) -> bool:
        """True once ``role`` has failed schema/JSON twice in a row."""
        return (
            self.schema_failure_count(role) >= _SCHEMA_FAILURES_BEFORE_ESCALATION
        )

    def note_success(self, role: str) -> None:
        """Reset ``role``'s consecutive schema-failure count after a good call."""
        self._schema_failures.pop(self._normalize_role(role), None)

    # -- routing ---------------------------------------------------------

    @staticmethod
    def _is_eligible(config: ProviderConfig, sensitivity: str) -> bool:
        """Secret (and any unknown label) may only use local-only providers."""
        if sensitivity not in ("public", "personal"):
            return config.is_local_only
        return True

    def fallback_chain(self, role: str, sensitivity: str) -> list[ProviderConfig]:
        """Role-assigned provider first, then other local-only providers,
        then cloud-backed ones -- never cloud for secret data.

        ``role`` is used for the per-role assignment; any sensitivity
        value other than "public"/"personal" is treated as secret
        (fail closed).
        """
        eligible = [c for c in self.configs if self._is_eligible(c, sensitivity)]
        assigned = None
        if isinstance(role, str):
            assigned = self._role_providers.get(role.upper())
        ordered: list[ProviderConfig] = []
        if assigned:
            for c in eligible:
                if c.name == assigned:
                    ordered.append(c)
                    break
        ordered += [
            c for c in eligible if c.is_local_only and c.name != assigned
        ]
        ordered += [
            c for c in eligible if c.is_cloud_backed and c.name != assigned
        ]
        return ordered

    def route(self, role: str, sensitivity: str) -> ProviderConfig:
        chain = self.fallback_chain(role, sensitivity)
        if not chain:
            raise ValueError("secret data must not leave the machine")
        return chain[0]

    # -- budgets --------------------------------------------------------

    def budget_limit(self, provider_name: str) -> int:
        config = self._config_named(provider_name)
        if config is not None and config.daily_budget is not None:
            return int(config.daily_budget)
        return int(self._budgets.get(provider_name, _DEFAULT_BUDGET))

    def monthly_budget_limit(self, provider_name: str) -> int:
        config = self._config_named(provider_name)
        if config is not None and config.monthly_budget is not None:
            return int(config.monthly_budget)
        if provider_name in self._monthly_budgets:
            return int(self._monthly_budgets[provider_name])
        return 30 * self.budget_limit(provider_name)

    def _config_named(self, provider_name: str) -> ProviderConfig | None:
        for c in self.configs:
            if c.name == provider_name:
                return c
        return None

    def budget_usage(self, provider_name: str) -> int:
        if self.usage_store is not None:
            return self.usage_store.daily(provider_name)
        return self._counts.get((provider_name, date.today().isoformat()), 0)

    def monthly_budget_usage(self, provider_name: str) -> int:
        if self.usage_store is not None:
            return self.usage_store.monthly(provider_name)
        return self._counts_monthly.get(
            (provider_name, date.today().strftime("%Y-%m")), 0
        )

    def check_budget(self, name: str) -> bool:
        """True when ``name`` is inside BOTH its daily and monthly caps."""
        return (
            self.budget_usage(name) < self.budget_limit(name)
            and self.monthly_budget_usage(name) < self.monthly_budget_limit(name)
        )

    def record_usage(self, name: str, units: int = 1) -> None:
        """Record ``units`` of usage for ``name`` (daily + monthly)."""
        today = date.today()
        key = (name, today.isoformat())
        self._counts[key] = self._counts.get(key, 0) + units
        month_key = (name, today.strftime("%Y-%m"))
        self._counts_monthly[month_key] = self._counts_monthly.get(month_key, 0) + units
        if self.usage_store is not None:
            self.usage_store.record(name, units)

    def _budget_exceeded(self, provider_name: str) -> bool:
        return not self.check_budget(provider_name)

    def _count_use(self, provider_name: str) -> None:
        self.record_usage(provider_name, 1)

    # -- availability probe (no chat, no budget consumed) -----------------

    def ping(self, config: ProviderConfig | None = None, timeout: int = 2) -> bool:
        """True if a provider answers a lightweight list-models request."""
        config = config or (self.configs[0] if self.configs else None)
        if config is None:
            return False
        if config.kind == "cli":
            # A CLI provider is "available" when its binary resolves.
            from .cli_providers import _resolve_binary

            try:
                _resolve_binary(config.cli_binary or "")
                return True
            except Exception:
                return False
        path = "/api/tags" if config.kind == "ollama" else "/models"
        url = config.base_url.rstrip("/") + path
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return 200 <= resp.status < 300
        except Exception:
            return False

    # -- Phase 2: role-based completion + escalation ----------------------

    def _call_provider(self, config: ProviderConfig, prompt: str) -> str:
        """Call one provider and return its text; raises on any failure
        (transport error, HTTP error, CLI error, empty/malformed reply)
        so the caller can mark the failure and try the next provider."""
        if config.kind == "cli":
            from .cli_providers import run_cli_provider

            return run_cli_provider(config, prompt, timeout=config.timeout)
        messages = [{"role": "user", "content": prompt}]
        url, payload = self._payload(config, messages)
        headers = self._headers(config)
        if self._transport is not None:
            raw = self._call_transport(config, url, payload, headers)
        else:
            raw = self._call_http(config, url, payload, headers)
        text = _extract_text(raw)
        if text is None:
            raise RuntimeError("model error: unexpected response")
        return text

    def _result(
        self,
        role: str,
        provider: str | None,
        text: str | None,
        cost_estimate: float,
        needs_approval: bool,
        escalated: bool,
        error: str | None = None,
    ) -> dict:
        result: dict = {
            "text": text,
            "provider": provider,
            "role": role,
            "cost_estimate": cost_estimate,
            "needs_approval": needs_approval,
            "escalated": escalated,
        }
        if error is not None:
            result["error"] = error
        return result

    def complete(
        self,
        role: str,
        prompt: str,
        sensitivity: str,
        *,
        preapproved: bool = False,
        complexity: str = "normal",
    ) -> dict:
        """Complete ``prompt`` with the provider assigned to ``role``.

        Returns {"text","provider","role","cost_estimate",
        "needs_approval","escalated"}. Local providers are tried first;
        a cloud-backed provider is only called when it is the role's
        explicitly assigned provider or ``preapproved`` is True --
        otherwise the call stops with needs_approval True, a cost
        estimate, and NO call to the cloud provider. ``complexity="high"``
        (planning) escalates a local-first role to the strongest
        configured provider the same way, but only for roles whose
        division allows high-complexity escalation (PLANNER); ROUTER,
        GROUNDER and SUMMARIZER stay local whatever the complexity.
        Budgets (daily + monthly) are
        checked BEFORE every call; exhausted or cooling-down providers
        are skipped and the next provider in the role chain is tried.
        Secret (or unknown-label) data only ever reaches local-only
        providers; with no local provider configured this raises
        ValueError, like ``route``/``chat``.
        """
        role = self._normalize_role(role)
        chain = self.fallback_chain(role, sensitivity)
        if not chain:
            raise ValueError("secret data must not leave the machine")
        assigned = self._role_providers.get(role)
        cloud_candidates = [c for c in chain if c.is_cloud_backed]
        # High-complexity work escalates to the strongest provider, but
        # only for roles whose division allows it (PLANNER per
        # DEFAULT_ROLE_ASSIGNMENT; ROUTER/GROUNDER/SUMMARIZER stay local).
        may_escalate_high = (
            "high complexity" in DEFAULT_ROLE_ASSIGNMENT[role]["escalation_trigger"]
        )
        if complexity == "high" and may_escalate_high and cloud_candidates and chain[0].is_local_only:
            # High-complexity work escalates to the strongest provider.
            target = cloud_candidates[0]
            if not preapproved:
                return self._result(
                    role, target.name, None, target.cost_per_call, True, True
                )
            return self._complete_with(role, target, prompt, escalated=True)
        for index, config in enumerate(chain):
            if not self.is_available(config.name):
                continue
            if not self.check_budget(config.name):
                continue
            if (
                config.is_cloud_backed
                and not preapproved
                and config.name != assigned
            ):
                # Cloud escalation needs approval: show the cost, do not call.
                return self._result(
                    role, config.name, None, config.cost_per_call, True, index > 0
                )
            try:
                text = self._call_provider(config, prompt)
            except Exception:
                self.mark_failure(config.name)
                continue
            self.record_usage(config.name)
            self.note_success(role)
            return self._result(
                role, config.name, text, config.cost_per_call, False, index > 0
            )
        return self._result(
            role, None, None, 0.0, False, False,
            error="no provider available or budget exceeded",
        )

    def _complete_with(
        self, role: str, config: ProviderConfig, prompt: str, *, escalated: bool
    ) -> dict:
        """Call one already-approved provider for ``complete``."""
        if not self.is_available(config.name):
            return self._result(
                role, None, None, 0.0, False, False,
                error=f"provider {config.name} is in cooldown",
            )
        if not self.check_budget(config.name):
            return self._result(
                role, None, None, 0.0, False, False,
                error=f"budget exceeded for provider {config.name}",
            )
        try:
            text = self._call_provider(config, prompt)
        except Exception:
            self.mark_failure(config.name)
            return self._result(
                role, None, None, 0.0, False, False,
                error=f"provider {config.name} failed",
            )
        self.record_usage(config.name)
        self.note_success(role)
        return self._result(
            role, config.name, text, config.cost_per_call, False, escalated
        )

    def escalate(
        self,
        role: str,
        prompt: str,
        sensitivity: str,
        reason: str,
        *,
        preapproved: bool = False,
    ) -> dict:
        """Try the next provider in ``role``'s chain after the current one.

        ``reason`` is one of ESCALATION_REASONS ("schema-fail" after two
        failures -- see ``record_schema_failure``/``should_escalate`` --
        "loop", "verification-fail", "high-complexity", "low-confidence").
        A cloud/cloud-backed next provider WITHOUT pre-approval returns
        {"needs_approval": True, "cost_estimate": ...} WITHOUT calling
        it. Returns the same shape as ``complete`` (with "escalated" True
        on a successful escalation).
        """
        role = self._normalize_role(role)
        if not isinstance(reason, str) or not reason:
            raise ValueError("escalation reason must be a non-empty string")
        chain = self.fallback_chain(role, sensitivity)
        if not chain:
            raise ValueError("secret data must not leave the machine")
        current = self.role_provider(role)
        names = [c.name for c in chain]
        start = names.index(current) if current in names else 0
        for config in chain[start + 1:]:
            if not self.is_available(config.name):
                continue
            if not self.check_budget(config.name):
                continue
            if config.is_cloud_backed and not preapproved:
                result = self._result(
                    role, config.name, None, config.cost_per_call, True, False
                )
                result["reason"] = reason
                return result
            try:
                text = self._call_provider(config, prompt)
            except Exception:
                self.mark_failure(config.name)
                continue
            self.record_usage(config.name)
            self.note_success(role)
            result = self._result(
                role, config.name, text, config.cost_per_call, False, True
            )
            result["reason"] = reason
            return result
        result = self._result(
            role, None, None, 0.0, False, False,
            error="no further provider available for escalation",
        )
        result["reason"] = reason
        return result

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
