"""Agent runtime: policy-checked, verified tool execution.

Flow for every tool call (ARCHITECTURE.md section 3):
  1. kill switch check (via the policy object),
  2. unknown-tool check,
  3. argument validation against the tool's JSON Schema,
  4. policy check (separate policy process / engine -- the model never
     authorizes),
  5. execution,
  6. verification against real system state,
  7. audit logging (best effort; a failed audit never fails the call).

The runtime accepts EITHER a PolicyEngine or a PolicyClient as ``policy``
(duck-typed) and a registry dict of tools (duck-typed ToolSpec objects or
plain dicts). Policy and tool modules are imported lazily where needed so
this module works even if they are not present yet.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .memory import default_state_dir

_REDACT_MARKERS = ("secret", "password", "token", "api_key", "api-key")

_JSON_TYPE_CHECKS = {
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "array": lambda v: isinstance(v, list),
    "object": lambda v: isinstance(v, dict),
    "null": lambda v: v is None,
}


def _tool_attr(tool: Any, name: str, default: Any = None) -> Any:
    if isinstance(tool, dict):
        return tool.get(name, default)
    return getattr(tool, name, default)


def _redact_args(args: dict) -> dict:
    redacted = {}
    for key, value in args.items():
        if isinstance(key, str) and any(m in key.lower() for m in _REDACT_MARKERS):
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = value
    return redacted


def _is_network_call(tool_name: str, args: dict) -> bool:
    """Whether this exact call performs network access (tools registry).

    False when the registry is unavailable; policyd re-classifies the
    call itself on its side, so a missing registry is not a bypass.
    """
    try:
        from tools.definitions import is_network_call
    except ImportError:
        return False
    try:
        return bool(is_network_call(tool_name, args or {}))
    except Exception:
        return False


def _normalize_decision(decision: Any) -> dict:
    """Accept a dict or a Decision object; always return a plain dict."""
    if decision is None:
        return {"allowed": False, "reason": "policy returned no decision",
                "needs_approval": False}
    if isinstance(decision, dict):
        return {
            "allowed": bool(decision.get("allowed", False)),
            "reason": str(decision.get("reason") or ""),
            "needs_approval": bool(decision.get("needs_approval", False)),
        }
    return {
        "allowed": bool(getattr(decision, "allowed", False)),
        "reason": str(getattr(decision, "reason", "") or ""),
        "needs_approval": bool(getattr(decision, "needs_approval", False)),
    }


def _policy_killed(policy: Any) -> tuple[bool, str]:
    """Return (killed, error). Fail closed when the policy cannot be read."""
    if policy is None:
        return True, "no policy engine available"
    is_killed = getattr(policy, "is_killed", None)
    if callable(is_killed):
        try:
            return bool(is_killed()), ""
        except Exception as exc:  # policy unreachable: fail closed
            return True, f"policy status check failed: {exc}"
    status = getattr(policy, "status", None)
    if callable(status):
        try:
            result = status()
            if isinstance(result, dict):
                return bool(result.get("killed", False)), ""
            return False, ""
        except Exception as exc:
            return True, f"policy status check failed: {exc}"
    killed = getattr(policy, "killed", None)
    if isinstance(killed, bool):
        return killed, ""
    return False, ""


def _token_workdir(token: Any, state_dir: Path) -> Path:
    """First scoped folder from a capability token, else the state dir.

    Accepts a dict token (``folders`` / ``scope.folders`` / ``workdir``)
    or a CapabilityToken-like object with a ``scope_folders`` attribute.
    """
    folders: Any = None
    workdir: Any = None
    if isinstance(token, dict):
        workdir = token.get("workdir")
        folders = token.get("folders")
        if folders is None:
            scope = token.get("scope")
            if isinstance(scope, dict):
                folders = scope.get("folders")
        if folders is None:
            folders = token.get("scope_folders")
    else:
        folders = getattr(token, "scope_folders", None)
        workdir = getattr(token, "workdir", None)
    if isinstance(workdir, str) and workdir:
        return Path(workdir)
    if isinstance(folders, (list, tuple)) and folders:
        first = folders[0]
        if isinstance(first, str) and first:
            return Path(first)
    return state_dir


def _validate_args(tool: Any, args: Any) -> str | None:
    """Validate args against the tool schema. Return an error string or None."""
    if not isinstance(args, dict):
        return "args must be an object"
    schema = _tool_attr(tool, "schema") or {}
    if not isinstance(schema, dict):
        return None
    properties = schema.get("properties") or {}
    required = schema.get("required") or []
    if not isinstance(properties, dict):
        properties = {}
    if not isinstance(required, list):
        required = []
    for name in required:
        if name not in args:
            return f"missing required argument: {name}"
    for name, value in args.items():
        if name not in properties:
            return f"unexpected argument: {name}"
        spec = properties.get(name) or {}
        expected = spec.get("type") if isinstance(spec, dict) else None
        if expected is None:
            continue
        check = _JSON_TYPE_CHECKS.get(expected)
        if check is not None and not check(value):
            return f"argument {name!r} must be of type {expected}"
    return None


def _split_verify(outcome: Any) -> tuple[bool, str]:
    """Normalize verify() output: bool, (bool, evidence) or dict."""
    if isinstance(outcome, bool):
        return outcome, ""
    if isinstance(outcome, (tuple, list)) and len(outcome) >= 1:
        verified = bool(outcome[0])
        evidence = str(outcome[1]) if len(outcome) > 1 else ""
        return verified, evidence
    if isinstance(outcome, dict):
        return (bool(outcome.get("verified", False)),
                str(outcome.get("evidence") or ""))
    return bool(outcome), ""


class Runtime:
    """Execute tools through policy checks and real-state verification.

    Phase 2: when a ``gateway`` is supplied *and* it has providers
    configured, :meth:`run_task` plans through the gateway roles
    (PLANNER, then VERIFIER on failure) and escalates once on a
    verification failure before reporting. When no gateway is
    configured, ``run_task`` runs caller-supplied steps directly --
    Phase 1 behaviour, no model needed. :meth:`run_tool` is unchanged
    either way: it always goes through the policy check, execution and
    verification, gateway or not.
    """

    def __init__(
        self,
        state_dir: str | Path | None = None,
        policy: Any = None,
        registry: dict | None = None,
        gateway: Any = None,
    ):
        self.state_dir = Path(state_dir) if state_dir is not None else default_state_dir()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.policy = policy
        self.gateway = gateway
        if registry is None:
            registry = self._load_registry()
        self.registry: dict = dict(registry)

    # -- gateway helpers (Phase 2 contracts, Phase 1 fallback) ---------
    def _gateway_configured(self) -> bool:
        """True when a gateway with at least one provider is attached."""
        if self.gateway is None:
            return False
        configs = getattr(self.gateway, "configs", None)
        return bool(configs)

    def _gateway_complete(
        self, role: str, prompt: str, sensitivity: str = "public"
    ) -> dict:
        """One gateway call, normalized.

        Prefers the Phase 2 contract ``Gateway.complete(role, prompt,
        sensitivity)`` -> {"text","provider","role","escalated",
        "needs_approval",...}; falls back to the Phase 1
        ``Gateway.chat(role, messages, sensitivity)`` shape. Returns a
        dict with "ok", "text", "provider", "escalated", "needs_approval"
        and "error" (None on success).
        """
        if not self._gateway_configured():
            return {"ok": False, "text": None, "provider": None,
                    "escalated": False, "needs_approval": False,
                    "error": "no gateway configured"}
        complete = getattr(self.gateway, "complete", None)
        try:
            if callable(complete):
                raw = complete(role, prompt, sensitivity)
            else:
                chat = getattr(self.gateway, "chat", None)
                if not callable(chat):
                    return {"ok": False, "text": None, "provider": None,
                            "escalated": False, "needs_approval": False,
                            "error": "gateway has no complete() or chat()"}
                raw = chat(role, [{"role": "user", "content": prompt}],
                           sensitivity)
        except ValueError as exc:
            # Secret routing failure etc: fail closed, do not retry.
            return {"ok": False, "text": None, "provider": None,
                    "escalated": False, "needs_approval": False,
                    "error": str(exc)}
        except Exception as exc:
            return {"ok": False, "text": None, "provider": None,
                    "escalated": False, "needs_approval": False,
                    "error": f"gateway call failed: {exc}"}
        if not isinstance(raw, dict):
            return {"ok": False, "text": None, "provider": None,
                    "escalated": False, "needs_approval": False,
                    "error": "gateway returned an unexpected response"}
        if raw.get("needs_approval"):
            return {"ok": False, "text": raw.get("text"),
                    "provider": raw.get("provider"),
                    "escalated": bool(raw.get("escalated", False)),
                    "needs_approval": True,
                    "error": "gateway call needs approval"}
        if raw.get("ok") is False:
            return {"ok": False, "text": raw.get("text"),
                    "provider": raw.get("provider"),
                    "escalated": bool(raw.get("escalated", False)),
                    "needs_approval": False,
                    "error": raw.get("error") or "gateway call failed"}
        text = raw.get("text")
        if not isinstance(text, str) or not text.strip():
            return {"ok": False, "text": None,
                    "provider": raw.get("provider"),
                    "escalated": bool(raw.get("escalated", False)),
                    "needs_approval": False,
                    "error": raw.get("error") or "gateway returned no text"}
        return {"ok": True, "text": text, "provider": raw.get("provider"),
                "role": raw.get("role", role),
                "escalated": bool(raw.get("escalated", False)),
                "needs_approval": False, "error": None}

    def _gateway_escalate(
        self, role: str, prompt: str, sensitivity: str, reason: str
    ) -> dict:
        """Escalate once to the next provider in the role chain.

        Prefers the Phase 2 contract ``Gateway.escalate(role, prompt,
        sensitivity, reason)``. Falls back to asking the next provider
        in ``fallback_chain(role, sensitivity)`` via ``complete``/``chat``
        (Phase 1 gateways have no escalate and route a single provider,
        so the fallback re-routes and reports the hop explicitly).
        The returned dict is the normalized ``_gateway_complete`` shape
        with "escalated": True when a different provider answered.
        """
        if not self._gateway_configured():
            return {"ok": False, "text": None, "provider": None,
                    "escalated": False, "needs_approval": False,
                    "error": "no gateway configured"}
        escalate = getattr(self.gateway, "escalate", None)
        if callable(escalate):
            try:
                raw = escalate(role, prompt, sensitivity, reason)
            except Exception as exc:
                return {"ok": False, "text": None, "provider": None,
                        "escalated": False, "needs_approval": False,
                        "error": f"escalation failed: {exc}"}
            if not isinstance(raw, dict):
                return {"ok": False, "text": None, "provider": None,
                        "escalated": False, "needs_approval": False,
                        "error": "escalation returned an unexpected response"}
            if raw.get("needs_approval"):
                return {"ok": False, "text": raw.get("text"),
                        "provider": raw.get("provider"),
                        "escalated": bool(raw.get("escalated", False)),
                        "needs_approval": True,
                        "error": "escalated call needs approval"}
            text = raw.get("text")
            if raw.get("ok") is False or not isinstance(text, str) or not text.strip():
                return {"ok": False, "text": None,
                        "provider": raw.get("provider"),
                        "escalated": bool(raw.get("escalated", False)),
                        "needs_approval": False,
                        "error": raw.get("error") or "escalation failed"}
            return {"ok": True, "text": text,
                    "provider": raw.get("provider"), "role": raw.get("role", role),
                    "escalated": True, "needs_approval": False, "error": None}
        # Phase 1 fallback: the Phase 1 gateway has no escalate() and its
        # route() always picks the head of the chain, so there is no way
        # to address the *next* provider directly. Report that honestly
        # instead of re-calling the same provider and pretending the
        # call escalated. (Phase 2 gateways implement escalate().)
        chain = []
        fallback_chain = getattr(self.gateway, "fallback_chain", None)
        if callable(fallback_chain):
            try:
                chain = list(fallback_chain(role, sensitivity) or [])
            except Exception:
                chain = []
        if len(chain) < 2:
            return {"ok": False, "text": None, "provider": None,
                    "escalated": False, "needs_approval": False,
                    "error": "no further provider to escalate to"}
        return {"ok": False, "text": None, "provider": None,
                "escalated": False, "needs_approval": False,
                "error": ("gateway does not support escalation "
                          "(no escalate(); single-provider routing)")}

    @staticmethod
    def _parse_plan(text: str) -> list[dict] | None:
        """Parse gateway plan text into [{"tool","args"}] steps.

        Accepts a bare JSON list, or {"steps": [...]} / {"plan": [...]}.
        Returns None when the text is not a usable plan (caller decides
        whether to fall back to caller-supplied steps or fail).
        """
        try:
            parsed = json.loads(text)
        except ValueError:
            return None
        if isinstance(parsed, dict):
            parsed = parsed.get("steps", parsed.get("plan"))
        if not isinstance(parsed, list):
            return None
        steps: list[dict] = []
        for item in parsed:
            if not isinstance(item, dict) or not item.get("tool"):
                return None
            args = item.get("args", {})
            if not isinstance(args, dict):
                return None
            steps.append({"tool": str(item["tool"]), "args": args})
        return steps

    def run_task(
        self,
        task: str,
        token: Any,
        steps: list[dict] | None = None,
        sensitivity: str = "public",
    ) -> dict:
        """Plan (via gateway when configured) and execute a task.

        ``steps`` is a caller-supplied plan of {"tool","args"} dicts.
        With a gateway, the PLANNER role produces the plan; if its
        output is unusable and caller steps were given, those are used
        instead (recorded in "plan_source"); if neither yields a plan,
        the task fails without executing anything. Every step runs
        through :meth:`run_tool` (policy + verify). On a step whose
        execution or verification fails, the VERIFIER role is escalated
        to once via the gateway and the step is retried once; a second
        failure stops the task and is reported. Returns
        {"ok","verified","steps","escalated","plan_source","error"}.
        """
        escalated = False
        plan_source = "direct"
        plan_steps: list[dict] = list(steps or [])
        if self._gateway_configured():
            plan = self._gateway_complete(
                "PLANNER",
                "Plan this task as a JSON list of {\"tool\",\"args\"} steps "
                f"using only tools from the registry. Task: {task}",
                sensitivity,
            )
            parsed = self._parse_plan(plan["text"]) if plan.get("ok") else None
            if parsed is not None:
                plan_steps = parsed
                plan_source = "gateway"
            elif plan_steps:
                plan_source = "direct (gateway plan unusable)"
            else:
                error = plan.get("error") or "gateway returned unusable plan"
                out = {"ok": False, "verified": False, "steps": [],
                       "escalated": False, "plan_source": "gateway",
                       "error": error}
                self._audit({"type": "task", "task": task, "ok": False,
                             "escalated": False, "plan_source": "gateway",
                             "error": error})
                return out
        if not plan_steps:
            error = ("no gateway configured and no steps provided"
                     if not self._gateway_configured()
                     else "empty plan")
            out = {"ok": False, "verified": False, "steps": [],
                   "escalated": False, "plan_source": plan_source,
                   "error": error}
            self._audit({"type": "task", "task": task, "ok": False,
                         "escalated": False, "plan_source": plan_source,
                         "error": error})
            return out

        results: list[dict] = []
        all_ok = True
        all_verified = True
        error: str | None = None
        for step in plan_steps:
            tool_name = step.get("tool", "")
            args = step.get("args", {})
            outcome = self.run_tool(token, tool_name, args)
            step_record: dict = {"tool": tool_name, "args": _redact_args(args),
                                 "ok": outcome.get("ok"),
                                 "verified": outcome.get("verified"),
                                 "decision": outcome.get("decision"),
                                 "escalated": False}
            if not outcome.get("ok") or not outcome.get("verified"):
                # Verification/execution failure: escalate once, retry once.
                if self._gateway_configured():
                    esc = self._gateway_escalate(
                        "VERIFIER",
                        f"Tool {tool_name} failed verification for task: {task}. "
                        f"Evidence: {outcome.get('evidence') or outcome.get('decision', {}).get('reason', '')}. "
                        "Confirm whether the step should be retried and why.",
                        sensitivity,
                        reason="verification failed",
                    )
                    step_record["escalated"] = True
                    step_record["escalation"] = {
                        "ok": esc.get("ok"), "provider": esc.get("provider"),
                        "needs_approval": esc.get("needs_approval"),
                        "error": esc.get("error"),
                    }
                    escalated = True
                    if esc.get("ok") and not esc.get("needs_approval"):
                        retry = self.run_tool(token, tool_name, args)
                        step_record["retry"] = {
                            "ok": retry.get("ok"),
                            "verified": retry.get("verified"),
                            "decision": retry.get("decision"),
                        }
                        outcome = retry
                        step_record["ok"] = retry.get("ok")
                        step_record["verified"] = retry.get("verified")
                        step_record["decision"] = retry.get("decision")
            results.append(step_record)
            if not outcome.get("ok") or not outcome.get("verified"):
                all_ok = False
                all_verified = False
                decision = outcome.get("decision") or {}
                tool_error = (outcome.get("result") or {}).get("error")
                if decision.get("allowed"):
                    # The step was allowed but the tool itself failed
                    # (scope, execution, verification): report the
                    # tool's own error, never the decision reason --
                    # "allowed" is not a failure reason.
                    detail = (tool_error or outcome.get("evidence")
                              or "not verified")
                else:
                    detail = (decision.get("reason") or tool_error
                              or "not verified")
                error = f"step {tool_name!r} failed: {detail}"
                break
        out = {"ok": all_ok, "verified": all_verified, "steps": results,
               "escalated": escalated, "plan_source": plan_source,
               "error": error}
        self._audit({"type": "task", "task": task, "ok": all_ok,
                     "verified": all_verified, "escalated": escalated,
                     "plan_source": plan_source, "error": error})
        return out

    @staticmethod
    def _load_registry() -> dict:
        """Best-effort import of the tool registry (may not exist yet)."""
        try:
            from tools.definitions import TOOLS  # type: ignore[import-not-found]

            return dict(TOOLS) if isinstance(TOOLS, dict) else {}
        except Exception:
            return {}

    def list_tools(self) -> list[dict]:
        tools = []
        for name, tool in self.registry.items():
            tools.append(
                {
                    "name": name,
                    "level": _tool_attr(tool, "level", 0),
                    "schema": _tool_attr(tool, "schema", {}) or {},
                    "description": _tool_attr(tool, "description", "") or "",
                }
            )
        return tools

    def _audit(self, event: dict) -> str | None:
        """Append an audit event. Returns an error string, or None on success.

        Uses policy.audit.AuditLog when available; falls back to a plain
        JSONL append only if the AuditLog module itself cannot be imported.
        Never raises.
        """
        try:
            from policy.audit import AuditLog  # type: ignore[import-not-found]
        except Exception as exc:
            try:
                entry = dict(event)
                entry.setdefault(
                    "ts", datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                )
                with open(self.state_dir / "audit.jsonl", "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry) + "\n")
                return None
            except Exception as fallback_exc:
                return f"audit failed: {fallback_exc} (AuditLog unavailable: {exc})"
        try:
            AuditLog(self.state_dir / "audit.jsonl").append(event)
            return None
        except Exception as exc:
            return f"audit failed: {exc}"

    def run_tool(
        self,
        token: Any,
        tool_name: str,
        args: dict,
        tainted: bool = False,
    ) -> dict:
        decision: dict = {"allowed": False, "reason": "", "needs_approval": False}
        result: dict = {}
        evidence = ""
        ok = False
        verified = False
        audit_error: str | None = None

        def finish() -> dict:
            nonlocal audit_error
            event = {
                "type": "tool_call",
                "tool": tool_name,
                "args": _redact_args(args if isinstance(args, dict) else {}),
                "decision": decision,
                "ok": ok,
                "verified": verified,
                "evidence": evidence,
            }
            audit_error = self._audit(event)
            out = {
                "ok": ok,
                "verified": verified,
                "decision": decision,
                "result": result,
                "evidence": evidence,
            }
            if audit_error is not None:
                out["audit_error"] = audit_error
            return out

        # (a) Kill switch.
        killed, kill_error = _policy_killed(self.policy)
        if killed:
            decision = {
                "allowed": False,
                "reason": kill_error or "kill switch active",
                "needs_approval": False,
            }
            return finish()

        # (b) Unknown tool.
        tool = self.registry.get(tool_name)
        if tool is None:
            decision = {
                "allowed": False,
                "reason": "unknown tool",
                "needs_approval": False,
            }
            return finish()

        # (c) Argument validation.
        arg_error = _validate_args(tool, args)
        if arg_error is not None:
            decision = {
                "allowed": False,
                "reason": f"invalid args: {arg_error}",
                "needs_approval": False,
            }
            return finish()

        # (d) Policy check.
        level = _tool_attr(tool, "level", 0)
        try:
            check = getattr(self.policy, "check", None)
            if not callable(check):
                raise AttributeError("policy object has no check() method")
            try:
                decision = _normalize_decision(
                    check(token, tool_name, level, args, tainted,
                          network_call=_is_network_call(tool_name, args))
                )
            except TypeError:
                # Older / test-double policy engines that do not accept
                # the network_call kwarg (5-arg check).
                decision = _normalize_decision(
                    check(token, tool_name, level, args, tainted)
                )
        except Exception as exc:
            decision = {
                "allowed": False,
                "reason": f"policy check failed: {exc}",
                "needs_approval": False,
            }
            return finish()
        if not decision["allowed"]:
            return finish()

        # (e) Execute.
        workdir = _token_workdir(token, self.state_dir)
        ctx = {"state_dir": str(self.state_dir), "workdir": str(workdir), "token": token}
        execute = _tool_attr(tool, "execute")
        try:
            if not callable(execute):
                raise AttributeError(f"tool {tool_name!r} has no execute() method")
            raw_result = execute(args, ctx)
        except Exception as exc:
            result = {"ok": False, "error": f"execute failed: {exc}"}
            return finish()
        if isinstance(raw_result, dict):
            result = raw_result
        else:
            result = {"ok": True, "value": raw_result}
        exec_ok = bool(result.get("ok", True))

        # (f) Verify against real state (only if execution reported success).
        if exec_ok:
            verify = _tool_attr(tool, "verify")
            try:
                if not callable(verify):
                    raise AttributeError(f"tool {tool_name!r} has no verify() method")
                verified, evidence = _split_verify(verify(args, result, ctx))
            except Exception as exc:
                verified, evidence = False, f"verify failed: {exc}"
        else:
            # Execution reported failure: carry the tool's own error
            # into the evidence so callers see *why* it failed, not
            # just that it did. (Before this, the evidence was the
            # generic "execution reported failure" and run_task then
            # reported the decision reason "allowed" instead.)
            verified, evidence = False, result.get("error") or "execution reported failure"
        ok = exec_ok and verified
        return finish()
