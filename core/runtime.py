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
    """Execute tools through policy checks and real-state verification."""

    def __init__(
        self,
        state_dir: str | Path | None = None,
        policy: Any = None,
        registry: dict | None = None,
    ):
        self.state_dir = Path(state_dir) if state_dir is not None else default_state_dir()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.policy = policy
        if registry is None:
            registry = self._load_registry()
        self.registry: dict = dict(registry)

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
            verified, evidence = False, "execution reported failure"
        ok = exec_ok and verified
        return finish()
