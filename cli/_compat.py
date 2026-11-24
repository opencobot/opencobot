"""Compatibility layer: load the real policy/tools/core slices.

R-009: there is no fallback any more. ``cli/_fallback.py`` (the
duplicate in-process policy engine and tool registry) was deleted,
and every loader here FAILS LOUDLY — :class:`PolicyUnavailable` /
:class:`RuntimeUnavailable` with a clear message — when the real
module is missing, instead of silently running a weaker in-process
copy. The real modules are guaranteed installed by ``pyproject.toml``
(``packages`` lists ``core``, ``policy``, ``tools``, ``adapters``,
``cli``), so a missing module means a broken install, not a mode to
work around.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

__all__ = [
    "PolicyUnavailable",
    "RuntimeUnavailable",
    "default_state_dir",
    "get_tools",
    "get_tool",
    "get_policy_client",
    "get_policy_engine",
    "get_runtime",
    "get_audit_log",
    "call_check",
    "call_issue_token",
    "call_approve",
    "tool_is_network_call",
    "ensure_policyd",
    "token_scope_folders",
    "normalize_check_result",
    "adapt_token_for_runtime",
    "normalize_run_result",
    "public_token_record",
]


class PolicyUnavailable(Exception):
    """The policy engine is not reachable (exit code 2 in the CLI)."""


class RuntimeUnavailable(Exception):
    """The agent runtime could not be constructed."""


def default_state_dir():
    """``$OPENCOBOT_STATE`` or ``~/.opencobot`` (per the task brief)."""
    return Path(os.environ.get("OPENCOBOT_STATE") or "~/.opencobot").expanduser()


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

def _normalize_tool(entry):
    if isinstance(entry, dict):
        schema = (entry.get("inputSchema") or entry.get("input_schema")
                  or entry.get("schema") or entry.get("parameters") or {})
        return {"name": str(entry.get("name")),
                "level": int(entry.get("level", 0)),
                "description": str(entry.get("description", "")),
                "inputSchema": schema,
                "category": str(entry.get("category", ""))}
    return {"name": str(getattr(entry, "name", "")),
            "level": int(getattr(entry, "level", 0)),
            "description": str(getattr(entry, "description", "")),
            "inputSchema": (getattr(entry, "inputSchema", None)
                            or getattr(entry, "input_schema", None)
                            or getattr(entry, "schema", None)
                            or getattr(entry, "parameters", None) or {}),
            "category": str(getattr(entry, "category", ""))}


def _real_tools():
    """Return the real registry (list of normalized dicts) or ``None``."""
    try:
        import tools.definitions as definitions
    except ImportError:
        return None
    raw = None
    if hasattr(definitions, "list_tools"):
        try:
            raw = definitions.list_tools()
        except Exception:
            raw = None
    if raw is None and hasattr(definitions, "TOOLS"):
        raw = definitions.TOOLS
    if raw is None:
        return None
    if isinstance(raw, dict):
        raw = list(raw.values())
    try:
        tools = [_normalize_tool(t) for t in raw]
    except Exception:
        return None
    tools = [t for t in tools if t["name"]]
    return tools or None


def get_tools():
    """Tool registry from the real ``tools.definitions``.

    Raises :class:`RuntimeUnavailable` when the real registry cannot
    be imported — there is no fallback registry (R-009).
    """
    tools = _real_tools()
    if tools is None:
        raise RuntimeUnavailable(
            "real tool registry (tools.definitions) is not installed; "
            "reinstall OpenCobot — the CLI never runs without it")
    return tools


def get_tool(name):
    for tool in get_tools():
        if tool["name"] == name:
            return tool
    return None


def _real_registry_object():
    """The object to hand to a real ``Runtime`` (module if present)."""
    try:
        import tools.definitions as definitions
        return definitions
    except ImportError:
        return None


# ---------------------------------------------------------------------------
# Policy / runtime loaders (lazy imports inside functions, per the brief)
# ---------------------------------------------------------------------------

def get_policy_client(state_dir):
    """``policy.client.PolicyClient``; fails loudly when not installed (R-009)."""
    try:
        from policy.client import PolicyClient
    except ImportError as exc:
        raise PolicyUnavailable(
            "real policy client (policy.client) is not installed; "
            "reinstall OpenCobot — the CLI never runs without it"
        ) from exc
    try:
        return PolicyClient(state_dir)
    except Exception as exc:
        raise PolicyUnavailable(f"policy client failed to start: {exc}") from exc


def get_policy_engine(state_dir):
    """``policy.engine.PolicyEngine``; fails loudly when not installed (R-009)."""
    try:
        from policy.engine import PolicyEngine
    except ImportError as exc:
        raise PolicyUnavailable(
            "real policy engine (policy.engine) is not installed; "
            "reinstall OpenCobot — the CLI never runs without it"
        ) from exc
    try:
        return PolicyEngine(state_dir)
    except Exception as exc:
        raise PolicyUnavailable(f"policy engine failed to start: {exc}") from exc


def get_runtime(state_dir, policy=None, registry=None):
    """``core.runtime.Runtime``; fails loudly when not installed (R-009)."""
    try:
        from core.runtime import Runtime
    except ImportError as exc:
        raise RuntimeUnavailable(
            "real runtime (core.runtime) is not installed; "
            "reinstall OpenCobot — the CLI never runs without it"
        ) from exc
    try:
        return Runtime(state_dir, policy, registry)
    except Exception as exc:
        raise RuntimeUnavailable(f"runtime failed to start: {exc}") from exc


def get_audit_log(state_dir):
    """``policy.audit.AuditLog`` at ``<state_dir>/audit.jsonl``.

    Fails loudly when the real module is not installed (R-009).
    """
    try:
        from policy.audit import AuditLog
    except ImportError as exc:
        raise PolicyUnavailable(
            "real audit log (policy.audit) is not installed; "
            "reinstall OpenCobot — the CLI never runs without it"
        ) from exc
    return AuditLog(Path(state_dir) / "audit.jsonl")


# ---------------------------------------------------------------------------
# Defensive call adapters (real method signatures may vary slightly)
# ---------------------------------------------------------------------------

def normalize_check_result(result):
    if isinstance(result, bool):
        return {"allowed": result, "needs_approval": not result,
                "reason": "allowed" if result else "denied", "level": None}
    if isinstance(result, dict):
        out = {"allowed": bool(result.get("allowed", False)),
               "needs_approval": bool(result.get("needs_approval", False)),
               "reason": str(result.get("reason", "")),
               "level": result.get("level")}
        if "tool" in result:
            out["tool"] = result["tool"]
        return out
    return {"allowed": bool(getattr(result, "allowed", False)),
            "needs_approval": bool(getattr(result, "needs_approval", False)),
            "reason": str(getattr(result, "reason", result)),
            "level": getattr(result, "level", None)}


def tool_is_network_call(tool_name, args):
    """Whether this exact call performs network access (tools registry).

    False when the registry is unavailable — callers must not treat
    that as a licence to run a network call; policyd re-classifies
    the call itself on its side.
    """
    try:
        from tools.definitions import is_network_call
    except ImportError:
        return False
    try:
        return bool(is_network_call(tool_name, args or {}))
    except Exception:
        return False


def call_check(client, tool_name, level, args, token=None, tainted=False,
               network_call=False):
    """Call ``client.check`` tolerating the likely signature shapes."""
    check = getattr(client, "check")
    try:
        return normalize_check_result(
            check(tool_name=tool_name, level=level, args=args,
                  token=token, tainted=tainted, network_call=network_call))
    except TypeError:
        pass
    try:
        return normalize_check_result(
            check(tool_name=tool_name, level=level, args=args,
                  token=token, tainted=tainted))
    except TypeError:
        pass
    try:
        return normalize_check_result(check(tool_name, level, args))
    except TypeError:
        pass
    return normalize_check_result(check(tool_name, level))


def call_issue_token(client, folders, tools, duration, network=False):
    """Call ``client.issue_token`` tolerating kwarg/positional shapes.

    Real signature (policy.client / policy.engine):
    ``issue_token(scope_folders, tools, duration_seconds=600,
    network=False)``. ``network`` defaults False (fail closed).
    """
    issue = getattr(client, "issue_token")
    for kwargs in ({"scope_folders": folders, "tools": tools,
                    "duration_seconds": duration, "network": bool(network)},
                   {"scope_folders": folders, "tools": tools,
                    "duration_seconds": duration},
                   {"folders": folders, "tools": tools, "duration": duration}):
        try:
            return issue(**kwargs)
        except TypeError:
            continue
    return issue(folders, tools, duration)


def call_approve(client, token_id, tool_name, level=None, args=None,
                 duration_seconds=600):
    """Call ``client.approve`` for exactly one call (R-007).

    Real signature (policy.client / policy.engine):
    ``approve(token_id, tool_name, level, args, duration_seconds=600)``
    -> approval id. The approval is bound to (token, tool, level,
    argument hash); callers must pass the level and the exact
    arguments of the call being approved.
    """
    approve = getattr(client, "approve")
    try:
        return approve(token_id, tool_name, level, args or {},
                       duration_seconds)
    except TypeError:
        return approve(token_id=token_id, tool_name=tool_name, level=level,
                       args=args or {}, duration_seconds=duration_seconds)


# ---------------------------------------------------------------------------
# policyd process management
# ---------------------------------------------------------------------------

def _find_spec(name):
    """``find_spec`` that returns None instead of raising when a parent
    package does not exist at all (stock ``find_spec`` raises
    ``ModuleNotFoundError`` in that case)."""
    try:
        return importlib.util.find_spec(name)
    except (ImportError, ValueError):
        return None


def _policyd_module_available():
    return _find_spec("policy.policyd") is not None


def _policyd_ready(state_dir):
    """True when a ``policyd`` is already reachable from ``state_dir``.

    BUG-K: on POSIX the Unix socket file is the readiness signal,
    but on Windows policyd serves on a named pipe and never creates
    a socket file — so on Windows probe it with a real
    ``PolicyClient.status()`` call instead. A missing pipe, a missing
    auth file and a rejected token all mean "not ready yet". Imports
    are lazy: this module must stay importable without the policy
    package (see :func:`get_policy_client`).
    """
    from core.transport import is_windows

    if not is_windows():
        return (Path(state_dir) / "policyd.sock").exists()
    try:
        from policy.client import PolicyClient
    except ImportError:
        return False
    try:
        PolicyClient(state_dir).status()
    except Exception:
        return False
    return True


def ensure_policyd(state_dir, wait_seconds=5.0):
    """Make sure ``policyd`` is reachable.

    Returns ``(status, proc)`` where status is ``"running"`` (a
    policyd is already reachable, or the real ``policyd`` was just
    started and became reachable) or ``"failed"`` (the real
    ``policyd`` was started but did not become reachable within
    ``wait_seconds``). Raises :class:`PolicyUnavailable` when the
    real ``policyd`` module is not installed — there is no
    in-process fallback any more (R-009).
    """
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    if _policyd_ready(state_dir):
        return "running", None
    if not _policyd_module_available():
        raise PolicyUnavailable(
            "real policyd module (policy.policyd) is not installed; "
            "reinstall OpenCobot — the CLI never runs without it")
    log_path = state_dir / "policyd.log"
    log_fh = open(log_path, "ab")
    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", "policy.policyd", "--state-dir", str(state_dir)],
            stdin=subprocess.DEVNULL, stdout=log_fh, stderr=log_fh,
            start_new_session=True, close_fds=True)
    finally:
        log_fh.close()
    (state_dir / "policyd.pid").write_text(str(proc.pid), encoding="utf-8")
    deadline = time.time() + wait_seconds
    while time.time() < deadline:
        if _policyd_ready(state_dir):
            return "running", proc
        if proc.poll() is not None:
            return "failed", proc
        time.sleep(0.1)
    return ("running", proc) if _policyd_ready(state_dir) else ("failed", proc)


# ---------------------------------------------------------------------------
# Token scoping helpers
# ---------------------------------------------------------------------------

def token_scope_folders(args, cwd=None):
    """Folders for a least-privilege token: cwd plus any existing paths in args.

    The user explicitly named those paths on the command line / in the
    MCP call, so scoping the token to them (plus the working directory)
    is least privilege without making ``tool run`` unusable from a
    different cwd (e.g. tests listing a tmp dir).
    """
    cwd = Path(cwd or os.getcwd()).expanduser().resolve()
    folders = {str(cwd)}
    for value in (args or {}).values():
        if isinstance(value, str) and value:
            candidate = Path(value).expanduser()
            if candidate.exists():
                resolved = candidate.resolve()
                folders.add(str(resolved if resolved.is_dir() else resolved.parent))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str) and item:
                    candidate = Path(item).expanduser()
                    if candidate.exists():
                        resolved = candidate.resolve()
                        folders.add(str(resolved if resolved.is_dir() else resolved.parent))
    return sorted(folders)


# ---------------------------------------------------------------------------
# Token adaptation for the tool layer
# ---------------------------------------------------------------------------

def adapt_token_for_runtime(token):
    """Return a token the tool layer can scope-check.

    Known cross-slice mismatch (reported, not silently papered over):
    the real ``CapabilityToken`` carries its folders as
    ``scope_folders``, but ``tools.definitions._token_roots`` only looks
    for ``folders`` / ``allowed_roots`` / ``allowed_folders`` / ``scope``
    / ``roots`` — so a plain ``CapabilityToken`` is treated as scoped to
    the workdir only and every other path is denied. This adapter
    exposes the same folders under the ``folders`` name the tools
    understand, without changing the token's identity, expiry or tools
    (policy checks use the inherited methods, so decisions are
    unchanged). The proper fix belongs in ``tools/definitions.py``
    (add ``scope_folders`` to that key list); until then this keeps the
    CLI/MCP usable against the real registry.
    """
    if token is None:
        return token
    if isinstance(token, dict):
        if "folders" not in token and "scope_folders" in token:
            token = {**token, "folders": list(token.get("scope_folders") or [])}
        return token
    try:
        from policy.tokens import CapabilityToken
    except ImportError:
        return token
    if isinstance(token, CapabilityToken):
        return _ScopedToken(
            token_id=token.token_id,
            scope_folders=list(token.scope_folders),
            tools=list(token.tools),
            network=bool(token.network),
            expires_at=float(token.expires_at),
            issued_at=float(token.issued_at),
        )
    return token


class _ScopedToken:
    """Placeholder replaced below (kept importable for type checks)."""


try:
    from policy.tokens import CapabilityToken as _BaseToken

    class _ScopedToken(_BaseToken):
        """A CapabilityToken that also exposes ``folders`` for the tools layer."""

        @property
        def folders(self):
            return list(self.scope_folders)

except ImportError:
    _ScopedToken = None  # type: ignore[assignment]


def _token_id_of(token):
    if token is None:
        return None
    if isinstance(token, dict):
        return token.get("token_id")
    return getattr(token, "token_id", None)


def _token_expiry_iso(token):
    """ISO-8601 expiry for a token (CapabilityToken or dict), or None."""
    import time
    from datetime import datetime, timezone

    expires_at = None
    if isinstance(token, dict):
        if isinstance(token.get("expiry"), str):
            return token["expiry"]
        expires_at = token.get("expires_at")
    else:
        expires_at = getattr(token, "expires_at", None)
    if expires_at is None:
        return None
    try:
        return datetime.fromtimestamp(float(expires_at), timezone.utc).isoformat()
    except (TypeError, ValueError):
        return None


def public_token_record(token, duration_seconds=None):
    """Public token info for printing: never includes any secret."""
    if isinstance(token, dict):
        folders = token.get("folders") or token.get("scope_folders") or []
        tools = token.get("tools") or []
        return {"token_id": token.get("token_id"),
                "expiry": _token_expiry_iso(token),
                "folders": list(folders), "tools": list(tools),
                "network": bool(token.get("network", False)),
                "duration_seconds": duration_seconds}
    folders = list(getattr(token, "scope_folders", []) or [])
    tools = list(getattr(token, "tools", []) or [])
    return {"token_id": _token_id_of(token),
            "expiry": _token_expiry_iso(token),
            "folders": folders, "tools": tools,
            "network": bool(getattr(token, "network", False)),
            "duration_seconds": duration_seconds}


def normalize_run_result(result, tool_name=None):
    """Normalize a runtime result to one flat shape.

    Real ``core.runtime.Runtime.run_tool`` returns
    ``{ok, verified, decision, result: {ok, data, error}, evidence}``.
    This returns the flat shape with ``result`` set to the tool's data
    payload and ``error`` always present (``None`` on success). When the
    decision says ``needs_approval``, the error reads ``needs approval:
    <reason>`` so callers/tests can rely on that wording.
    """
    if not isinstance(result, dict):
        return {"ok": bool(getattr(result, "ok", False)),
                "verified": bool(getattr(result, "verified", False)),
                "tool": tool_name,
                "result": getattr(result, "result", None),
                "error": getattr(result, "error", None)}
    decision = result.get("decision") or {}
    if not isinstance(decision, dict):
        decision = {"allowed": bool(getattr(decision, "allowed", False)),
                    "reason": str(getattr(decision, "reason", "")),
                    "needs_approval": bool(getattr(decision, "needs_approval", False))}
    inner = result.get("result")
    if isinstance(inner, dict) and ("data" in inner or "error" in inner):
        data = inner.get("data", {})
        inner_error = inner.get("error")
    else:
        data = inner
        inner_error = None
    ok = bool(result.get("ok", False))
    verified = bool(result.get("verified", False))
    error = result.get("error") or inner_error
    if not ok and error is None:
        error = decision.get("reason") or "tool run failed"
    if not ok and decision.get("needs_approval"):
        reason = decision.get("reason") or error or ""
        error = f"needs approval: {reason}" if reason else "needs approval"
    return {"ok": ok, "verified": verified,
            "tool": result.get("tool", tool_name),
            "result": data, "error": error,
            "decision": decision,
            "evidence": result.get("evidence", "")}

def audit_verify(log):
    """``(ok, count, errors)`` from the real ``AuditLog``.

    ``policy.audit.AuditLog.verify()`` returns ``(bool, [errors])``.
    """
    verify = getattr(log, "verify", None) or getattr(log, "audit_verify", None)
    result = verify()
    if isinstance(result, tuple):
        ok = bool(result[0])
        if len(result) == 2 and isinstance(result[1], list):
            errors = list(result[1])
            count = len(audit_read_last(log, 10 ** 9))
            return ok, count, errors
        count = int(result[1]) if len(result) > 1 else 0
        error = result[2] if len(result) > 2 else None
        return ok, count, [error] if error else []
    if isinstance(result, dict):
        return (bool(result.get("ok", result.get("valid", False))),
                int(result.get("entries", result.get("count", 0))),
                list(result.get("errors", [])) or
                ([result["error"]] if result.get("error") else []))
    return bool(result), 0, []


def audit_read_last(log, n=20):
    read_all = getattr(log, "read_all", None)
    if callable(read_all):
        try:
            return list(read_all())[-n:]
        except Exception:
            pass
    for method in ("read_last", "entries", "list_entries", "tail"):
        fn = getattr(log, method, None)
        if fn is None:
            continue
        try:
            entries = fn(n)
        except TypeError:
            try:
                entries = fn()
            except Exception:
                continue
        if isinstance(entries, list):
            return entries[-n:]
    return []
