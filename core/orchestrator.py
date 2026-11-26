"""Multi-model orchestrator (ADR-011, Phase 3).

A thin layer over the existing :class:`~core.model_gateway.Gateway` and
:class:`~core.runtime.Runtime` — never a second model-calling path. A
user-chosen "architect" provider decomposes a task into subtasks with
scoped context; each subtask is dispatched to a worker provider through
the gateway's EXECUTOR role (so CLI providers, budgets, the cloud
pre-approval gate and the fallback chain are all reused); every worker
output is verified before integration; integration writes only to
workspace files, only through ``Runtime.run_tool`` (policy-gated), and
only when verification passed (fail closed).

Security notes (ADR-011, risks R-026–R-028):
  * Worker output is untrusted input: it is treated as tainted data
    (integration calls pass ``tainted=True``), it is never executed,
    and it is never stored in memory (only metadata + verdicts are
    recorded; output text stays in the in-memory return value).
  * A subtask's sensitivity defaults to the parent task's label and may
    only be tightened, never loosened; the gateway's eligibility check
    is enforced per call regardless of the label.
  * ``integrate()`` refuses unless ``verification.passed`` is true,
    unless a runtime is configured, and unless the target path stays
    under the workspace root.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

__all__ = [
    "Orchestrator",
    "load_orchestrator_config",
    "sensitivity_strictness",
    "clamp_sensitivity",
]

#: Sensitivity labels, strictest first. Any unknown label fails closed
#: as secret (strictness 3) — see Gateway._is_eligible.
_SENSITIVITY_STRICTNESS = {"public": 1, "personal": 2, "secret": 3}

#: Gateway error text that means "try again later" (budget exhausted,
#: whole chain cooling down, or nothing available) rather than "this
#: subtask failed". ``Gateway.complete`` reports exactly these phrases
#: when the fallback chain is exhausted.
_TRANSIENT_MARKERS = ("budget exceeded", "no provider available", "cooldown")

_ORCHESTRATOR_KEY = "orchestrator"


def sensitivity_strictness(label: str) -> int:
    """Strictness of a sensitivity label; unknown labels are secret (3)."""
    return _SENSITIVITY_STRICTNESS.get(str(label).lower(), 3)


def clamp_sensitivity(subtask_label: str, parent_label: str) -> str:
    """The stricter of the two labels (a subtask may only tighten)."""
    if sensitivity_strictness(subtask_label) >= sensitivity_strictness(parent_label):
        return str(subtask_label).lower()
    return str(parent_label).lower()


def load_orchestrator_config(path: str | None = None) -> dict:
    """Read the ``"orchestrator"`` section of the gateway config file.

    File format (``gateway.json``, same file ``load_gateway_configs``
    reads)::

        {"providers": [...],
         "orchestrator": {"architect": "<provider>", "workers": [...]}}

    Returns ``{"architect": <name or None>, "workers": [...]}``. A
    missing file (or no ``"orchestrator"`` key) yields the defaults
    (no architect chosen, no worker list). Malformed values fail
    loudly so a typo does not silently change who plans the work.
    """
    from .model_gateway import gateway_config_path

    config_path = gateway_config_path(path)
    if config_path is None:
        return {"architect": None, "workers": []}
    try:
        # utf-8-sig: tolerate a leading UTF-8 BOM, like the gateway
        # loader (Windows editors and PowerShell write one).
        data = json.loads(config_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        raise ValueError(
            f"orchestrator config {config_path} is not valid JSON: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise ValueError(
            f"orchestrator config {config_path} must be a JSON object")
    section = data.get(_ORCHESTRATOR_KEY, {})
    if section is None:
        section = {}
    if not isinstance(section, dict):
        raise ValueError(
            f"orchestrator config {config_path}: 'orchestrator' must be "
            f"an object")
    architect = section.get("architect")
    workers = section.get("workers", [])
    if architect is not None and not isinstance(architect, str):
        raise ValueError(
            f"orchestrator config {config_path}: 'architect' must be a "
            f"provider name string")
    if not isinstance(workers, list) or not all(
        isinstance(w, str) for w in workers
    ):
        raise ValueError(
            f"orchestrator config {config_path}: 'workers' must be a "
            f"list of provider name strings")
    return {"architect": architect, "workers": list(workers)}


def _is_transient_error(error: str | None) -> bool:
    """True when a gateway error means "retry later", not "failed"."""
    if not error:
        return False
    lowered = str(error).lower()
    return any(marker in lowered for marker in _TRANSIENT_MARKERS)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class Orchestrator:
    """Decompose a task, dispatch subtasks to worker models, verify
    every output, and integrate only what passed verification.

    ``gateway`` is a :class:`~core.model_gateway.Gateway` (or a
    duck-typed object with ``configs``, ``complete``,
    ``set_role_provider`` and ``role_provider``). ``runtime`` is a
    :class:`~core.runtime.Runtime` (or a ``run_tool`` callable); when
    it is None, integration is refused. ``memory`` is a
    :class:`~core.memory.Memory` (or None — recording is best effort
    and never fails a run). ``token`` is passed through to
    ``run_tool``; its scope must cover ``workspace`` for integration
    to succeed (the tools resolve paths against the token's scope).
    """

    def __init__(
        self,
        gateway: Any,
        runtime: Any = None,
        memory: Any = None,
        state_dir: str | Path | None = None,
        workspace: str | Path | None = None,
        token: Any = None,
        architect: str | None = None,
        workers: list[str] | None = None,
        sensitivity: str = "public",
        project: str | None = None,
        config: dict | None = None,
        config_path: str | None = None,
    ):
        if gateway is None:
            raise TypeError("orchestrator needs a gateway")
        for method in ("complete", "set_role_provider", "role_provider"):
            if not callable(getattr(gateway, method, None)):
                raise TypeError(f"gateway must have a {method}() method")
        configs = getattr(gateway, "configs", None)
        if not isinstance(configs, list):
            raise TypeError("gateway must expose a configs list")
        self.gateway = gateway
        self.sensitivity = str(sensitivity).lower()
        self.token = token

        # Architect: explicit arg wins, then the config file, then the
        # PLANNER role's current provider. Unknown names fail loudly.
        loaded = config if config is not None else load_orchestrator_config(config_path)
        if architect is None:
            architect = loaded.get("architect")
        if architect is None:
            architect = gateway.role_provider("PLANNER")
        if not isinstance(architect, str) or not architect:
            raise ValueError("no architect provider configured")
        if not any(getattr(c, "name", None) == architect for c in configs):
            raise ValueError(f"unknown architect provider: {architect!r}")
        self.architect = architect
        # The architect IS the planner for this orchestrator instance.
        # (Documented side effect on the shared gateway; dispatch
        # restores the EXECUTOR assignment after each subtask.)
        gateway.set_role_provider("PLANNER", architect)
        if workers is None:
            workers = list(loaded.get("workers") or [])
        self.workers: list[str] = list(workers)

        # Runtime: a Runtime object (use its run_tool) or a bare
        # run_tool callable. None means integration is refused.
        if runtime is None:
            self._run_tool = None
        elif callable(getattr(runtime, "run_tool", None)):
            self._run_tool = runtime.run_tool
        elif callable(runtime):
            self._run_tool = runtime
        else:
            raise TypeError(
                "runtime must be a Runtime (with run_tool) or a "
                "run_tool callable")
        self.runtime = runtime
        self.memory = memory
        self.state_dir = Path(state_dir) if state_dir is not None else None
        self.workspace = Path(workspace).resolve() if workspace is not None else Path.cwd().resolve()
        self.project = project or self.workspace.name

    # -- decomposition -------------------------------------------------

    def decompose(self, task: str, sensitivity: str | None = None) -> list[dict]:
        """Ask the architect for subtasks; retry once, then fall back
        to one subtask covering the whole task.

        Each subtask carries only its own goal/context plus the
        top-level task title — never the full history or a memory dump.
        """
        sensitivity = (sensitivity or self.sensitivity).lower()
        prompt = (
            "Decompose this task into subtasks and reply with JSON only, "
            "exactly {\"subtasks\": [{\"title\": ..., \"goal\": ..., "
            "\"context\": ..., \"provider\": <provider name or null>, "
            "\"output\": {\"kind\": \"file\" or \"text\", \"path\": "
            "<relative path or null>}, \"checks\": [{\"tool\": ..., "
            "\"args\": {...}}], \"sensitivity\": \"public\"|\"personal\"|"
            "\"secret\", \"verify_model\": true|false}]}. "
            "Keep each subtask's context to what that subtask needs. "
            f"Task: {task}"
        )
        subtasks: list[dict] | None = None
        note = ""
        for attempt in range(2):
            raw = self.gateway.complete("PLANNER", prompt, sensitivity)
            if isinstance(raw, dict) and raw.get("needs_approval"):
                note = "architect call needs approval"
                break
            text = raw.get("text") if isinstance(raw, dict) else None
            if isinstance(text, str):
                subtasks = self._parse_subtasks(text, task, sensitivity)
            if subtasks:
                break
            note = "architect returned unusable decomposition"
            prompt += (" Your previous reply was not usable JSON in the "
                       "requested shape. Reply with JSON only.")
        if not subtasks:
            subtasks = [self._fallback_subtask(task, sensitivity)]
        if note:
            subtasks[0]["decompose_note"] = note
        return subtasks

    @staticmethod
    def _fallback_subtask(task: str, sensitivity: str) -> dict:
        """Deterministic single subtask: the whole task, no hints."""
        return {
            "title": task[:80] or "task",
            "goal": task,
            "context": "",
            "provider": None,
            "output": {"kind": "text", "path": None},
            "checks": [],
            "sensitivity": sensitivity,
            "verify_model": False,
        }

    @classmethod
    def _parse_subtasks(
        cls, text: str, task: str, sensitivity: str
    ) -> list[dict] | None:
        """Strictly parse architect JSON into normalized subtasks.

        Returns None when the text is not a usable decomposition.
        Invalid subtask entries are dropped (a plan with no usable
        entries is unusable); per-subtask sensitivity is clamped to
        the parent label (may only tighten, never loosen — R-027).
        """
        try:
            parsed = json.loads(text)
        except ValueError:
            return None
        if isinstance(parsed, dict):
            parsed = parsed.get("subtasks")
        if not isinstance(parsed, list) or not parsed:
            return None
        subtasks: list[dict] = []
        for item in parsed:
            if not isinstance(item, dict):
                continue
            title = item.get("title")
            if not isinstance(title, str) or not title.strip():
                continue
            goal = item.get("goal")
            if not isinstance(goal, str):
                goal = title
            context = item.get("context")
            if not isinstance(context, str):
                context = ""
            provider = item.get("provider")
            if provider is not None and not isinstance(provider, str):
                provider = None
            output = item.get("output")
            if not isinstance(output, dict):
                output = {}
            kind = output.get("kind")
            if kind not in ("file", "text"):
                kind = "text"
            path = output.get("path")
            if path is not None and not isinstance(path, str):
                path = None
            if kind == "text":
                path = None
            checks: list[dict] = []
            raw_checks = item.get("checks")
            if isinstance(raw_checks, list):
                for check in raw_checks:
                    if (
                        isinstance(check, dict)
                        and isinstance(check.get("tool"), str)
                        and isinstance(check.get("args", {}), dict)
                    ):
                        checks.append({"tool": check["tool"],
                                     "args": check["args"]})
            sub_sensitivity = item.get("sensitivity", sensitivity)
            if not isinstance(sub_sensitivity, str):
                sub_sensitivity = sensitivity
            subtasks.append({
                "title": title.strip(),
                "goal": goal,
                "context": context,
                "provider": provider,
                "output": {"kind": kind, "path": path},
                "checks": checks,
                "sensitivity": clamp_sensitivity(sub_sensitivity, sensitivity),
                "verify_model": bool(item.get("verify_model", False)),
                "task": task,
            })
        return subtasks or None

    # -- dispatch ------------------------------------------------------

    def dispatch(
        self,
        subtask: dict,
        sensitivity: str | None = None,
        feedback: str | None = None,
    ) -> dict:
        """Run one subtask on its hinted worker via the EXECUTOR role.

        The prompt carries only the top-level task title plus this
        subtask's own goal/context. A hint naming an unknown provider
        is recorded and the role default is used instead. A cloud
        worker that needs approval is NOT called (``needs_approval``);
        a whole-chain budget exhaustion marks the subtask ``queued``.
        """
        sensitivity = (sensitivity or subtask.get("sensitivity")
                       or self.sensitivity).lower()
        hint = subtask.get("provider")
        worker: str | None = None
        hint_note = ""
        previous = None
        try:
            previous = self.gateway.role_provider("EXECUTOR")
        except Exception:
            previous = None
        if isinstance(hint, str) and hint:
            known = [getattr(c, "name", None) for c in self.gateway.configs]
            if hint in known:
                self.gateway.set_role_provider("EXECUTOR", hint)
                worker = hint
            else:
                hint_note = f"unknown worker provider hint: {hint!r}"
        prompt = (
            f"Task: {subtask.get('task', '')}\n"
            f"Subtask: {subtask.get('title', '')}\n"
            f"Goal: {subtask.get('goal', '')}\n"
            f"Context: {subtask.get('context', '')}"
        )
        if feedback:
            prompt += f"\nPrevious attempt failed verification: {feedback}"
        try:
            raw = self.gateway.complete("EXECUTOR", prompt, sensitivity)
        finally:
            # Restore the EXECUTOR assignment the caller had.
            if previous is not None:
                try:
                    self.gateway.set_role_provider("EXECUTOR", previous)
                except Exception:
                    pass
        if not isinstance(raw, dict):
            return {"status": "failed", "worker": worker,
                    "error": "worker returned an unexpected response",
                    "hint_note": hint_note}
        if raw.get("needs_approval"):
            return {"status": "needs_approval", "worker": worker,
                    "provider": raw.get("provider"),
                    "cost_estimate": raw.get("cost_estimate"),
                    "hint_note": hint_note}
        error = raw.get("error")
        if error or not isinstance(raw.get("text"), str) or not raw["text"].strip():
            message = error or "worker returned no text"
            if _is_transient_error(message):
                return {"status": "queued", "worker": worker,
                        "reason": message, "hint_note": hint_note}
            return {"status": "failed", "worker": worker,
                    "error": message, "hint_note": hint_note}
        return {"status": "done", "worker": raw.get("provider") or worker,
                "output": raw["text"], "hint_note": hint_note}

    # -- verification --------------------------------------------------

    def _resolve_in_workspace(self, path: str) -> Path | None:
        """Resolve a worker-supplied file path inside the workspace.

        Returns the resolved target, or None when the path is absolute
        or escapes the workspace (``../``). ``Path.is_absolute()``
        alone is not enough: on Windows a path like ``/etc/passwd``
        is drive-relative, so ``is_absolute()`` is False yet the path
        still lands outside the workspace — verify() used to pass it
        while integrate() refused it (the Windows failure of
        ``test_verify_rejects_empty_output_and_absolute_path``). The
        same gap existed on Linux for ``../`` escapes. verify(),
        integrate() and _workspace_key() all use this one check, so a
        verdict can never pass a path that integrate() would refuse.
        Resolve errors fail closed (None) instead of raising.
        """
        if not isinstance(path, str) or not path.strip():
            return None
        if Path(path).is_absolute():
            return None
        try:
            target = (self.workspace / path).resolve()
            target.relative_to(self.workspace)
        except (ValueError, OSError, RuntimeError):
            return None
        return target

    def verify(
        self,
        subtask: dict,
        output_text: str,
        sensitivity: str | None = None,
    ) -> dict:
        """Verify a worker output before it may be integrated.

        Deterministic shape checks always run; declared ``checks``
        (policy-gated ``run_tool`` calls) run next; a VERIFIER-role
        architect review runs only when the subtask asks for it. Any
        failure fails the verdict closed (no partial pass).
        """
        sensitivity = (sensitivity or subtask.get("sensitivity")
                       or self.sensitivity).lower()
        methods: list[str] = ["shape"]
        evidence: list[str] = []
        if not isinstance(output_text, str) or not output_text.strip():
            return {"passed": False, "method": "shape",
                    "evidence": "worker output is empty"}
        output = subtask.get("output") or {}
        if output.get("kind") == "file":
            path = output.get("path")
            if not isinstance(path, str) or not path.strip():
                return {"passed": False, "method": "shape",
                        "evidence": "file output has no path"}
            if Path(path).is_absolute():
                return {"passed": False, "method": "shape",
                        "evidence": f"file path must be relative: {path!r}"}
            if self._resolve_in_workspace(path) is None:
                return {"passed": False, "method": "shape",
                        "evidence": f"file path escapes the workspace: {path!r}"}
        for check in subtask.get("checks") or []:
            methods.append("checks")
            if self._run_tool is None:
                return {"passed": False, "method": "+".join(methods),
                        "evidence": "declared check needs a runtime"}
            try:
                outcome = self._run_tool(
                    self.token, check["tool"], check.get("args", {}))
            except Exception as exc:
                return {"passed": False, "method": "+".join(methods),
                        "evidence": f"check {check['tool']!r} raised: {exc}"}
            if not isinstance(outcome, dict) or not outcome.get("ok") \
                    or not outcome.get("verified"):
                detail = ""
                if isinstance(outcome, dict):
                    detail = str(outcome.get("evidence") or
                                 outcome.get("result") or "")
                return {"passed": False, "method": "+".join(methods),
                        "evidence": f"check {check['tool']!r} failed: {detail}"}
            evidence.append(f"check {check['tool']!r} passed")
        if subtask.get("verify_model"):
            methods.append("model-review")
            prompt = (
                "Review this worker output for the subtask below and reply "
                "with JSON only, exactly {\"verdict\": \"pass\" or "
                "\"fail\", \"reason\": ...}. "
                f"Subtask: {subtask.get('title', '')}\n"
                f"Goal: {subtask.get('goal', '')}\n"
                f"Output:\n{output_text}"
            )
            raw = self.gateway.complete("VERIFIER", prompt, sensitivity)
            if not isinstance(raw, dict) or raw.get("needs_approval") \
                    or raw.get("error") or not isinstance(raw.get("text"), str):
                return {"passed": False, "method": "+".join(methods),
                        "evidence": "verifier review unavailable: "
                        f"{raw.get('error') if isinstance(raw, dict) else 'bad response'}"}
            try:
                parsed = json.loads(raw["text"])
            except ValueError:
                return {"passed": False, "method": "+".join(methods),
                        "evidence": "verifier review was not usable JSON"}
            if not isinstance(parsed, dict) or parsed.get("verdict") != "pass":
                reason = ""
                if isinstance(parsed, dict):
                    reason = str(parsed.get("reason") or "")
                return {"passed": False, "method": "+".join(methods),
                        "evidence": f"verifier rejected the output: {reason}"}
            evidence.append("verifier review passed")
        return {"passed": True, "method": "+".join(methods),
                "evidence": "; ".join(evidence) if evidence else "shape ok"}

    # -- integration ---------------------------------------------------

    def integrate(
        self, subtask: dict, output_text: str, verdict: dict
    ) -> dict:
        """Write a verified file output into the workspace — or refuse.

        Fail closed: no passing verdict, no runtime, a path outside
        the workspace, or an absolute path all refuse. Writes go only
        through ``Runtime.run_tool`` (``write_file`` when the file
        exists, ``create_file`` when it does not; both Level 2,
        policy-gated), with ``tainted=True`` because worker output is
        untrusted input (R-026). Text outputs have no file to write.
        """
        if not isinstance(verdict, dict) or not verdict.get("passed"):
            return {"ok": False, "integrated": False,
                    "error": "verification did not pass; refusing to integrate"}
        output = subtask.get("output") or {}
        if output.get("kind") != "file":
            return {"ok": True, "integrated": False,
                    "reason": "text output has no file to write"}
        if self._run_tool is None:
            return {"ok": False, "integrated": False,
                    "error": "no runtime configured; cannot integrate"}
        path = output.get("path")
        target = self._resolve_in_workspace(path)
        if target is None:
            return {"ok": False, "integrated": False,
                    "error": f"refusing to integrate outside the workspace: {path!r}"}
        tool = "write_file" if target.exists() else "create_file"
        try:
            outcome = self._run_tool(
                self.token, tool,
                {"path": str(target), "content": output_text}, tainted=True)
        except TypeError as exc:
            # Older test doubles whose run_tool takes no tainted kwarg:
            # retry without it. Any other TypeError is a real failure
            # and is not retried (a second write would be a duplicate).
            if "tainted" not in str(exc):
                raise
            outcome = self._run_tool(
                self.token, tool, {"path": str(target), "content": output_text})
        if not isinstance(outcome, dict) or not outcome.get("ok") \
                or not outcome.get("verified"):
            detail = ""
            if isinstance(outcome, dict):
                detail = str(outcome.get("evidence") or
                             outcome.get("result") or "")
            return {"ok": False, "integrated": False,
                    "error": f"{tool} failed: {detail}"}
        return {"ok": True, "integrated": True, "tool": tool,
                "path": str(target)}

    def _workspace_key(self, path: str) -> str | None:
        """Workspace-relative key for a file path, or None if it escapes.

        Normalizes spellings (``./a.py`` vs ``a.py``) so two workers
        targeting the same file are grouped as one conflict.
        """
        target = self._resolve_in_workspace(path)
        if target is None:
            return None
        return target.relative_to(self.workspace).as_posix()

    # -- conflict resolution -------------------------------------------

    def resolve_conflicts(
        self, candidates: list[dict], sensitivity: str | None = None
    ) -> dict | None:
        """Pick one winner among passing outputs for the same file.

        ``candidates`` are ``{"subtask", "output", "verdict"}`` dicts.
        The architect (PLANNER) chooses by index; an unusable answer
        means nobody wins (fail closed — nothing is integrated for
        that path).
        """
        sensitivity = sensitivity or self.sensitivity
        listing = []
        for index, candidate in enumerate(candidates):
            subtask = candidate["subtask"]
            listing.append(
                f"[{index}] {subtask.get('title', '')} "
                f"(provider {candidate.get('worker') or 'unknown'}):\n"
                f"{candidate.get('output', '')}"
            )
        prompt = (
            "Two or more workers produced output for the same file. "
            "Reply with JSON only, exactly {\"winner\": <index>, "
            "\"reason\": ...}, naming the index of the output to keep.\n"
            + "\n\n".join(listing)
        )
        raw = self.gateway.complete("PLANNER", prompt, sensitivity)
        if not isinstance(raw, dict) or raw.get("needs_approval") \
                or raw.get("error") or not isinstance(raw.get("text"), str):
            return None
        try:
            parsed = json.loads(raw["text"])
        except ValueError:
            return None
        if not isinstance(parsed, dict):
            return None
        winner = parsed.get("winner")
        if not isinstance(winner, int) or not 0 <= winner < len(candidates):
            return None
        return candidates[winner]

    # -- full run ------------------------------------------------------

    def run(self, task: str, sensitivity: str | None = None) -> dict:
        """Decompose, dispatch, verify and integrate one task.

        Failed verification gets one re-dispatch with the verification
        evidence as feedback; a second failure is reported, never
        integrated. Subtasks that hit a whole-chain budget exhaustion
        are ``queued`` and the run continues with the others; subtasks
        needing approval are recorded, never auto-approved.
        """
        sensitivity = (sensitivity or self.sensitivity).lower()
        run_id = uuid.uuid4().hex[:12]
        subtasks = self.decompose(task, sensitivity)
        records: list[dict] = []
        passing_files: dict[str, list[dict]] = {}
        for subtask in subtasks:
            record: dict = {
                "title": subtask.get("title"),
                "provider_hint": subtask.get("provider"),
                "sensitivity": subtask.get("sensitivity", sensitivity),
                "status": "pending",
                "subtask": subtask,
            }
            records.append(record)
            result = self.dispatch(subtask, sensitivity)
            record["worker"] = result.get("worker")
            record["dispatch"] = {k: v for k, v in result.items()
                                  if k != "output"}
            if result["status"] != "done":
                record["status"] = result["status"]
                if result["status"] == "queued":
                    record["reason"] = result.get("reason")
                elif result["status"] == "needs_approval":
                    record["cost_estimate"] = result.get("cost_estimate")
                else:
                    record["error"] = result.get("error")
                continue
            output_text = result["output"]
            verdict = self.verify(subtask, output_text, sensitivity)
            record["verdict"] = verdict
            if not verdict["passed"]:
                # One re-dispatch with the evidence as feedback.
                retry = self.dispatch(
                    subtask, sensitivity,
                    feedback=verdict.get("evidence", ""))
                record["retry_dispatch"] = {
                    k: v for k, v in retry.items() if k != "output"}
                if retry["status"] != "done":
                    record["status"] = retry["status"]
                    record["error"] = retry.get("error") or retry.get("reason")
                    continue
                output_text = retry["output"]
                record["worker"] = retry.get("worker")
                verdict = self.verify(subtask, output_text, sensitivity)
                record["verdict"] = verdict
                if not verdict["passed"]:
                    record["status"] = "failed"
                    record["error"] = (
                        "verification failed twice: "
                        f"{verdict.get('evidence', '')}")
                    continue
            record["output"] = output_text
            if (subtask.get("output") or {}).get("kind") == "file":
                path = (subtask["output"] or {}).get("path") or ""
                key = self._workspace_key(path)
                if key is None:
                    record["status"] = "failed"
                    record["error"] = (
                        "refusing to integrate outside the workspace: "
                        f"{path!r}")
                    continue
                passing_files.setdefault(key, []).append({
                    "record": record, "subtask": subtask,
                    "output": output_text, "verdict": verdict,
                    "worker": record.get("worker"),
                })
                record["status"] = "verified"
            else:
                record["status"] = "done"
        # Integrate passing file outputs; conflicts resolve to one winner.
        for path, candidates in passing_files.items():
            chosen = candidates
            if len(candidates) > 1:
                winner = self.resolve_conflicts(candidates, sensitivity)
                if winner is None:
                    for candidate in candidates:
                        candidate["record"]["status"] = "failed"
                        candidate["record"]["error"] = (
                            "conflict could not be resolved; "
                            "nothing integrated for this file")
                    continue
                for candidate in candidates:
                    if candidate is not winner:
                        candidate["record"]["status"] = "conflict_lost"
                        candidate["record"]["error"] = (
                            "another worker's output was chosen for "
                            f"{path!r}")
                chosen = [winner]
            for candidate in chosen:
                record = candidate["record"]
                outcome = self.integrate(
                    candidate["subtask"], candidate["output"],
                    candidate["verdict"])
                record["integration"] = outcome
                if outcome.get("ok") and outcome.get("integrated"):
                    record["status"] = "integrated"
                else:
                    record["status"] = "failed"
                    record["error"] = outcome.get("error")
        summary = self._summarize(run_id, task, sensitivity, records)
        self._record_run(run_id, task, sensitivity, summary, records)
        return summary

    def _summarize(
        self, run_id: str, task: str, sensitivity: str, records: list[dict]
    ) -> dict:
        """Build the run summary (no output text is stored)."""
        def titles(status: str) -> list[str]:
            return [r["title"] for r in records if r["status"] == status]

        failed = titles("failed")
        queued = titles("queued")
        needs_approval = titles("needs_approval")
        ok = not failed and not queued and not needs_approval
        error = None
        if failed:
            error = f"{len(failed)} subtask(s) failed: {', '.join(failed)}"
        elif queued:
            error = f"{len(queued)} subtask(s) queued: {', '.join(queued)}"
        elif needs_approval:
            error = ("approval needed for "
                     f"{', '.join(needs_approval)}")
        return {
            "ok": ok,
            "run_id": run_id,
            "task": task,
            "sensitivity": sensitivity,
            "integrated": titles("integrated"),
            "done": titles("done"),
            "failed": failed,
            "queued": queued,
            "needs_approval": needs_approval,
            "conflict_lost": titles("conflict_lost"),
            "error": error,
            "subtasks": [
                {k: v for k, v in r.items()
                 if k not in ("output", "subtask")}
                for r in records
            ],
        }

    def _record_run(
        self, run_id: str, task: str, sensitivity: str,
        summary: dict, records: list[dict],
    ) -> None:
        """Record the run in memory (best effort; never fails a run).

        Only metadata is stored — never worker output text (R-026:
        output may contain secrets) and never the full subtask dicts
        beyond what retry_queued needs (title, goal, context,
        provider, output, checks, sensitivity).
        """
        if self.memory is None:
            return
        stored_subtasks = []
        for record in records:
            subtask = record.get("subtask") or {}
            stored_subtasks.append({
                "title": subtask.get("title"),
                "goal": subtask.get("goal"),
                "context": subtask.get("context"),
                "provider": subtask.get("provider"),
                "output": subtask.get("output"),
                "checks": subtask.get("checks"),
                "sensitivity": subtask.get("sensitivity", sensitivity),
                "verify_model": bool(subtask.get("verify_model", False)),
                "task": task,
                "status": record.get("status"),
            })
        # Store a sanitized copy of the summary: verdict evidence can
        # quote worker output, and output text must never be persisted
        # (R-026/R-024). The live return value keeps the evidence.
        stored_summary = json.loads(json.dumps(summary))
        for subtask_record in stored_summary.get("subtasks", []):
            verdict = subtask_record.get("verdict")
            if isinstance(verdict, dict):
                verdict["evidence"] = ""
        try:
            self.memory.store(f"orchestrator:run:{run_id}", {
                "run_id": run_id, "task": task, "sensitivity": sensitivity,
                "ts": _now_iso(), "summary": stored_summary,
                "subtasks": stored_subtasks,
            })
            self.memory.store(f"orchestrator:{self.project}:last_run", {
                "run_id": run_id, "task": task, "ts": _now_iso(),
                "summary": stored_summary,
            })
        except Exception:
            pass

    def retry_queued(self, run_id: str, sensitivity: str | None = None) -> dict:
        """Re-attempt a previous run's queued subtasks.

        Queued subtasks are re-dispatched (and verified + integrated
        on success); the stored run record is updated in place.
        """
        if self.memory is None:
            return {"ok": False, "run_id": run_id,
                    "error": "no memory configured"}
        stored = self.memory.get(f"orchestrator:run:{run_id}")
        if not isinstance(stored, dict):
            return {"ok": False, "run_id": run_id,
                    "error": f"no stored run: {run_id!r}"}
        sensitivity = (sensitivity or stored.get("sensitivity")
                       or self.sensitivity).lower()
        task = str(stored.get("task", ""))
        queued = [s for s in stored.get("subtasks", [])
                  if s.get("status") == "queued"]
        if not queued:
            return {"ok": True, "run_id": run_id,
                    "retried": [], "still_queued": [],
                    "error": None}
        retried: list[str] = []
        still_queued: list[str] = []
        for subtask in queued:
            result = self.dispatch(subtask, sensitivity)
            if result["status"] == "queued":
                still_queued.append(str(subtask.get("title")))
                continue
            if result["status"] != "done":
                subtask["status"] = result["status"]
                retried.append(str(subtask.get("title")))
                continue
            verdict = self.verify(subtask, result["output"], sensitivity)
            if not verdict["passed"]:
                subtask["status"] = "failed"
                retried.append(str(subtask.get("title")))
                continue
            if (subtask.get("output") or {}).get("kind") == "file":
                outcome = self.integrate(subtask, result["output"], verdict)
                subtask["status"] = (
                    "integrated" if outcome.get("ok") and outcome.get("integrated")
                    else "failed")
            else:
                subtask["status"] = "done"
            retried.append(str(subtask.get("title")))
        # The `queued` list holds references into stored["subtasks"],
        # so the loop already updated the stored dicts in place; just
        # refresh the summary + timestamp and persist.
        try:
            stored["summary"] = self._summarize(
                run_id, task, sensitivity,
                [{"title": s.get("title"), "status": s.get("status")}
                 for s in stored.get("subtasks", [])])
            stored["ts"] = _now_iso()
            self.memory.store(f"orchestrator:run:{run_id}", stored)
        except Exception:
            pass
        return {"ok": not still_queued, "run_id": run_id,
                "retried": retried, "still_queued": still_queued,
                "error": None if not still_queued else
                f"{len(still_queued)} subtask(s) still queued"}

    def recall(self, project: str | None = None, limit: int = 5) -> list[dict]:
        """Most recent orchestrator records for a project (newest first).

        Prefix + recency only, never a full dump (ADR-011 memory rule).
        """
        if self.memory is None:
            return []
        prefix = f"orchestrator:{project or self.project}:"
        try:
            keys = [k for k in self.memory.list_keys()
                    if k.startswith(prefix)]
        except Exception:
            return []
        values: list[dict] = []
        for key in keys:
            try:
                value = self.memory.get(key)
            except Exception:
                continue
            if isinstance(value, dict):
                values.append(value)
        values.sort(key=lambda v: str(v.get("ts", "")), reverse=True)
        return values[: max(0, int(limit))]
