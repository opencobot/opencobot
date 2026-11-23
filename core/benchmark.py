"""Capability benchmark for model providers (SPEC section 8.3, ARCHITECTURE section 6).

On connecting a model, run a small deterministic test suite and produce a
capability report plus a recommended automation profile:

  * total score < 0.5  -> "safe tasks only"
  * total score < 0.8  -> "supervised"
  * total score >= 0.8 -> "full"

The suite is the Phase 2 contract set (vision is out of scope for a
text-only ``call`` and is not included here):

  instruction_following, structured_json, tool_calling,
  multi_step_planning, context_handling, error_recovery, consistency.

``run_benchmark`` takes a plain ``call(prompt) -> text`` callable, so the
same suite works for an HTTP gateway provider and for a CLI provider
(Worker A: ``core/cli_providers.run_cli_provider`` wrapped in a callable,
or Worker C: ``opencobot benchmark`` wiring).

Scoring is deterministic string/JSON checks only -- no model is asked to
judge another model. Each test returns a score in 0..1 and passes at
>= 0.5. The total score is the unweighted mean of the seven test scores.
A provider that raises, returns a non-string, or returns empty text
scores 0 on that test; the benchmark never raises for a bad provider.

The prompts are written so a deterministic mock provider can pass them
(see ``evals/benchmark_run.py`` for the good/bad demo mocks) while a
provider returning garbage, empty text, or malformed JSON fails them.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Callable

# Pass mark for a single test; total-score profile cut-offs live in
# profile_for_score() below.
PASS_THRESHOLD = 0.5

TEST_NAMES = (
    "instruction_following",
    "structured_json",
    "tool_calling",
    "multi_step_planning",
    "context_handling",
    "error_recovery",
    "consistency",
)

# -- prompts ---------------------------------------------------------------
# Kept as module constants so tests and evals can reference them exactly.

PROMPT_INSTRUCTION = (
    "Reply with exactly the word BLUE and nothing else. "
    "Do not add any other text, punctuation, or explanation."
)

PROMPT_STRUCTURED_JSON = (
    'Reply with ONLY a JSON object, no other text, with exactly these keys: '
    '"name" (a string), "age" (an integer), "city" (a string). '
    'Example: {"name": "Asha", "age": 30, "city": "Pune"}'
)

PROMPT_TOOL_CALLING = (
    "You have a tool called file_create that creates a file. "
    'It takes arguments "path" and "content". '
    "Reply with ONLY a JSON object of the form "
    '{"tool": "file_create", "arguments": {"path": "/tmp/notes.txt", '
    '"content": "hello"}}. Do not add any other text.'
)

PROMPT_PLANNING = (
    "Plan how to organise a messy downloads folder into subfolders by "
    "file type. Reply with a numbered list of steps, one step per line, "
    "at least 3 steps. Do not add any other text."
)

PROMPT_CONTEXT = (
    "Context: the user's favourite colour is green, their dog is named "
    "Milo, and they live in Lisbon. Question: what is the name of the "
    "user's dog? Reply with just the dog's name and nothing else."
)

PROMPT_ERROR_RECOVERY = (
    "You previously said the capital of France is London. That is wrong. "
    "Correct yourself: what is the capital of France? "
    "Reply with just the city name and nothing else."
)

PROMPT_CONSISTENCY = "What is 17 + 25? Reply with just the number and nothing else."

_PLANNING_KEYWORDS = (
    "folder", "file", "move", "sort", "rename", "subfolder",
    "organise", "organize",
)
_NUMBERED_STEP = re.compile(r"^\s*\d+[.)]\s+\S", re.MULTILINE)


# -- report types ------------------------------------------------------------


@dataclass
class TestResult:
    """One benchmark test: pass/fail, a score in 0..1, and what was seen."""

    __test__ = False  # name starts with "Test"; not a pytest test class

    name: str
    passed: bool
    score: float
    detail: str


@dataclass
class BenchmarkReport:
    """Full benchmark outcome for one provider."""

    name: str
    results: list[TestResult] = field(default_factory=list)
    total_score: float = 0.0

    @property
    def profile(self) -> str:
        """Recommended automation profile for this total score."""
        return profile_for_score(self.total_score)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    def to_dict(self) -> dict:
        return {
            "provider": self.name,
            "total_score": round(self.total_score, 4),
            "profile": self.profile,
            "passed": self.passed,
            "total_tests": len(self.results),
            "results": [
                {
                    "name": r.name,
                    "passed": r.passed,
                    "score": round(r.score, 4),
                    "detail": r.detail,
                }
                for r in self.results
            ],
        }

    def to_json(self) -> str:
        """Machine-readable report (stable key order, indented)."""
        return json.dumps(self.to_dict(), indent=2)

    def to_text(self) -> str:
        """Human-readable report, one line per test plus a summary."""
        lines = [
            f"Benchmark report: {self.name}",
            f"Total score: {self.total_score:.2f} "
            f"({self.passed}/{len(self.results)} tests passed)",
            f"Recommended profile: {self.profile}",
            "",
        ]
        for r in self.results:
            mark = "PASS" if r.passed else "FAIL"
            lines.append(f"  [{mark}] {r.name:<22} score {r.score:.2f} -- {r.detail}")
        return "\n".join(lines)


def profile_for_score(score: float) -> str:
    """Map a total score in 0..1 to a recommended automation profile."""
    if score < 0.5:
        return "safe tasks only"
    if score < 0.8:
        return "supervised"
    return "full"


# -- scoring helpers ---------------------------------------------------------


def _safe_call(call: Callable[[str], str], prompt: str) -> tuple[str | None, str | None]:
    """Call the provider; return (text, error). Never raises."""
    try:
        out = call(prompt)
    except Exception as exc:  # provider blew up: score 0, keep going
        return None, f"provider call raised {type(exc).__name__}: {exc}"
    if not isinstance(out, str):
        return None, f"provider returned non-string {type(out).__name__}"
    return out, None


def _result(name: str, score: float, detail: str) -> TestResult:
    return TestResult(name=name, passed=score >= PASS_THRESHOLD,
                      score=score, detail=detail)


def _parse_json_object(text: str) -> tuple[dict | None, str]:
    """Parse a JSON object, tolerating surrounding prose (partial credit).

    Returns (obj, note): obj is None when nothing parseable was found.
    """
    stripped = text.strip()
    try:
        obj = json.loads(stripped)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", stripped, re.DOTALL)
        if not match:
            return None, "no JSON object found"
        try:
            obj = json.loads(match.group(0))
        except json.JSONDecodeError:
            return None, "JSON object found but malformed"
        if not isinstance(obj, dict):
            return None, "JSON is not an object"
        return obj, "JSON found inside extra text"
    if not isinstance(obj, dict):
        return None, "JSON is not an object"
    return obj, "valid JSON object"


def _score_instruction(resp: str) -> tuple[float, str]:
    if resp.strip() == "BLUE":
        return 1.0, "exact match 'BLUE'"
    if "BLUE" in resp:
        return 0.5, "contains 'BLUE' with extra text"
    return 0.0, "did not output 'BLUE'"


def _score_structured_json(resp: str) -> tuple[float, str]:
    obj, note = _parse_json_object(resp)
    if obj is None:
        return 0.0, note
    # bool is a subclass of int; a boolean "age" is not an integer here.
    good = sum([
        isinstance(obj.get("name"), str),
        isinstance(obj.get("age"), int) and not isinstance(obj.get("age"), bool),
        isinstance(obj.get("city"), str),
    ])
    if good == 3:
        return 1.0, "all 3 keys present with correct types"
    if good >= 2:
        return 0.5, f"only {good}/3 keys correct ({note})"
    return 0.0, f"only {good}/3 keys correct ({note})"


def _score_tool_calling(resp: str) -> tuple[float, str]:
    obj, note = _parse_json_object(resp)
    if obj is None:
        return 0.0, note
    if obj.get("tool") != "file_create":
        return 0.0, f"wrong tool: {obj.get('tool')!r} ({note})"
    args = obj.get("arguments")
    if not isinstance(args, dict):
        return 0.5, "tool correct but arguments missing/not an object"
    if (isinstance(args.get("path"), str) and args["path"]
            and isinstance(args.get("content"), str) and args["content"]):
        return 1.0, "tool call with complete arguments"
    return 0.5, "tool correct but arguments incomplete"


def _score_planning(resp: str) -> tuple[float, str]:
    steps = len(_NUMBERED_STEP.findall(resp))
    keyword = any(k in resp.lower() for k in _PLANNING_KEYWORDS)
    if steps >= 3 and keyword:
        return 1.0, f"{steps} numbered steps about organising files"
    if steps >= 3:
        return 0.5, f"{steps} numbered steps but not about organising files"
    if 1 <= steps < 3 and keyword:
        return 0.5, f"only {steps} numbered step(s)"
    if steps:
        return 0.0, f"only {steps} numbered step(s), off-topic"
    return 0.0, "no numbered steps found"


def _score_context(resp: str) -> tuple[float, str]:
    if resp.strip() == "Milo":
        return 1.0, "exact match 'Milo'"
    if "Milo" in resp:
        return 0.5, "contains 'Milo' with extra text"
    return 0.0, "did not answer with the dog's name from context"


def _score_error_recovery(resp: str) -> tuple[float, str]:
    if resp.strip() == "Paris":
        return 1.0, "corrected to 'Paris'"
    if "Paris" in resp:
        return 0.5, "contains 'Paris' with extra text"
    return 0.0, "did not correct the wrong answer"


# -- the seven tests ---------------------------------------------------------


def _test_instruction_following(call) -> TestResult:
    resp, err = _safe_call(call, PROMPT_INSTRUCTION)
    if err is not None:
        return _result("instruction_following", 0.0, err)
    return _result("instruction_following", *_score_instruction(resp))


def _test_structured_json(call) -> TestResult:
    resp, err = _safe_call(call, PROMPT_STRUCTURED_JSON)
    if err is not None:
        return _result("structured_json", 0.0, err)
    return _result("structured_json", *_score_structured_json(resp))


def _test_tool_calling(call) -> TestResult:
    resp, err = _safe_call(call, PROMPT_TOOL_CALLING)
    if err is not None:
        return _result("tool_calling", 0.0, err)
    return _result("tool_calling", *_score_tool_calling(resp))


def _test_multi_step_planning(call) -> TestResult:
    resp, err = _safe_call(call, PROMPT_PLANNING)
    if err is not None:
        return _result("multi_step_planning", 0.0, err)
    return _result("multi_step_planning", *_score_planning(resp))


def _test_context_handling(call) -> TestResult:
    resp, err = _safe_call(call, PROMPT_CONTEXT)
    if err is not None:
        return _result("context_handling", 0.0, err)
    return _result("context_handling", *_score_context(resp))


def _test_error_recovery(call) -> TestResult:
    resp, err = _safe_call(call, PROMPT_ERROR_RECOVERY)
    if err is not None:
        return _result("error_recovery", 0.0, err)
    return _result("error_recovery", *_score_error_recovery(resp))


def _test_consistency(call) -> TestResult:
    first, err = _safe_call(call, PROMPT_CONSISTENCY)
    if err is not None:
        return _result("consistency", 0.0, err)
    second, err = _safe_call(call, PROMPT_CONSISTENCY)
    if err is not None:
        return _result("consistency", 0.0, err)
    a, b = first.strip(), second.strip()
    if not a or not b:
        return _result("consistency", 0.0, "empty output on repeat call")
    if a == b == "42":
        return _result("consistency", 1.0, "same correct answer twice ('42')")
    if a == b:
        return _result("consistency", 0.5, f"same answer twice ({a!r}) but wrong")
    return _result("consistency", 0.0, f"answers differ: {a!r} vs {b!r}")


_TESTS = (
    _test_instruction_following,
    _test_structured_json,
    _test_tool_calling,
    _test_multi_step_planning,
    _test_context_handling,
    _test_error_recovery,
    _test_consistency,
)


# -- entry points --------------------------------------------------------------


def run_benchmark(call: Callable[[str], str], *, name: str = "provider") -> BenchmarkReport:
    """Run the 7-test capability suite against ``call(prompt) -> text``.

    ``call`` may wrap an HTTP gateway (``Gateway.chat`` / Worker A's
    ``Gateway.complete``) or a CLI provider (Worker A's
    ``core.cli_providers.run_cli_provider``). The benchmark never raises
    for a misbehaving provider: a failing test scores 0.
    """
    results = [fn(call) for fn in _TESTS]
    total = sum(r.score for r in results) / len(results) if results else 0.0
    return BenchmarkReport(name=name, results=results, total_score=total)


def gateway_callable(gateway, role: str = "router", sensitivity: str = "public"):
    """Adapt a Phase 1 ``Gateway`` (``chat(role, messages, sensitivity)``)
    to the ``call(prompt) -> text`` shape ``run_benchmark`` expects.

    Raises RuntimeError if the gateway reports the call as failed, so the
    benchmark records it as a 0 for that test instead of silently passing
    on an error string. Worker A's ``Gateway.complete`` can be wrapped the
    same way once it lands; this helper only depends on ``chat``.
    """
    def call(prompt: str) -> str:
        result = gateway.chat(role, [{"role": "user", "content": prompt}],
                              sensitivity=sensitivity)
        if not result.get("ok"):
            raise RuntimeError(result.get("error") or "gateway call failed")
        return result.get("text") or ""

    return call
