"""Tests for core.benchmark (SPEC section 8.3).

No network and no live model: every provider here is a deterministic
mock callable, plus one fake CLI script run through subprocess (argv
array only, no shell) to prove the benchmark works for CLI-shaped
providers too.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from core.benchmark import (  # noqa: E402
    TEST_NAMES,
    BenchmarkReport,
    TestResult,
    gateway_callable,
    profile_for_score,
    run_benchmark,
)
from core.model_gateway import Gateway, ProviderConfig  # noqa: E402
from evals.benchmark_run import bad_mock_provider, good_mock_provider  # noqa: E402

# -- helpers ---------------------------------------------------------------

_PLAN_FULL = (
    "1. Create a subfolder for each file type.\n"
    "2. Move each file into the folder for its type.\n"
    "3. Sort the remaining files and rename any duplicates."
)


def selective_mock(passing: set[str]):
    """Mock that answers correctly only for the named tests."""
    answers = {
        "instruction_following": "BLUE",
        "structured_json": '{"name": "Asha", "age": 30, "city": "Pune"}',
        "tool_calling": ('{"tool": "file_create", "arguments": '
                         '{"path": "/tmp/notes.txt", "content": "hello"}}'),
        "multi_step_planning": _PLAN_FULL,
        "context_handling": "Milo",
        "error_recovery": "Paris",
        "consistency": "42",
    }

    def call(prompt: str) -> str:
        p = prompt.lower()
        if "exactly the word blue" in p:
            key = "instruction_following"
        elif "file_create" in p:
            key = "tool_calling"
        elif '"name"' in p and "json object" in p:
            key = "structured_json"
        elif "numbered list of steps" in p:
            key = "multi_step_planning"
        elif "name of the user's dog" in p:
            key = "context_handling"
        elif "capital of france" in p:
            key = "error_recovery"
        elif "17 + 25" in p:
            key = "consistency"
        else:
            return "??? "
        return answers[key] if key in passing else "garbage"

    return call


def by_name(report: BenchmarkReport, name: str) -> TestResult:
    return next(r for r in report.results if r.name == name)


# -- good mock / bad mock: both directions ---------------------------------

def test_good_mock_passes_all_seven():
    report = run_benchmark(good_mock_provider, name="good-mock")
    assert [r.name for r in report.results] == list(TEST_NAMES)
    assert all(r.passed for r in report.results)
    assert all(r.score == 1.0 for r in report.results)
    assert report.total_score == 1.0
    assert report.profile == "full"
    assert report.passed == 7


def test_bad_mock_fails_all_seven():
    report = run_benchmark(bad_mock_provider, name="bad-mock")
    assert all(not r.passed for r in report.results)
    assert all(r.score == 0.0 for r in report.results)
    assert report.total_score == 0.0
    assert report.profile == "safe tasks only"
    assert report.passed == 0


def test_test_names_are_the_contract_seven():
    assert TEST_NAMES == (
        "instruction_following",
        "structured_json",
        "tool_calling",
        "multi_step_planning",
        "context_handling",
        "error_recovery",
        "consistency",
    )


# -- per-test scoring ------------------------------------------------------

def test_instruction_extra_text_is_partial_credit():
    report = run_benchmark(lambda p: "The word is BLUE, of course.")
    result = by_name(report, "instruction_following")
    assert result.score == 0.5 and result.passed


def test_instruction_wrong_word_fails():
    report = run_benchmark(lambda p: "RED")
    assert by_name(report, "instruction_following").score == 0.0


def test_structured_json_wrong_types_partial():
    report = run_benchmark(
        lambda p: '{"name": "Asha", "age": "thirty", "city": "Pune"}')
    result = by_name(report, "structured_json")
    assert result.score == 0.5 and result.passed


def test_structured_json_missing_key_fails():
    report = run_benchmark(lambda p: '{"name": "Asha"}')
    assert by_name(report, "structured_json").score == 0.0


def test_structured_json_invalid_fails():
    report = run_benchmark(lambda p: "{not json")
    assert by_name(report, "structured_json").score == 0.0


def test_structured_json_wrapped_in_prose_still_counts():
    report = run_benchmark(
        lambda p: 'Here it is: {"name": "Asha", "age": 30, "city": "Pune"}')
    result = by_name(report, "structured_json")
    assert result.score == 1.0 and result.passed


def test_tool_calling_wrong_tool_fails():
    report = run_benchmark(
        lambda p: '{"tool": "shell_exec", "arguments": {"cmd": "rm -rf /"}}')
    assert by_name(report, "tool_calling").score == 0.0


def test_tool_calling_incomplete_arguments_partial():
    report = run_benchmark(
        lambda p: '{"tool": "file_create", "arguments": {"path": "/tmp/x"}}')
    result = by_name(report, "tool_calling")
    assert result.score == 0.5 and result.passed


def test_planning_too_few_steps_partial():
    report = run_benchmark(
        lambda p: "1. Make a folder for files.\n2. Move the files.")
    result = by_name(report, "multi_step_planning")
    assert result.score == 0.5 and result.passed


def test_planning_no_numbered_steps_fails():
    report = run_benchmark(lambda p: "Just sort everything somehow.")
    assert by_name(report, "multi_step_planning").score == 0.0


def test_context_extra_text_is_partial_credit():
    report = run_benchmark(lambda p: "The dog's name is Milo.")
    result = by_name(report, "context_handling")
    assert result.score == 0.5 and result.passed


def test_context_wrong_fact_fails():
    report = run_benchmark(lambda p: "Lisbon")
    assert by_name(report, "context_handling").score == 0.0


def test_error_recovery_repeats_wrong_answer_fails():
    report = run_benchmark(lambda p: "London")
    assert by_name(report, "error_recovery").score == 0.0


def test_consistency_same_wrong_answer_is_partial():
    report = run_benchmark(lambda p: "43")
    result = by_name(report, "consistency")
    assert result.score == 0.5 and result.passed


def test_consistency_differing_answers_fail():
    answers = iter(["42", "43"])
    report = run_benchmark(lambda p: next(answers))
    assert by_name(report, "consistency").score == 0.0


# -- scoring math and profile thresholds -----------------------------------

def test_total_score_is_mean_of_test_scores():
    # 1 full pass (1.0) + 2 partials (0.5) = 2.0 / 7.
    calls = {
        "exactly the word blue": "BLUE",
        '"name"': '{"name": "Asha", "age": "thirty", "city": "Pune"}',
        "file_create": "garbage",
        "numbered list of steps": "garbage",
        "name of the user's dog": "garbage",
        "capital of france": "garbage",
        "17 + 25": "43",
    }

    def call(prompt: str) -> str:
        for needle, answer in calls.items():
            if needle in prompt.lower():
                return answer
        return "garbage"

    report = run_benchmark(call)
    # 1.0 + 0.5 + 0 + 0 + 0 + 0 + 0.5 = 2.0 / 7
    assert report.total_score == pytest.approx(2.0 / 7)
    assert report.profile == "safe tasks only"
    assert report.passed == 3  # 1.0, 0.5, 0.5 all pass at >= 0.5


def test_selective_mock_supervised_profile():
    # 4 full passes (1.0) + consistency partial (0.5: same wrong answer
    # "garbage" twice) = 4.5/7 ~= 0.643 -> "supervised".
    passing = {"instruction_following", "structured_json",
               "tool_calling", "context_handling"}
    report = run_benchmark(selective_mock(passing))
    assert report.total_score == pytest.approx(4.5 / 7)
    assert report.profile == "supervised"
    assert report.passed == 5


@pytest.mark.parametrize("score,expected", [
    (0.0, "safe tasks only"),
    (0.49, "safe tasks only"),
    (0.5, "supervised"),
    (0.79, "supervised"),
    (0.7999, "supervised"),
    (0.8, "full"),
    (1.0, "full"),
])
def test_profile_threshold_boundaries(score, expected):
    assert profile_for_score(score) == expected


def test_report_profile_uses_total_score():
    report = BenchmarkReport(name="x", results=[], total_score=0.5)
    assert report.profile == "supervised"
    report.total_score = 0.8
    assert report.profile == "full"


# -- report output ---------------------------------------------------------

def test_to_json_roundtrip():
    report = run_benchmark(good_mock_provider, name="good-mock")
    data = json.loads(report.to_json())
    assert data["provider"] == "good-mock"
    assert data["total_score"] == 1.0
    assert data["profile"] == "full"
    assert data["passed"] == 7 and data["total_tests"] == 7
    assert [r["name"] for r in data["results"]] == list(TEST_NAMES)
    assert all(r["passed"] and r["score"] == 1.0 for r in data["results"])
    assert all("detail" in r for r in data["results"])


def test_to_text_contains_summary_and_every_test():
    report = run_benchmark(bad_mock_provider, name="bad-mock")
    text = report.to_text()
    assert "Benchmark report: bad-mock" in text
    assert "Total score: 0.00" in text
    assert "Recommended profile: safe tasks only" in text
    for name in TEST_NAMES:
        assert name in text
    assert "[FAIL]" in text


def test_default_name_is_provider():
    report = run_benchmark(good_mock_provider)
    assert report.name == "provider"


# -- misbehaving providers never raise -------------------------------------

def test_provider_exception_scores_zero_not_raise():
    def boom(prompt: str) -> str:
        raise RuntimeError("model exploded")

    report = run_benchmark(boom)
    assert report.total_score == 0.0
    assert all("raised RuntimeError" in r.detail for r in report.results)


def test_provider_non_string_return_scores_zero():
    report = run_benchmark(lambda p: None)
    assert report.total_score == 0.0
    assert all("non-string" in r.detail for r in report.results)


def test_provider_empty_string_fails_everything():
    report = run_benchmark(lambda p: "")
    assert report.total_score == 0.0
    assert report.profile == "safe tasks only"


# -- adapters: HTTP gateway and CLI-shaped provider ------------------------

def test_gateway_callable_adapter_runs_full_benchmark():
    """Gateway.chat with a mock transport, adapted via gateway_callable."""
    def transport(config, payload, headers):
        content = payload["messages"][-1]["content"]
        return {"text": good_mock_provider(content)}

    gateway = Gateway(
        configs=[ProviderConfig("ollama-local", "ollama",
                                "http://localhost:11434", "llama3.1")],
        transport=transport,
    )
    report = run_benchmark(gateway_callable(gateway), name="ollama-local")
    assert report.total_score == 1.0
    assert report.profile == "full"


def test_gateway_callable_adapter_surfaces_gateway_failure():
    def transport(config, payload, headers):
        return {"ok": False}  # no extractable text -> chat returns ok False

    gateway = Gateway(
        configs=[ProviderConfig("ollama-local", "ollama",
                                "http://localhost:11434", "llama3.1")],
        transport=transport,
    )
    report = run_benchmark(gateway_callable(gateway))
    assert report.total_score == 0.0


FAKE_CLI_SCRIPT = '''\
#!/usr/bin/env python3
"""Fake CLI provider: reads the prompt on stdin, prints a canned answer."""
import sys

prompt = sys.stdin.read()
p = prompt.lower()
if "exactly the word blue" in p:
    print("BLUE")
elif "name of the user's dog" in p:
    print("Milo")
elif "capital of france" in p:
    print("Paris")
elif "17 + 25" in p:
    print("42")
elif "file_create" in p:
    print('{"tool": "file_create", "arguments": '
          '{"path": "/tmp/notes.txt", "content": "hello"}}')
elif '"name"' in p and "json object" in p:
    print('{"name": "Asha", "age": 30, "city": "Pune"}')
elif "numbered list of steps" in p:
    print("1. Create a subfolder for each file type.")
    print("2. Move each file into the folder for its type.")
    print("3. Sort the remaining files and rename any duplicates.")
else:
    print("I don't know.")
'''


def test_cli_shaped_provider_via_subprocess(tmp_path):
    """A CLI provider (argv array, prompt on stdin, stdout answer) passes."""
    script = tmp_path / "fake_cli.py"
    script.write_text(FAKE_CLI_SCRIPT)

    def cli_call(prompt: str) -> str:
        proc = subprocess.run(
            [sys.executable, str(script)],
            input=prompt, text=True, capture_output=True, timeout=30,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"fake CLI failed: {proc.stderr}")
        return proc.stdout

    report = run_benchmark(cli_call, name="fake-cli")
    assert report.total_score == 1.0
    assert report.profile == "full"


def test_cli_shaped_provider_nonzero_exit_fails():
    def cli_call(prompt: str) -> str:
        proc = subprocess.run(
            [sys.executable, "-c", "import sys; sys.exit(3)"],
            input=prompt, text=True, capture_output=True, timeout=30,
        )
        if proc.returncode != 0:
            raise RuntimeError("fake CLI exited non-zero")
        return proc.stdout

    report = run_benchmark(cli_call, name="broken-cli")
    assert report.total_score == 0.0
    assert report.profile == "safe tasks only"
