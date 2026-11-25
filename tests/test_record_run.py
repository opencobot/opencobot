"""Tests for evals/record_run.py — the test-run recorder.

The parser is tested on canned pytest output; the end-to-end test runs
pytest on a tiny temporary test file (1 pass + 1 skip) and checks the
results file the tool writes. No real suite run is needed here.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from evals.record_run import (  # noqa: E402
    build_report,
    git_info,
    os_token,
    parse_pytest_output,
    resolve_pytest_args,
    run_record,
)

ALL_PASS = """\
....................                                                    [100%]
625 passed, 1 skipped in 45.87s
"""

WITH_FAILURES = """\
tests/test_example.py::test_a PASSED                                [ 25%]
tests/test_example.py::test_b FAILED                                [ 50%]
tests/test_example.py::test_c SKIPPED (needs network)               [ 75%]
tests/test_example.py::test_d PASSED                                [100%]
=========================== short test summary info ============================
FAILED tests/test_example.py::test_b - assert 1 == 2
SKIPPED [1] tests/test_example.py::test_c: needs network
================= 1 failed, 2 passed, 1 skipped in 0.42s ==================
"""

WITH_ERROR = """\
ERROR tests/test_broken.py - collected 0 items / 1 error
=========================== short test summary info ============================
ERROR tests/test_broken.py - SyntaxError: invalid syntax
==================== 1 error in 0.12s ====================
"""

NO_SUMMARY = "usage: pytest [options] [file_or_dir]\npytest: error: unrecognized arguments: --nope\n"


def test_parse_all_passed_counts():
    parsed = parse_pytest_output(ALL_PASS)
    assert parsed["passed"] == 625
    assert parsed["failed"] == 0
    assert parsed["skipped"] == 1
    assert parsed["errors"] == 0
    assert parsed["duration_seconds"] == pytest.approx(45.87)
    assert parsed["failed_tests"] == []
    assert len(parsed["skipped_tests"]) == 0  # no summary block in this sample


def test_parse_with_failures_lists_failed_and_skipped():
    parsed = parse_pytest_output(WITH_FAILURES)
    assert parsed["passed"] == 2
    assert parsed["failed"] == 1
    assert parsed["skipped"] == 1
    assert parsed["duration_seconds"] == pytest.approx(0.42)
    assert parsed["failed_tests"] == [
        "FAILED tests/test_example.py::test_b - assert 1 == 2"
    ]
    assert parsed["skipped_tests"] == [
        "SKIPPED [1] tests/test_example.py::test_c: needs network"
    ]


def test_parse_error_output():
    parsed = parse_pytest_output(WITH_ERROR)
    assert parsed["errors"] == 1
    assert parsed["error_tests"] == [
        "ERROR tests/test_broken.py - SyntaxError: invalid syntax"
    ]


def test_parse_no_summary_keeps_raw_tail():
    parsed = parse_pytest_output(NO_SUMMARY)
    assert parsed["summary_line"] == ""
    assert parsed["duration_seconds"] is None
    assert any("--nope" in line for line in parsed["raw_tail"])


def test_build_report_contains_required_fields(tmp_path):
    parsed = parse_pytest_output(WITH_FAILURES)
    report = build_report(
        parsed=parsed,
        command=[sys.executable, "-m", "pytest", "-q", "-rs"],
        by="human",
        repo_root=tmp_path,  # not a git repo -> commit "unknown"
    )
    for field in ("OS:", "Python:", "Git commit:", "Recorded by: human",
                  "Command", "Passed: 2", "Failed: 1", "Skipped: 1",
                  "Duration: 0.42s", "test_b - assert 1 == 2",
                  "needs network", "measured output only"):
        assert field in report, field
    assert "unknown" in report  # git info unavailable in tmp_path


def test_resolve_pytest_args_defaults():
    # Both "not given" and "given empty" must keep -q -rs: without -rs
    # skipped tests are counted but never listed (found by the first
    # record_run run, whose results file listed 1 skipped and no reason).
    assert resolve_pytest_args(None) == ["-q", "-rs"]
    assert resolve_pytest_args([]) == ["-q", "-rs"]
    assert resolve_pytest_args(["tests/test_tools.py"]) == ["tests/test_tools.py"]


def test_os_token_matches_platform():
    assert os_token() == ("windows" if sys.platform.startswith("win")
                          else "macos" if sys.platform == "darwin"
                          else "linux")


def test_git_info_unknown_outside_repo(tmp_path):
    sha, dirty = git_info(tmp_path)
    assert sha == "unknown"
    assert dirty == "unknown"


def test_run_writes_results_file(tmp_path):
    test_file = tmp_path / "test_tiny.py"
    test_file.write_text(
        "import pytest\n"
        "\n"
        "def test_passes():\n"
        "    assert 1 == 1\n"
        "\n"
        "@pytest.mark.skip(reason='demo skip')\n"
        "def test_skipped():\n"
        "    assert False\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "results"
    path, returncode = run_record(
        by="human",
        pytest_args=["-q", "-rs", str(test_file)],
        output_dir=out_dir,
        repo_root=tmp_path,
    )
    assert returncode == 0
    assert path.parent == out_dir
    assert path.name.startswith("20") and path.suffix == ".md"
    text = path.read_text(encoding="utf-8")
    assert "Passed: 1" in text
    assert "Failed: 0" in text
    assert "Skipped: 1" in text
    assert "demo skip" in text
    assert "Recorded by: human" in text
    assert "Git commit: `unknown`" in text
