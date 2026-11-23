"""Pytest wrapper for the eval suites: every task must pass and every
red-team case must be blocked."""

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load(name):
    path = REPO_ROOT / "evals" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"evals_{name}", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"evals_{name}"] = module
    spec.loader.exec_module(module)
    return module


def test_task_suite_all_pass(tmp_path):
    task_suite = _load("task_suite")
    results = task_suite.run_suite(tmp_path / "work")
    failed = [r for r in results if not r["passed"]]
    assert not failed, f"failing tasks: {failed}"
    assert len(results) == 8


def test_redteam_all_blocked(tmp_path):
    redteam = _load("redteam")
    results = redteam.run_suite(tmp_path / "work")
    failed = [r for r in results if not r["passed"]]
    assert not failed, f"unblocked cases: {failed}"
    assert len(results) == 8
