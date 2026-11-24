"""Tests for `opencobot doctor` on Windows, where os.getuid is missing.

Windows has no os.getuid, so doctor used to crash with an unhandled
AttributeError. These tests simulate Windows by deleting os.getuid
before the CLI starts (in a subprocess, so the real CLI code path is
exercised) and assert doctor completes and reports the
policy-boundary identity check as skipped instead of crashing.
The deletion is guarded (``try/except AttributeError``) so the
simulation also works on a real Windows host, where os.getuid
does not exist to delete in the first place.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(REPO_ROOT))

from tests._procutil import kill_pid_file, reap_pid_file  # noqa: E402

# Wrapper run with `python -c`: deletes os.getuid first (as on
# Windows), then runs the real CLI main() with the remaining argv.
# The deletion is guarded: on real Windows os.getuid does not exist,
# so a bare `del os.getuid` would raise AttributeError before the
# CLI even starts. Nothing else in the CLI or policy code calls
# os.getuid, so this isolates exactly the doctor identity check.
_NO_GETUID_WRAPPER = (
    "import os, sys\n"
    "try:\n"
    "    del os.getuid\n"
    "except AttributeError:\n"
    "    pass  # already absent, as on real Windows\n"
    "from cli.opencobot_cli import main\n"
    "raise SystemExit(main(sys.argv[1:]))\n"
)


@pytest.fixture()
def state_dir(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    yield state
    # Teardown: stop anything this test started (policyd).
    # Platform-aware kill (tests/_procutil.py, BUG-D): os.kill with
    # SIGTERM is invalid on Windows (WinError 87).
    for pid_file in ("policyd.pid", "daemon.pid"):
        kill_pid_file(state, pid_file)
    for pid_file in ("policyd.pid", "daemon.pid"):
        reap_pid_file(state, pid_file, timeout=2.0)


def _run_doctor_without_getuid(state, *extra_args):
    return subprocess.run(
        [sys.executable, "-c", _NO_GETUID_WRAPPER,
         "--state-dir", str(state), "doctor", *extra_args],
        capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=60)


def test_doctor_without_getuid_completes(state_dir):
    proc = _run_doctor_without_getuid(state_dir)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Traceback" not in proc.stderr
    assert "AttributeError" not in proc.stderr
    assert "policy boundary" in proc.stdout
    assert "unavailable on Windows" in proc.stdout
    assert "same-user identity check skipped" in proc.stdout


def test_doctor_without_getuid_reports_check_skipped_json(state_dir):
    proc = _run_doctor_without_getuid(state_dir, "--json")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Traceback" not in proc.stderr
    checks = {c["name"]: c for c in json.loads(proc.stdout)["checks"]}
    boundary = checks["policy boundary"]
    assert boundary["status"] == "INFO"
    assert boundary["essential"] is False
    assert "skipped" in boundary["detail"]
    assert "os.getuid" in boundary["detail"]
