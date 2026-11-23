"""Tests for `opencobot doctor` on Windows, where os.getuid is missing.

Windows has no os.getuid, so doctor used to crash with an unhandled
AttributeError. These tests simulate Windows by deleting os.getuid
before the CLI starts (in a subprocess, so the real CLI code path is
exercised) and assert doctor completes and reports the
policy-boundary identity check as skipped instead of crashing.
"""

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# Wrapper run with `python -c`: deletes os.getuid first (as on
# Windows), then runs the real CLI main() with the remaining argv.
# Nothing else in the CLI or policy code calls os.getuid, so this
# isolates exactly the doctor identity check.
_NO_GETUID_WRAPPER = (
    "import os, sys; del os.getuid; "
    "from cli.opencobot_cli import main; "
    "raise SystemExit(main(sys.argv[1:]))"
)


@pytest.fixture()
def state_dir(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    yield state
    # Teardown: stop anything this test started (policyd).
    for pid_file in ("policyd.pid", "daemon.pid"):
        pid_path = state / pid_file
        if not pid_path.exists():
            continue
        try:
            pid = int(pid_path.read_text(encoding="utf-8").strip())
        except ValueError:
            continue
        try:
            os.kill(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
    deadline = time.time() + 2.0
    for pid_file in ("policyd.pid", "daemon.pid"):
        pid_path = state / pid_file
        if not pid_path.exists():
            continue
        try:
            pid = int(pid_path.read_text(encoding="utf-8").strip())
        except ValueError:
            continue
        while time.time() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)


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
