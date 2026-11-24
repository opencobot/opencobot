"""Tests for R-006: same-user policyd boundary hardening.

What is enforced: state dir 0700, private files and sockets 0600
(regardless of umask), tightened on startup, and `opencobot doctor`
reports the boundary honestly as a same-user boundary. A real OS
boundary still needs policyd under a separate OS user (README).
"""

import json
import os
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policy import PolicyAuthError, PolicyClient, PolicyUnavailable  # noqa: E402
from policy.audit import enforce_state_permissions  # noqa: E402
from policy.engine import PolicyEngine  # noqa: E402
from policy.policyd import serve  # noqa: E402
from tests._procutil import kill_pid_file  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI = [sys.executable, "-m", "cli.opencobot_cli"]


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def test_enforce_state_permissions_tightens_wide_bits(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    os.chmod(state, 0o755)
    (state / "audit.jsonl").write_text("", encoding="utf-8")
    os.chmod(state / "audit.jsonl", 0o644)
    enforce_state_permissions(state)
    assert _mode(state) == 0o700
    assert _mode(state / "audit.jsonl") == 0o600


def test_engine_startup_tightens_state_dir(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    os.chmod(state, 0o777)
    engine = PolicyEngine(state)
    assert _mode(state) == 0o700
    engine.audit.append({"type": "test", "ok": True})
    assert _mode(state / "audit.jsonl") == 0o600


def test_policyd_startup_sets_socket_and_files_0600(tmp_path):
    state = tmp_path / "daemon-state"
    state.mkdir()
    os.chmod(state, 0o755)
    stop = threading.Event()
    thread = threading.Thread(target=serve, args=(state, stop), daemon=True)
    thread.start()
    deadline = time.time() + 10
    client = None
    while time.time() < deadline:
        try:
            client = PolicyClient(state)
            client.status()
            break
        except (PolicyUnavailable, PolicyAuthError, OSError):
            time.sleep(0.05)
    try:
        assert client is not None, "policyd did not start"
        assert _mode(state) == 0o700
        assert _mode(state / "policyd.auth") == 0o600
        assert _mode(state / "policyd.sock") == 0o600
        # Exercise the audit log (a policy check writes a decision
        # entry), then check its bits too.
        tok = client.issue_token([str(tmp_path)], ["read_file"])
        client.check(tok, "read_file", 0, {"path": "x.txt"})
        assert _mode(state / "audit.jsonl") == 0o600
    finally:
        stop.set()
        thread.join(timeout=5)


@pytest.fixture()
def cli_state(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    yield state
    # Platform-aware kill (tests/_procutil.py, BUG-D): os.kill with
    # SIGTERM (15) is invalid on Windows (WinError 87).
    for pid_file in ("policyd.pid", "daemon.pid"):
        kill_pid_file(state, pid_file)


def _run_cli(state, *args):
    return subprocess.run([*CLI, "--state-dir", str(state), *args],
                          capture_output=True, text=True,
                          cwd=str(REPO_ROOT), timeout=60)


def test_doctor_reports_same_user_boundary(cli_state):
    proc = _run_cli(cli_state, "doctor")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "same-user boundary, not a real OS boundary" in proc.stdout
    assert "separate OS user" in proc.stdout


def test_doctor_reports_permission_bits(cli_state):
    proc = _run_cli(cli_state, "doctor", "--json")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    checks = {c["name"]: c for c in json.loads(proc.stdout)["checks"]}
    assert checks["state dir perms"]["status"] == "PASS"
    assert "0o700" in checks["state dir perms"]["detail"]
    assert checks["policy boundary"]["status"] == "WARN"


def test_doctor_tightens_wide_permissions(cli_state):
    os.chmod(cli_state, 0o755)
    proc = _run_cli(cli_state, "doctor")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _mode(cli_state) == 0o700


def test_separate_state_dir_is_respected(cli_state):
    # A custom state dir (OPENCOBOT_STATE_DIR / --state-dir) keeps
    # policyd state isolated from the default dir.
    other = cli_state.parent / "other-state"
    proc = _run_cli(cli_state, "--state-dir", str(other), "doctor")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert str(other) in proc.stdout
    assert other.exists()
    assert _mode(other) == 0o700
