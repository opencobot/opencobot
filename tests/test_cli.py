"""Tests for the OpenCobot CLI (Phase 1, Linux MVP).

Runs the real CLI as a subprocess with the venv python, against tmp
state dirs. No network. Any policyd/daemon subprocess a test starts
is terminated in teardown (see the ``state_dir`` fixture).
"""

import json
import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI = [sys.executable, "-m", "cli.opencobot_cli"]


def _kill_pid_file(state_dir, name):
    pid_path = Path(state_dir) / name
    if not pid_path.exists():
        return
    try:
        pid = int(pid_path.read_text(encoding="utf-8").strip())
    except ValueError:
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except PermissionError:
        pass


@pytest.fixture()
def state_dir(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    yield state
    # Teardown: stop anything this test started (policyd / daemon).
    for pid_file in ("policyd.pid", "daemon.pid"):
        _kill_pid_file(state, pid_file)
    # Give them a moment, then SIGKILL leftovers.
    import time
    deadline = time.time() + 2.0
    for pid_file in ("policyd.pid", "daemon.pid"):
        pid_path = state / pid_file
        if pid_path.exists():
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
            else:
                try:
                    os.kill(pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass


def run_cli(state_dir, *args, timeout=60):
    return subprocess.run(
        CLI + ["--state-dir", str(state_dir), *args],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=timeout)


def run_cli_json(state_dir, *args, timeout=60):
    proc = run_cli(state_dir, *args, timeout=timeout)
    return proc, json.loads(proc.stdout)


def test_tools_list_contains_at_least_20_tools(state_dir):
    proc, payload = run_cli_json(state_dir, "tools", "list", "--json")
    assert proc.returncode == 0
    assert payload["count"] >= 20
    names = {t["name"] for t in payload["tools"]}
    assert "list_dir" in names
    assert "run_command" in names
    for tool in payload["tools"]:
        assert tool["name"] and tool["description"] and isinstance(tool["level"], int)


def test_tools_list_human_output(state_dir):
    proc = run_cli(state_dir, "tools", "list")
    assert proc.returncode == 0
    assert "list_dir" in proc.stdout
    assert "run_command" in proc.stdout


def test_tool_run_list_dir_succeeds_and_is_verified(state_dir, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "hello.txt").write_text("hi", encoding="utf-8")
    (data / "world.txt").write_text("yo", encoding="utf-8")
    proc = run_cli(state_dir, "tool", "run", "list_dir",
                   "--args-json", json.dumps({"path": str(data)}))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    result = json.loads(proc.stdout)
    assert result["ok"] is True
    assert result["verified"] is True
    names = {e["name"] for e in result["result"]["entries"]}
    assert names == {"hello.txt", "world.txt"}


def test_tool_run_run_command_denied_without_approval(state_dir):
    proc = run_cli(state_dir, "tool", "run", "run_command",
                   "--args-json", json.dumps({"argv": ["echo", "hi"]}))
    assert proc.returncode != 0
    assert "needs approval" in (proc.stdout + proc.stderr).lower()


def test_tool_run_run_command_succeeds_with_explicit_approval(state_dir):
    proc = run_cli(state_dir, "tool", "run", "run_command", "--approve",
                   "--args-json", json.dumps({"argv": ["echo", "hi"]}))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    result = json.loads(proc.stdout)
    assert result["ok"] is True
    assert result["verified"] is True
    assert result["result"]["stdout"].strip() == "hi"


def test_tool_run_unknown_tool_is_usage_error(state_dir):
    proc = run_cli(state_dir, "tool", "run", "no_such_tool",
                   "--args-json", "{}")
    assert proc.returncode == 2
    assert "unknown tool" in (proc.stdout + proc.stderr).lower()


def test_audit_verify_passes_after_a_run(state_dir, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    run_cli(state_dir, "tool", "run", "list_dir",
            "--args-json", json.dumps({"path": str(data)}))
    proc = run_cli(state_dir, "audit", "verify")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "OK" in proc.stdout
    proc = run_cli(state_dir, "audit", "show", "--limit", "5", "--json")
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["count"] >= 1
    assert all("hash" in e and "prev_hash" in e for e in payload["entries"])


def test_kill_blocks_tool_run_and_unkill_restores(state_dir, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "a.txt").write_text("a", encoding="utf-8")

    proc = run_cli(state_dir, "kill")
    assert proc.returncode == 0
    proc = run_cli(state_dir, "tool", "run", "list_dir",
                   "--args-json", json.dumps({"path": str(data)}))
    assert proc.returncode != 0
    assert "kill switch" in (proc.stdout + proc.stderr).lower()

    proc = run_cli(state_dir, "unkill")
    assert proc.returncode == 0
    proc = run_cli(state_dir, "tool", "run", "list_dir",
                   "--args-json", json.dumps({"path": str(data)}))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert json.loads(proc.stdout)["ok"] is True


def test_policy_check_reports_decisions_without_executing(state_dir):
    proc, payload = run_cli_json(state_dir, "policy", "check",
                                 "--tool", "list_dir", "--json")
    assert proc.returncode == 0
    assert payload["allowed"] is True
    proc, payload = run_cli_json(state_dir, "policy", "check",
                                 "--tool", "run_command", "--level", "3", "--json")
    assert proc.returncode == 0
    assert payload["allowed"] is False
    assert payload["needs_approval"] is True


def test_token_issue_prints_token_id_but_no_secret(state_dir):
    proc, payload = run_cli_json(
        state_dir, "token", "issue", "--json",
        "--folders", "/tmp", "--tools", "list_dir", "--duration", "600")
    assert proc.returncode == 0
    assert payload["token_id"]
    assert payload["tools"] == ["list_dir"]
    assert payload["duration_seconds"] == 600
    assert payload["expiry"]
    # The policyd auth secret stored on disk must never appear in output.
    auth_path = Path(state_dir) / "policyd.auth"
    if auth_path.exists():
        secret = auth_path.read_text(encoding="utf-8").strip()
        assert secret and secret not in proc.stdout
    # No token secret material may leak either: the output must contain
    # only the public record (token_id, expiry, folders, tools).
    assert set(payload) == {"token_id", "expiry", "folders", "tools",
                           "duration_seconds"}


def test_doctor_exits_zero(state_dir):
    proc = run_cli(state_dir, "doctor")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "PASS" in proc.stdout
    # Ollama / display are informational only: they must be reported
    # but must not fail the run when absent.
    assert "ollama" in proc.stdout.lower()
    assert "display" in proc.stdout.lower()


def test_daemon_status_reports_not_running(state_dir):
    proc = run_cli(state_dir, "daemon", "status")
    assert proc.returncode != 0
    assert "not running" in proc.stdout.lower()
