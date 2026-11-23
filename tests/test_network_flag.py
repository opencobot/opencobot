"""Tests for the token ``network`` flag (security-fixes round).

The flag is carried on the capability token (default False — fail
closed) and enforced by the policy engine: a call that performs
network access is denied when the token has network=False. See
ADR-006 and docs/risks.md (token network flag).
"""

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policy import PolicyAuthError, PolicyClient, PolicyUnavailable  # noqa: E402
from policy.engine import PolicyEngine  # noqa: E402
from policy.policyd import serve  # noqa: E402
from tools.definitions import get_tool, is_network_call, list_tools  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI = [sys.executable, "-m", "cli.opencobot_cli"]


def _engine_and_token(tmp_path, network=False, tools=("run_command",)):
    state_dir = tmp_path / "state"
    engine = PolicyEngine(state_dir)
    scope = tmp_path / "work"
    scope.mkdir(exist_ok=True)
    token = engine.issue_token([str(scope)], list(tools), network=network)
    return engine, token


def _approved_run(engine, token, args):
    """Approve and run the exact call; returns the Decision."""
    engine.approve(token.token_id, "run_command", 3, args)
    return engine.check(token, "run_command", 3, args,
                        network_call=is_network_call("run_command", args))


# -- classification ------------------------------------------------------

def test_run_command_is_the_only_network_capable_tool():
    capable = [t["name"] for t in list_tools() if t["network"]]
    assert capable == ["run_command"]
    assert get_tool("run_command").network is True
    assert get_tool("read_file").network is False


@pytest.mark.parametrize("argv,expected", [
    (["curl", "http://example.com"], True),
    (["wget", "-q", "http://example.com"], True),
    (["ssh", "host"], True),
    (["scp", "a", "b:."], True),
    (["rsync", "-a", "src", "dst"], True),
    (["/usr/bin/curl", "-s", "http://x"], True),
    (["git", "fetch"], True),
    (["git", "clone", "https://github.com/x/y"], True),
    (["git", "push"], True),
    (["git", "status"], False),
    (["git", "log", "--oneline"], False),
    (["echo", "hello"], False),
    (["python3", "-c", "print(1)"], False),
    ([], False),
    (None, False),
])
def test_is_network_call(argv, expected):
    args = {"argv": argv} if argv is not None else {}
    assert is_network_call("run_command", args) is expected


def test_is_network_call_only_applies_to_run_command():
    assert is_network_call("read_file", {"path": "x"}) is False
    assert is_network_call("launch_app", {"argv": ["curl"]}) is False


# -- engine enforcement ---------------------------------------------------

def test_network_call_denied_with_default_token(tmp_path):
    engine, token = _engine_and_token(tmp_path)  # network=False default
    assert token.network is False
    d = _approved_run(engine, token, {"argv": ["curl", "--version"]})
    assert d.allowed is False
    assert "network" in d.reason.lower()


def test_network_call_allowed_with_network_token(tmp_path):
    engine, token = _engine_and_token(tmp_path, network=True)
    d = _approved_run(engine, token, {"argv": ["curl", "--version"]})
    assert d.allowed is True


def test_non_network_call_unaffected_by_flag(tmp_path):
    engine, token = _engine_and_token(tmp_path)  # network=False
    d = _approved_run(engine, token, {"argv": ["echo", "hi"]})
    assert d.allowed is True


def test_network_denial_is_audited(tmp_path):
    engine, token = _engine_and_token(tmp_path)
    _approved_run(engine, token, {"argv": ["curl", "--version"]})
    entries = engine.audit.read_all()
    decision = [e for e in entries if e.get("type") == "policy_decision"]
    assert decision
    assert decision[-1]["allowed"] is False
    assert decision[-1]["network_call"] is True
    assert decision[-1]["token_network"] is False


def test_network_token_still_needs_approval(tmp_path):
    engine, token = _engine_and_token(tmp_path, network=True)
    # No approval granted: network flag alone does not authorise a
    # level-3 tool.
    d = engine.check(token, "run_command", 3,
                     {"argv": ["curl", "--version"]},
                     network_call=True)
    assert d.allowed is False and d.needs_approval is True


# -- policyd round-trip ---------------------------------------------------

@pytest.fixture()
def policyd_server(tmp_path):
    state = tmp_path / "daemon-state"
    state.mkdir()
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
    assert client is not None, "policyd did not start"
    yield state, client
    stop.set()
    thread.join(timeout=5)


def test_policyd_enforces_network_flag(policyd_server, tmp_path):
    state, client = policyd_server
    scope = tmp_path / "work"
    scope.mkdir()
    tok = client.issue_token([str(scope)], ["run_command"])
    assert tok.network is False
    args = {"argv": ["curl", "--version"]}
    client.approve(tok.token_id, "run_command", 3, args)
    assert client.check(tok, "run_command", 3, args).allowed is False
    # The client sends network_call=False by default, so this also
    # verifies policyd's own classification: a caller cannot downgrade
    # a network call by claiming it is not one.
    tok_net = client.issue_token([str(scope)], ["run_command"], network=True)
    assert tok_net.network is True
    client.approve(tok_net.token_id, "run_command", 3, args)
    assert client.check(tok_net, "run_command", 3, args).allowed is True


# -- CLI -----------------------------------------------------------------

@pytest.fixture()
def cli_state(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    yield state
    for pid_file in ("policyd.pid", "daemon.pid"):
        pid_path = state / pid_file
        if pid_path.exists():
            try:
                os.kill(int(pid_path.read_text().strip()), 15)
            except (ValueError, ProcessLookupError, PermissionError):
                pass


def _run_cli(state, *args):
    return subprocess.run([*CLI, "--state-dir", str(state), *args],
                          capture_output=True, text=True,
                          cwd=str(REPO_ROOT), timeout=60)


def test_cli_token_issue_network_flag(cli_state):
    r = _run_cli(cli_state, "token", "issue", "--tools", "run_command",
                 "--json")
    assert r.returncode == 0, r.stderr
    payload = json.loads(r.stdout)
    assert payload["network"] is False
    r = _run_cli(cli_state, "token", "issue", "--tools", "run_command",
                 "--network", "--json")
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["network"] is True


def test_cli_network_tool_denied_without_flag(cli_state):
    r = _run_cli(cli_state, "tool", "run", "run_command",
                 "--args-json", '{"argv": ["curl", "--version"]}',
                 "--approve")
    assert r.returncode != 0
    assert "network" in (r.stdout + r.stderr).lower()


def test_cli_network_tool_allowed_with_flag(cli_state):
    r = _run_cli(cli_state, "tool", "run", "run_command",
                 "--args-json", '{"argv": ["curl", "--version"]}',
                 "--approve", "--network")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "curl" in (r.stdout + r.stderr).lower()
