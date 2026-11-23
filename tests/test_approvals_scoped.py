"""Tests for R-007: approvals are level-scoped and argument-bound (ADR-005).

An approval is (token_id, tool_name, level, argument_hash). It must
authorise exactly one call: the same tool with different arguments, or
the same arguments at a different level, must be denied and need a
fresh approval. Only the argument hash is stored — never raw args.
"""

import json
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policy import PolicyAuthError, PolicyClient, PolicyUnavailable  # noqa: E402
from policy.engine import PolicyEngine, argument_hash  # noqa: E402
from policy.policyd import serve  # noqa: E402


@pytest.fixture()
def policyd_server(tmp_path):
    """Start policyd in a thread on a tmp state dir; yield (state, client)."""
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


def test_policyd_scoped_approval_round_trip(policyd_server, tmp_path):
    state, client = policyd_server
    scope = tmp_path / "work"
    scope.mkdir()
    tok = client.issue_token([str(scope)], ["run_command"])
    args = {"argv": ["echo", "hi"]}
    assert client.check(tok, "run_command", 3, args).allowed is False
    client.approve(tok.token_id, "run_command", 3, args)
    assert client.check(tok, "run_command", 3, args).allowed is True
    # Replay with different arguments over the same policyd: denied.
    assert client.check(tok, "run_command", 3,
                        {"argv": ["echo", "bye"]}).allowed is False
    # And at a different level: denied.
    assert client.check(tok, "run_command", 4, args).allowed is False



def _engine_and_token(tmp_path, tools=("run_command", "delete_to_trash")):
    state_dir = tmp_path / "state"
    engine = PolicyEngine(state_dir)
    scope = tmp_path / "work"
    scope.mkdir(exist_ok=True)
    token = engine.issue_token([str(scope)], list(tools))
    return engine, token


# -- argument_hash ------------------------------------------------------

def test_argument_hash_is_key_order_independent():
    assert argument_hash({"b": 1, "a": [1, 2]}) == argument_hash({"a": [1, 2], "b": 1})


def test_argument_hash_differs_for_different_args():
    assert argument_hash({"argv": ["echo", "hi"]}) != argument_hash(
        {"argv": ["echo", "bye"]})
    assert argument_hash({}) != argument_hash({"argv": ["echo"]})


def test_argument_hash_none_equals_empty():
    assert argument_hash(None) == argument_hash({})


# -- exact-match approvals ----------------------------------------------

def test_approval_allows_exact_call_only(tmp_path):
    engine, token = _engine_and_token(tmp_path)
    args = {"argv": ["echo", "hi"]}
    engine.approve(token.token_id, "run_command", 3, args)
    assert engine.check(token, "run_command", 3, args).allowed is True
    # Same tool, different arguments: denied, needs a fresh approval.
    d = engine.check(token, "run_command", 3, {"argv": ["echo", "bye"]})
    assert d.allowed is False and d.needs_approval is True
    # Same tool and arguments, different level: denied.
    d = engine.check(token, "run_command", 4, args)
    assert d.allowed is False and d.needs_approval is True
    # Same arguments, different tool: denied.
    d = engine.check(token, "delete_to_trash", 3, args)
    assert d.allowed is False


def test_approval_record_stores_hash_not_raw_args(tmp_path):
    engine, token = _engine_and_token(tmp_path)
    engine.approve(token.token_id, "run_command", 3,
                   {"argv": ["echo", "secret-word-123"]})
    raw = (tmp_path / "state" / "approvals.json").read_text()
    assert "secret-word-123" not in raw
    assert argument_hash({"argv": ["echo", "secret-word-123"]}) in raw


def test_approval_without_level_never_matches(tmp_path):
    engine, token = _engine_and_token(tmp_path)
    # Legacy-style approval with no level: recorded, but fail-closed —
    # it can never match a real check, which always has a level.
    engine.approve(token.token_id, "run_command")
    assert engine.check(token, "run_command", 3,
                        {"argv": ["echo", "hi"]}).allowed is False


def test_approval_expiry_still_enforced(tmp_path):
    engine, token = _engine_and_token(tmp_path)
    args = {"argv": ["echo", "hi"]}
    engine.approve(token.token_id, "run_command", 3, args,
                   duration_seconds=-1)
    d = engine.check(token, "run_command", 3, args)
    assert d.allowed is False and d.needs_approval is True


def test_revoke_scoped_approval(tmp_path):
    engine, token = _engine_and_token(tmp_path)
    args = {"argv": ["echo", "hi"]}
    approval_id = engine.approve(token.token_id, "run_command", 3, args)
    assert engine.check(token, "run_command", 3, args).allowed is True
    assert engine.revoke_approval(approval_id) is True
    assert engine.check(token, "run_command", 3, args).allowed is False


def test_tainted_call_denied_even_with_exact_approval(tmp_path):
    engine, token = _engine_and_token(tmp_path)
    args = {"argv": ["echo", "hi"]}
    engine.approve(token.token_id, "run_command", 3, args)
    engine.mark_tainted(token.token_id)
    assert engine.check(token, "run_command", 3, args).allowed is False


def test_audit_records_arg_hash_not_raw_args(tmp_path):
    engine, token = _engine_and_token(tmp_path)
    args = {"argv": ["echo", "audit-secret-456"]}
    engine.check(token, "run_command", 3, args)
    entries = engine.audit.read_all()
    decision = [e for e in entries if e.get("type") == "policy_decision"]
    assert decision
    assert decision[-1]["arg_hash"] == argument_hash(args)
    assert "audit-secret-456" not in json.dumps(entries)
