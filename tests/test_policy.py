"""Tests for the policy engine, tokens and policyd (policy/*.py)."""

import json
import os
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.transport import TransportNotAvailableError  # noqa: E402
from policy import (  # noqa: E402
    AuditLog,
    CapabilityToken,
    Decision,
    PolicyAuthError,
    PolicyClient,
    PolicyEngine,
    PolicyError,
    PolicyUnavailable,
)
from policy.policyd import _load_or_create_auth, serve  # noqa: E402


@pytest.fixture()
def state_dir(tmp_path):
    return tmp_path / "state"


@pytest.fixture()
def scope(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    return work


@pytest.fixture()
def engine(state_dir):
    return PolicyEngine(state_dir)


@pytest.fixture()
def token(engine, scope):
    return engine.issue_token(
        [str(scope)], ["read_file", "write_file", "delete_file", "run_shell"]
    )


def check(engine, token, tool="read_file", level=0, args=None, tainted=False):
    return engine.check(token, tool, level, args or {}, tainted=tainted)


# -- happy path: levels 0/1/2 in scope --------------------------------

@pytest.mark.parametrize("level", [0, 1, 2])
def test_allow_levels_0_1_2_in_scope(engine, token, scope, level):
    d = check(engine, token, "read_file", level, {"path": str(scope / "a.txt")})
    assert d.allowed is True
    assert d.needs_approval is False


def test_allow_without_path_args(engine, token):
    assert check(engine, token, "read_file", 1).allowed is True


def test_token_allows_tool_wildcard(engine, scope):
    tok = engine.issue_token([str(scope)], ["*"])
    assert check(engine, tok, "anything_at_all", 2).allowed is True


# -- levels 3/4 need approval -----------------------------------------

def test_level3_denied_without_approval_then_allowed_after(engine, token):
    d = check(engine, token, "delete_file", 3)
    assert d.allowed is False
    assert d.needs_approval is True
    assert "approval" in d.reason

    engine.approve(token.token_id, "delete_file", 3, {})
    d = check(engine, token, "delete_file", 3)
    assert d.allowed is True


def test_level4_denied_without_approval(engine, token):
    d = check(engine, token, "run_shell", 4)
    assert d.allowed is False
    assert d.needs_approval is True


def test_level4_allowed_after_approval(engine, token):
    engine.approve(token.token_id, "run_shell", 4, {})
    assert check(engine, token, "run_shell", 4).allowed is True


def test_approval_for_other_tool_or_token_does_not_count(engine, token):
    engine.approve(token.token_id, "write_file", 2, {})
    assert check(engine, token, "delete_file", 3).allowed is False
    engine.approve("some-other-token", "delete_file", 3, {})
    assert check(engine, token, "delete_file", 3).allowed is False


def test_expired_approval_does_not_count(engine, token):
    engine.approve(token.token_id, "delete_file", 3, {}, duration_seconds=-1)
    d = check(engine, token, "delete_file", 3)
    assert d.allowed is False
    assert d.needs_approval is True


def test_revoke_approval(engine, token):
    approval_id = engine.approve(token.token_id, "delete_file", 3, {})
    assert check(engine, token, "delete_file", 3).allowed is True
    assert engine.revoke_approval(approval_id) is True
    assert engine.revoke_approval(approval_id) is False
    assert check(engine, token, "delete_file", 3).allowed is False


def test_approvals_file_is_0600(engine, token):
    engine.approve(token.token_id, "delete_file", 3, {})
    mode = stat.S_IMODE(os.stat(engine.state_dir / "approvals.json").st_mode)
    assert mode == 0o600


# -- token failures ----------------------------------------------------

def test_deny_expired_token(engine, scope):
    tok = engine.issue_token([str(scope)], ["read_file"], duration_seconds=-10)
    assert tok.is_expired()
    d = check(engine, tok, "read_file", 0)
    assert d.allowed is False
    assert "expired" in d.reason


def test_deny_no_token(engine):
    d = engine.check(None, "read_file", 0, {})
    assert d.allowed is False


def test_deny_tool_outside_token_tools(engine, token):
    d = check(engine, token, "send_email", 1)
    assert d.allowed is False
    assert "tool" in d.reason


# -- path scope --------------------------------------------------------

@pytest.mark.parametrize("key", ["path", "source", "destination", "directory", "folder", "file", "cwd"])
def test_deny_path_outside_scope_for_each_key(engine, token, tmp_path, scope, key):
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    d = check(engine, token, "write_file", 2, {key: str(outside / "x.txt")})
    assert d.allowed is False
    assert d.reason == "outside capability token scope"


def test_deny_dotdot_escape(engine, token, tmp_path, scope):
    escape = scope / ".." / "elsewhere" / "secret.txt"
    d = check(engine, token, "read_file", 0, {"path": str(escape)})
    assert d.allowed is False


def test_deny_symlink_escape_via_resolved_path(engine, token, tmp_path, scope):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")
    link = scope / "link.txt"
    link.symlink_to(outside / "secret.txt")
    d = check(engine, token, "read_file", 0, {"path": str(link)})
    assert d.allowed is False


def test_allow_symlink_staying_inside_scope(engine, token, scope):
    real = scope / "real.txt"
    real.write_text("hi")
    link = scope / "alias.txt"
    link.symlink_to(real)
    assert check(engine, token, "read_file", 0, {"path": str(link)}).allowed is True


def test_empty_scope_denies_all_paths(engine):
    tok = engine.issue_token([], ["read_file"])
    assert tok.allows_path("/tmp/anything") is False
    assert check(engine, tok, "read_file", 0, {"path": "/tmp/x"}).allowed is False


# -- taint --------------------------------------------------------------

def test_tainted_level3_denied_even_after_approval(engine, token):
    engine.approve(token.token_id, "delete_file", 3, {})
    assert check(engine, token, "delete_file", 3).allowed is True
    d = check(engine, token, "delete_file", 3, tainted=True)
    assert d.allowed is False
    assert d.reason == "tainted context: level 3+ locked"


def test_tainted_level0_still_allowed(engine, token):
    assert check(engine, token, "read_file", 0, tainted=True).allowed is True


def test_mark_tainted_blocks_level3_without_flag(engine, token):
    engine.approve(token.token_id, "delete_file", 3, {})
    engine.mark_tainted(token.token_id)
    assert engine.is_tainted(token.token_id) is True
    assert check(engine, token, "delete_file", 3).allowed is False
    assert check(engine, token, "read_file", 0).allowed is True
    engine.clear_taint(token.token_id)
    assert engine.is_tainted(token.token_id) is False
    assert check(engine, token, "delete_file", 3).allowed is True


# -- kill switch ---------------------------------------------------------

def test_kill_switch_denies_everything_and_unkill_restores(engine, token):
    assert check(engine, token, "read_file", 0).allowed is True
    engine.set_kill(True)
    assert engine.is_killed() is True
    for level in (0, 1, 2, 3, 4):
        d = check(engine, token, "read_file", level)
        assert d.allowed is False
        assert d.reason == "kill switch active"
    engine.set_kill(False)
    assert engine.is_killed() is False
    assert check(engine, token, "read_file", 0).allowed is True


def test_kill_switch_survives_new_engine_instance(state_dir, engine, token):
    engine.set_kill(True)
    assert PolicyEngine(state_dir).is_killed() is True
    PolicyEngine(state_dir).set_kill(False)
    assert PolicyEngine(state_dir).is_killed() is False


# -- audit ---------------------------------------------------------------

def test_engine_audits_every_decision_and_chain_verifies(engine, token):
    check(engine, token, "read_file", 0)
    check(engine, token, "delete_file", 3)
    check(engine, None, "read_file", 0)
    log = AuditLog(engine.state_dir / "audit.jsonl")
    entries = log.read_all()
    assert len(entries) == 3
    assert all(e["type"] == "policy_decision" for e in entries)
    assert entries[0]["allowed"] is True
    assert entries[1]["allowed"] is False
    assert entries[2]["token_id"] is None
    valid, errors = log.verify()
    assert valid is True, errors


# -- policyd round-trip ---------------------------------------------------

@pytest.fixture()
def policyd_server(tmp_path):
    """Start policyd in a thread on a tmp state dir; yield (state_dir, client)."""
    state = tmp_path / "daemon-state"
    state.mkdir()
    stop = threading.Event()
    thread = threading.Thread(
        target=serve, args=(state, stop), daemon=True
    )
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


def test_policyd_check_issue_approve_kill_round_trip(policyd_server, tmp_path):
    state, client = policyd_server
    scope = tmp_path / "work"
    scope.mkdir()

    tok = client.issue_token([str(scope)], ["read_file", "delete_file"])
    assert isinstance(tok, CapabilityToken)
    assert tok.token_id

    d = client.check(tok, "read_file", 0, {"path": str(scope / "a.txt")})
    assert isinstance(d, Decision)
    assert d.allowed is True

    d = client.check(tok, "delete_file", 3)
    assert d.allowed is False and d.needs_approval is True

    client.approve(tok.token_id, "delete_file", 3, {})
    assert client.check(tok, "delete_file", 3).allowed is True

    assert client.kill() is True
    assert client.status()["killed"] is True
    assert client.check(tok, "read_file", 0).allowed is False
    assert client.unkill() is False
    assert client.check(tok, "read_file", 0).allowed is True

    assert client.taint(tok.token_id) is True
    assert client.check(tok, "delete_file", 3).allowed is False
    assert client.untaint(tok.token_id) is False
    assert client.check(tok, "delete_file", 3).allowed is True

    status = client.status()
    assert status["audit_entries"] > 0
    result = client.audit_verify()
    assert result["valid"] is True
    assert result["errors"] == []


def test_policyd_wrong_auth_rejected(policyd_server):
    state, client = policyd_server
    bad = PolicyClient(state)
    bad._auth = "0" * 64
    with pytest.raises(PolicyAuthError):
        bad.status()


def test_policyd_auth_file_reused_and_0600(policyd_server):
    state, _client = policyd_server
    auth_path = state / "policyd.auth"
    first = auth_path.read_text(encoding="utf-8").strip()
    assert len(first) == 64
    assert stat.S_IMODE(os.stat(auth_path).st_mode) == 0o600
    # Loading again returns the same token (generated once, reused).
    assert _load_or_create_auth(state) == first


def test_policyd_unknown_op_rejected(policyd_server):
    state, client = policyd_server
    with pytest.raises(PolicyError):
        client._request("explode")


# -- readonly + revoke_approval ops (R-022) -------------------------------
# Restored by agent/restore-r022-tests-status: these tests were added by
# PR #31 and lost when PR #32's merge kept its own version of this file.

def test_policyd_readonly_get_set_round_trip(policyd_server):
    _state, client = policyd_server
    assert client.get_readonly() is False
    assert client.readonly_info() == {"readonly": False, "source": "file"}
    assert client.set_readonly(True) is True
    assert client.get_readonly() is True
    assert client.readonly_info()["source"] == "file"
    assert client.set_readonly(False) is False
    assert client.get_readonly() is False


def test_policyd_readonly_rejects_non_bool(policyd_server):
    _state, client = policyd_server
    with pytest.raises(PolicyError, match="readonly needs enabled"):
        client._request("readonly", enabled="yes")
    # The rejected set did not change the flag.
    assert client.get_readonly() is False


def test_policyd_revoke_approval_round_trip(policyd_server):
    state, client = policyd_server
    engine = PolicyEngine(state)
    approval_id = engine.approve("tok-1", "read_file", 0, {}, 600)
    assert engine.has_approval("tok-1", "read_file", 0, {}) is True
    assert client.revoke_approval(approval_id) is True
    assert engine.has_approval("tok-1", "read_file", 0, {}) is False
    # Revoking again, or an unknown id, reports False (nothing removed).
    assert client.revoke_approval(approval_id) is False
    assert client.revoke_approval("no-such-id") is False


def test_policyd_readonly_and_revoke_reject_wrong_auth(policyd_server):
    state, client = policyd_server
    bad = PolicyClient(state)
    bad._auth = "0" * 64
    with pytest.raises(PolicyAuthError):
        bad.get_readonly()
    with pytest.raises(PolicyAuthError):
        bad.set_readonly(True)
    with pytest.raises(PolicyAuthError):
        bad.revoke_approval("whatever")
    # The rejected calls changed nothing.
    assert client.get_readonly() is False


# -- PolicyClient over a fake transport (Windows pipe race) ---------------


class _RecordingTransport:
    """Stand-in for a policyd connection: records requests, replays replies.

    Implements the transport API (``connect`` returns the stream) and
    the stream API core.transport uses (write/flush/readline) plus the
    context-manager protocol PolicyClient._request uses. With
    ``fail_connect_times`` set, the first N connects raise
    TransportNotAvailableError, simulating a transient connect
    failure (e.g. the Windows single-instance pipe race: the server
    has not recycled the instance yet when the next client connects).
    """

    def __init__(self, replies, fail_connect_times=0):
        self.replies = list(replies)
        self.requests = []
        self.fail_connect_times = fail_connect_times
        self.connect_attempts = 0

    def connect(self):
        self.connect_attempts += 1
        if self.connect_attempts <= self.fail_connect_times:
            raise TransportNotAvailableError(
                "simulated transient connect failure"
            )
        return self

    def write(self, data: bytes) -> None:
        self.requests.append(json.loads(data.decode("utf-8")))

    def flush(self) -> None:
        pass

    def readline(self) -> bytes:
        if not self.replies:
            return b""
        return (json.dumps(self.replies.pop(0)) + "\n").encode("utf-8")

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _client_with_fake_transport(state_dir, replies, fail_connect_times=0):
    """A PolicyClient whose transport is a recording fake.

    ``PolicyClient`` takes the transport in its constructor, so no
    socket is opened and no monkeypatching is needed.
    """
    state_dir.mkdir(parents=True, exist_ok=True)
    _load_or_create_auth(state_dir)
    fake = _RecordingTransport(replies,
                               fail_connect_times=fail_connect_times)
    return PolicyClient(state_dir, transport=fake), fake


def test_client_retries_transient_connect_failure(state_dir):
    """One failed connect (the pipe race) is retried and the call succeeds."""
    client, fake = _client_with_fake_transport(state_dir, [
        {"ok": True, "killed": False, "socket": "unix",
         "audit_entries": 0},
    ], fail_connect_times=1)
    assert client.status()["killed"] is False
    assert fake.connect_attempts == 2
    assert len(fake.requests) == 1
    assert fake.requests[0]["op"] == "status"


def test_client_connect_retries_are_bounded(state_dir):
    """A genuinely-down policyd still surfaces PolicyUnavailable promptly."""
    import time

    client, fake = _client_with_fake_transport(
        state_dir, [], fail_connect_times=999)
    start = time.monotonic()
    with pytest.raises(PolicyUnavailable):
        client.status()
    elapsed = time.monotonic() - start
    assert fake.connect_attempts == PolicyClient._CONNECT_ATTEMPTS
    assert elapsed < 2.0


def test_client_does_not_retry_auth_failure(state_dir):
    """Auth failures are not retried: only the connect is."""
    client, fake = _client_with_fake_transport(state_dir, [
        {"ok": False, "error": "auth failed"},
    ])
    with pytest.raises(PolicyAuthError):
        client.status()
    assert fake.connect_attempts == 1


def test_client_does_not_retry_mid_request_failure(state_dir):
    """A connect that succeeds but a reply that never comes is not retried."""
    client, fake = _client_with_fake_transport(state_dir, [])
    with pytest.raises(PolicyError, match="closed the connection"):
        client.status()
    assert fake.connect_attempts == 1


# -- readonly + revoke_approval client methods (R-022) -------------------
# Restored by agent/restore-r022-tests-status: added by PR #31, lost in
# the PR #32 merge. Adapted to PR #32's helper shape, which returns
# (client, fake) — the auth token is reloaded below for the assertion
# (the helper creates it once; reloading returns the same token).


def test_client_readonly_methods_send_readonly_op(state_dir):
    client, fake = _client_with_fake_transport(state_dir, [
        {"ok": True, "readonly": False, "source": "file"},
        {"ok": True, "readonly": True, "source": "file"},
        {"ok": True, "readonly": False, "source": "file"},
        {"ok": True, "readonly": True, "source": "env"},
    ])
    auth = _load_or_create_auth(state_dir)
    assert client.get_readonly() is False
    assert client.set_readonly(True) is True
    assert client.set_readonly(False) is False
    assert client.readonly_info() == {"readonly": True, "source": "env"}
    assert [(r["op"], r.get("enabled")) for r in fake.requests] == [
        ("readonly", None), ("readonly", True),
        ("readonly", False), ("readonly", None),
    ]
    assert all(r["auth"] == auth for r in fake.requests)


def test_client_revoke_approval_sends_op(state_dir):
    client, fake = _client_with_fake_transport(state_dir, [
        {"ok": True, "revoked": True},
        {"ok": True, "revoked": False},
    ])
    assert client.revoke_approval("appr-1") is True
    assert client.revoke_approval("nope") is False
    assert [(r["op"], r["approval_id"]) for r in fake.requests] == [
        ("revoke_approval", "appr-1"), ("revoke_approval", "nope"),
    ]


def test_client_unavailable_when_no_daemon(tmp_path):
    client_state = tmp_path / "no-daemon"
    client_state.mkdir()
    # Auth file must exist for the client to construct; socket does not.
    (client_state / "policyd.auth").write_text("a" * 64)
    client = PolicyClient(client_state)
    with pytest.raises(PolicyUnavailable):
        client.status()


def test_client_missing_auth_file(tmp_path):
    with pytest.raises(PolicyAuthError):
        PolicyClient(tmp_path / "empty-state")
