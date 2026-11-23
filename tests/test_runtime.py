"""Tests for core.runtime, core.memory and core.daemon.

Uses small fake policy/tools objects so the suite passes standalone even
though policy/ and tools/ are built in parallel; where the real modules
are importable, extra integration tests exercise them too.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from core.daemon import Daemon  # noqa: E402
from core.memory import Memory  # noqa: E402
from core.runtime import Runtime  # noqa: E402


# ---------------------------------------------------------------- fakes

class Decision:
    """Decision object shape (as opposed to a plain dict)."""

    def __init__(self, allowed, reason="", needs_approval=False):
        self.allowed = allowed
        self.reason = reason
        self.needs_approval = needs_approval


class StubPolicy:
    """L0-L2 allowed; L3+ needs an explicit approval for the tool."""

    def __init__(self):
        self.killed = False
        self.approved: set[str] = set()

    def is_killed(self):
        return self.killed

    def check(self, token, tool_name, level, args, tainted):
        if level >= 3 and tool_name not in self.approved:
            return {"allowed": False, "reason": "approval required",
                    "needs_approval": True}
        return {"allowed": True, "reason": "allowed", "needs_approval": False}


class DecisionObjectPolicy(StubPolicy):
    def check(self, token, tool_name, level, args, tainted):
        raw = super().check(token, tool_name, level, args, tainted)
        return Decision(raw["allowed"], raw["reason"], raw["needs_approval"])


def make_echo_tool():
    return SimpleNamespace(
        level=0,
        schema={"type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"]},
        description="Echo text back",
        execute=lambda args, ctx: {"ok": True, "echo": args["text"]},
        verify=lambda args, result, ctx: (True, "echo verified"),
    )


def make_create_file_tool():
    def execute(args, ctx):
        path = Path(ctx["workdir"]) / args["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(args["content"], encoding="utf-8")
        return {"ok": True, "path": str(path)}

    def verify(args, result, ctx):
        path = Path(ctx["workdir"]) / args["path"]
        if not path.exists():
            return False, "file missing after execute"
        if path.read_text(encoding="utf-8") != args["content"]:
            return False, "file content mismatch"
        return True, "file exists with expected content"

    return SimpleNamespace(
        level=0,
        schema={"type": "object",
                "properties": {"path": {"type": "string"},
                               "content": {"type": "string"}},
                "required": ["path", "content"]},
        description="Create a file",
        execute=execute,
        verify=verify,
    )


def make_write_file_tool():
    """L3 tool: same behaviour as create_file, but sensitive level."""
    tool = make_create_file_tool()
    tool.level = 3
    tool.description = "Write a file (sensitive)"
    return tool


def make_unverified_tool():
    return SimpleNamespace(
        level=0,
        schema={"type": "object", "properties": {}, "required": []},
        description="Never verifies",
        execute=lambda args, ctx: {"ok": True},
        verify=lambda args, result, ctx: (False, "verification failed"),
    )


def make_boom_tool():
    def execute(args, ctx):
        raise RuntimeError("kaboom")

    return SimpleNamespace(
        level=0,
        schema={"type": "object", "properties": {}, "required": []},
        description="Always raises",
        execute=execute,
        verify=lambda args, result, ctx: (True, ""),
    )


@pytest.fixture
def registry():
    return {
        "echo": make_echo_tool(),
        "create_file": make_create_file_tool(),
        "write_file": make_write_file_tool(),
        "unverified": make_unverified_tool(),
        "boom": make_boom_tool(),
    }


@pytest.fixture
def runtime(tmp_path, registry):
    return Runtime(tmp_path, StubPolicy(), registry)


def audit_entries(state_dir):
    path = Path(state_dir) / "audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


# ---------------------------------------------------------------- runtime

def test_l0_tool_allowed_and_verified_with_real_file_state(tmp_path, runtime):
    workdir = tmp_path / "scope"
    workdir.mkdir()
    token = {"folders": [str(workdir)]}
    out = runtime.run_tool(token, "create_file",
                           {"path": "hello.txt", "content": "hi"}, tainted=False)
    assert out["ok"] is True
    assert out["verified"] is True
    assert (workdir / "hello.txt").read_text(encoding="utf-8") == "hi"
    assert out["evidence"] == "file exists with expected content"
    assert out["decision"]["allowed"] is True


def test_echo_tool(runtime):
    out = runtime.run_tool(None, "echo", {"text": "hello"})
    assert out == {
        "ok": True,
        "verified": True,
        "decision": {"allowed": True, "reason": "allowed", "needs_approval": False},
        "result": {"ok": True, "echo": "hello"},
        "evidence": "echo verified",
    }


def test_l3_denied_without_approval_then_allowed_after(runtime):
    denied = runtime.run_tool(None, "write_file",
                              {"path": "x.txt", "content": "x"})
    assert denied["ok"] is False
    assert denied["verified"] is False
    assert denied["decision"]["allowed"] is False
    assert denied["decision"]["needs_approval"] is True
    assert "approval required" in denied["decision"]["reason"]

    runtime.policy.approved.add("write_file")
    allowed = runtime.run_tool(None, "write_file",
                               {"path": "x.txt", "content": "x"})
    assert allowed["ok"] is True
    assert allowed["verified"] is True


def test_policy_decision_object_is_accepted(tmp_path, registry):
    rt = Runtime(tmp_path, DecisionObjectPolicy(), registry)
    out = rt.run_tool(None, "echo", {"text": "hi"})
    assert out["ok"] is True
    assert out["decision"]["allowed"] is True


def test_kill_switch_blocks_and_audits(tmp_path, registry):
    policy = StubPolicy()
    policy.killed = True
    rt = Runtime(tmp_path, policy, registry)
    out = rt.run_tool(None, "echo", {"text": "hi"})
    assert out["ok"] is False
    assert "kill switch active" in out["decision"]["reason"]
    entries = audit_entries(tmp_path)
    assert entries and entries[-1]["tool"] == "echo"
    assert entries[-1]["ok"] is False


def test_invalid_args_rejected(runtime):
    assert runtime.run_tool(None, "echo", {})["ok"] is False  # missing required
    assert runtime.run_tool(None, "echo", {"text": 42})["ok"] is False  # wrong type
    assert runtime.run_tool(None, "echo", {"text": "x", "extra": 1})["ok"] is False
    denied = runtime.run_tool(None, "echo", {"text": 42})
    assert "invalid args" in denied["decision"]["reason"]


def test_unknown_tool_rejected(runtime):
    out = runtime.run_tool(None, "nope", {})
    assert out["ok"] is False
    assert out["decision"]["reason"] == "unknown tool"


def test_execute_exception_is_failure_not_crash(runtime):
    out = runtime.run_tool(None, "boom", {})
    assert out["ok"] is False
    assert out["verified"] is False
    assert "kaboom" in out["result"]["error"]


def test_verify_failure_means_not_ok(runtime):
    out = runtime.run_tool(None, "unverified", {})
    assert out["ok"] is False
    assert out["verified"] is False
    assert out["evidence"] == "verification failed"


def test_audit_log_entry_written_and_verifiable(tmp_path, runtime):
    runtime.run_tool(None, "echo", {"text": "secret-free"})
    runtime.run_tool(None, "echo", {"text": "x", "api_key": "should-not-appear"})
    entries = audit_entries(tmp_path)
    assert len(entries) == 2
    assert entries[0]["type"] == "tool_call"
    assert entries[0]["tool"] == "echo"
    assert entries[0]["ok"] is True
    assert entries[0]["verified"] is True
    # Secrets in args must be redacted in the audit log.
    assert entries[1]["args"].get("api_key") == "[REDACTED]"
    assert "should-not-appear" not in (tmp_path / "audit.jsonl").read_text()
    try:
        from policy.audit import AuditLog
    except Exception:
        pytest.skip("real AuditLog not available yet")
    valid, errors = AuditLog(tmp_path / "audit.jsonl").verify()
    assert valid is True, errors


def test_list_tools(runtime):
    tools = runtime.list_tools()
    by_name = {t["name"]: t for t in tools}
    assert by_name["echo"]["level"] == 0
    assert by_name["write_file"]["level"] == 3
    assert by_name["echo"]["schema"]["required"] == ["text"]


def test_real_registry_if_importable(tmp_path):
    try:
        from tools.definitions import TOOLS
    except Exception:
        pytest.skip("real tool registry not available yet")
    assert isinstance(TOOLS, dict) and TOOLS
    rt = Runtime(tmp_path, StubPolicy(), TOOLS)
    assert len(rt.list_tools()) == len(TOOLS)


def test_real_policy_engine_if_importable(tmp_path, registry):
    try:
        from policy.engine import PolicyEngine
    except Exception:
        pytest.skip("real PolicyEngine not available yet")
    rt = Runtime(tmp_path, PolicyEngine(tmp_path), registry)
    out = rt.run_tool(None, "echo", {"text": "hi"})
    assert set(out) >= {"ok", "verified", "decision", "result", "evidence"}
    assert isinstance(out["decision"], dict) and "allowed" in out["decision"]


# ---------------------------------------------------------------- memory

def test_memory_store_get_delete_list(tmp_path):
    mem = Memory(tmp_path)
    assert mem.get("missing") is None
    mem.store("prefs", {"theme": "dark"})
    mem.store("project", {"name": "demo"})
    assert mem.get("prefs") == {"theme": "dark"}
    assert mem.list_keys() == ["prefs", "project"]
    mem.store("prefs", {"theme": "light"})
    assert mem.get("prefs") == {"theme": "light"}
    mem.delete("project")
    assert mem.list_keys() == ["prefs"]
    mem.delete("project")  # deleting a missing key is fine


@pytest.mark.parametrize("bad_key", ["api_key", "my_secret", "password", "auth_token",
                                     "SECRET_VALUE"])
def test_memory_rejects_secret_keys(tmp_path, bad_key):
    mem = Memory(tmp_path)
    with pytest.raises(ValueError, match="secrets must not be stored in memory"):
        mem.store(bad_key, {"x": 1})


def test_memory_rejects_secret_keys_inside_values(tmp_path):
    mem = Memory(tmp_path)
    with pytest.raises(ValueError, match="secrets must not be stored in memory"):
        mem.store("config", {"password": "hunter2"})


# ---------------------------------------------------------------- daemon

def _daemon_call(sock_path, payload):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(10)
        sock.connect(str(sock_path))
        sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    return json.loads(buf.decode("utf-8"))


def test_daemon_status_list_tools_and_policyd_unavailable(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    # A stale regular file where the socket will go must not block startup.
    (state_dir / "daemon.sock").write_text("stale", encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT)
    proc = subprocess.Popen(
        [sys.executable, "-m", "core.daemon", "--state-dir", str(state_dir)],
        cwd=REPO_ROOT, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        sock_path = state_dir / "daemon.sock"
        auth_path = state_dir / "daemon.auth"
        deadline = time.time() + 15
        while time.time() < deadline:
            # The stale regular file pre-created at sock_path must not count:
            # wait until the daemon has written its auth token AND the path
            # is a real socket.
            if auth_path.exists() and sock_path.exists():
                import stat as _stat
                if _stat.S_ISSOCK(sock_path.stat().st_mode):
                    break
            if proc.poll() is not None:
                break
            time.sleep(0.1)
        assert proc.poll() is None, "daemon exited during startup"
        assert auth_path.exists(), "daemon auth file never appeared"
        assert sock_path.exists(), "daemon socket never appeared"
        token = auth_path.read_text(encoding="utf-8").strip()
        assert len(token) == 64
        assert oct((state_dir / "daemon.auth").stat().st_mode & 0o777) == "0o600"

        assert _daemon_call(sock_path, {"auth": "wrong", "op": "status"}) == {
            "ok": False, "error": "unauthorized"}

        status = _daemon_call(sock_path, {"auth": token, "op": "status"})
        assert status["ok"] is True
        try:
            from tools.definitions import TOOLS
            expected_tools = len(TOOLS)
        except Exception:
            expected_tools = 0
        assert status["tools"] == expected_tools
        assert status["policyd_reachable"] is False
        assert status["killed"] is False

        listed = _daemon_call(sock_path, {"auth": token, "op": "list_tools"})
        assert listed["ok"] is True
        assert len(listed["tools"]) == expected_tools

        run = _daemon_call(sock_path, {"auth": token, "op": "run_tool",
                                       "token": None, "tool_name": "echo",
                                       "args": {"text": "hi"}, "tainted": False})
        assert run["ok"] is False
        assert run["decision"]["reason"] == "policyd unavailable"

        kill = _daemon_call(sock_path, {"auth": token, "op": "kill"})
        assert kill == {"ok": False, "error": "policyd unavailable"}

        gw = _daemon_call(sock_path, {"auth": token, "op": "gateway_status"})
        assert gw["ok"] is True
        assert gw["provider"] == "ollama-local"
        assert gw["model"] == "llama3.1"
        assert gw["available"] is False  # no Ollama in the test env

        assert _daemon_call(sock_path, {"auth": token, "op": "bogus"})["ok"] is False
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
