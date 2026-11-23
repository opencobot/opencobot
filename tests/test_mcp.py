"""Tests for the OpenCobot MCP server (Phase 1, Linux MVP).

Drives the real server as a subprocess over stdio JSON-RPC 2.0, with a
tmp state dir. No network.
"""

import json
import select
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SERVER = [sys.executable, "mcp-server/server.py"]


class MCPClient:
    def __init__(self, state_dir):
        self.proc = subprocess.Popen(
            SERVER + ["--state-dir", str(state_dir)],
            cwd=REPO_ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1)
        self._next_id = 1

    def _readline(self, timeout=10.0):
        ready, _w, _x = select.select([self.proc.stdout], [], [], timeout)
        if not ready:
            raise TimeoutError("no MCP response within timeout")
        line = self.proc.stdout.readline()
        if not line:
            raise EOFError("MCP server closed stdout")
        return json.loads(line)

    def send(self, obj):
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def request(self, method, params=None):
        req_id = self._next_id
        self._next_id += 1
        req = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            req["params"] = params
        self.send(req)
        resp = self._readline()
        assert resp.get("id") == req_id, resp
        return resp

    def notify(self, method, params=None):
        req = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            req["params"] = params
        self.send(req)

    def close(self):
        try:
            self.proc.stdin.close()
        except BrokenPipeError:
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)


@pytest.fixture()
def mcp(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    client = MCPClient(state)
    try:
        resp = client.request("initialize", {})
        assert "result" in resp, resp
        client.notify("notifications/initialized")
        yield client
    finally:
        client.close()


def test_initialize(mcp):
    resp = mcp.request("initialize", {"protocolVersion": "2024-11-05",
                                      "capabilities": {},
                                      "clientInfo": {"name": "test", "version": "0"}})
    result = resp["result"]
    assert result["protocolVersion"] == "2024-11-05"
    assert result["capabilities"] == {"tools": {}}
    assert result["serverInfo"]["name"] == "opencobot"
    assert result["serverInfo"]["version"] == "0.1.0"


def test_ping(mcp):
    resp = mcp.request("ping")
    assert resp["result"] == {}


def test_tools_list_returns_at_least_20_tools(mcp):
    resp = mcp.request("tools/list")
    tools = resp["result"]["tools"]
    assert len(tools) >= 20
    by_name = {t["name"]: t for t in tools}
    assert "list_dir" in by_name
    assert "run_command" in by_name
    for tool in tools:
        assert tool["description"]
        assert isinstance(tool["inputSchema"], dict)
        assert tool["inputSchema"].get("type") == "object"


def test_tools_call_list_dir_returns_real_listing(mcp, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "alpha.txt").write_text("a", encoding="utf-8")
    (data / "beta.txt").write_text("b", encoding="utf-8")
    resp = mcp.request("tools/call", {"name": "list_dir",
                                      "arguments": {"path": str(data)}})
    result = resp["result"]
    assert result["isError"] is False, result
    assert len(result["content"]) == 1
    assert result["content"][0]["type"] == "text"
    payload = json.loads(result["content"][0]["text"])
    assert payload["ok"] is True
    assert payload["verified"] is True
    names = {e["name"] for e in payload["result"]["entries"]}
    assert names == {"alpha.txt", "beta.txt"}


def test_tools_call_unknown_tool_returns_is_error(mcp):
    resp = mcp.request("tools/call", {"name": "no_such_tool", "arguments": {}})
    result = resp["result"]
    assert result["isError"] is True
    payload = json.loads(result["content"][0]["text"])
    assert payload["ok"] is False
    assert "unknown tool" in payload["error"]


def test_tools_call_denied_tool_returns_is_error(mcp):
    resp = mcp.request("tools/call", {"name": "run_command",
                                      "arguments": {"argv": ["echo", "hi"]}})
    result = resp["result"]
    assert result["isError"] is True
    payload = json.loads(result["content"][0]["text"])
    assert "needs approval" in payload["error"].lower()


def test_unknown_method_returns_error_minus_32601(mcp):
    resp = mcp.request("bogus/method")
    assert resp["error"]["code"] == -32601
    assert "bogus/method" in resp["error"]["message"]


def test_notification_gets_no_reply(mcp):
    # A notification must not produce a response line: the next line we
    # read after it must be the reply to the ping that follows it.
    mcp.notify("notifications/initialized")
    resp = mcp.request("ping")
    assert resp["result"] == {}


def test_batched_requests(mcp):
    mcp.send([
        {"jsonrpc": "2.0", "id": 101, "method": "ping"},
        {"jsonrpc": "2.0", "id": 102, "method": "tools/list"},
    ])
    resp = mcp._readline()
    assert isinstance(resp, list)
    by_id = {r["id"]: r for r in resp}
    assert by_id[101]["result"] == {}
    assert len(by_id[102]["result"]["tools"]) >= 20
