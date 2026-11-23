"""Tests for the Phase 2 web UI (ui/web.py) and `opencobot ui` CLI.

Starts the real server on an ephemeral localhost port and fetches it
with urllib. No network beyond loopback, no framework, no CDN.
"""

import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policy.engine import PolicyEngine  # noqa: E402
from ui.web import (  # noqa: E402
    create_server,
    load_auth_token,
    start_server_in_thread,
    validate_host,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI = [sys.executable, "-m", "cli.opencobot_cli"]


@pytest.fixture()
def server(tmp_path):
    state_dir = tmp_path / "state"
    srv = start_server_in_thread(state_dir, port=0)
    token = load_auth_token(state_dir)
    yield {"server": srv, "state_dir": state_dir, "token": token,
           "port": srv.server_address[1]}
    srv.shutdown()
    srv.server_close()


def fetch(port, path, method="GET", data=None, token="ok", headers=None,
          raw_headers=None):
    hdrs = dict(headers or {})
    if raw_headers is None:
        if token == "ok":
            hdrs["Authorization"] = "Bearer PLACEHOLDER"
        elif token == "bad":
            hdrs["Authorization"] = "Bearer wrong-token"
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                                 data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


def fetch_auth(server, path, **kwargs):
    """fetch() with the real token substituted in."""
    token = kwargs.pop("token", "ok")
    if token == "ok":
        kwargs.setdefault("headers", {})
        kwargs["headers"]["Authorization"] = f"Bearer {server['token']}"
        return fetch(server["port"], path, token=None, **kwargs)
    return fetch(server["port"], path, token=token, **kwargs)


# -- auth -----------------------------------------------------------------

def test_missing_token_rejected(server):
    status, body = fetch(server["port"], "/api/status", token=None)
    assert status == 401
    assert json.loads(body)["error"] == "unauthorized"


def test_wrong_token_rejected(server):
    status, _ = fetch(server["port"], "/api/status", token="bad")
    assert status == 401


def test_token_in_query_param_accepted(server):
    status, body = fetch(server["port"],
                         f"/api/status?token={server['token']}", token=None)
    assert status == 200
    assert json.loads(body)["ok"] is True


def test_unauthenticated_root_serves_login_form(server):
    status, body = fetch(server["port"], "/", token=None)
    assert status == 401
    assert "daemon auth token" in body
    assert "<form" in body


# -- status page + endpoints ----------------------------------------------

def test_status_page_and_api_status(server):
    status, body = fetch_auth(server, "/")
    assert status == 200
    assert "OpenCobot" in body and "Read-only" in body
    assert "cdn" not in body.lower() and "<script" not in body.lower()
    status, body = fetch_auth(server, "/api/status")
    assert status == 200
    payload = json.loads(body)
    assert payload["readonly"] is False
    assert payload["killed"] is False
    assert payload["tools"] >= 20
    assert payload["providers"] == ["ollama-local", "openai-compatible"]


def test_tools_and_providers(server):
    _, body = fetch_auth(server, "/api/tools")
    payload = json.loads(body)
    assert payload["ok"] is True
    names = {t["name"] for t in payload["tools"]}
    assert {"list_dir", "read_file", "run_command"} <= names
    _, body = fetch_auth(server, "/api/providers")
    providers = json.loads(body)["providers"]
    assert [p["name"] for p in providers] == ["ollama-local", "openai-compatible"]
    assert all(p["egress"] == "local-only" for p in providers)
    assert all(p["kind"] and p["model"] for p in providers)


def test_benchmark_endpoint_returns_report(server):
    # core.benchmark landed with the benchmark slice, so the endpoint
    # now runs a real report (against the first configured provider,
    # ollama-local, which is not running here — score 0, still a report).
    status, body = fetch_auth(server, "/api/benchmark")
    assert status == 200
    payload = json.loads(body)
    assert payload["ok"] is True
    assert "ollama-local" in payload["report"]
    assert "profile" in payload["report"]


def test_unknown_path_404(server):
    status, body = fetch_auth(server, "/api/nope")
    assert status == 404


# -- readonly + kill through the UI -----------------------------------------

def test_readonly_toggle_through_ui(server):
    engine = PolicyEngine(server["state_dir"])
    assert engine.is_readonly() is False
    status, body = fetch_auth(server, "/api/readonly", method="POST",
                              data={"enabled": True})
    assert status == 200
    assert json.loads(body) == {"ok": True, "readonly": True}
    assert PolicyEngine(server["state_dir"]).is_readonly() is True
    _, body = fetch_auth(server, "/api/status")
    assert json.loads(body)["readonly"] is True
    status, body = fetch_auth(server, "/api/readonly", method="POST",
                              data={"enabled": False})
    assert json.loads(body) == {"ok": True, "readonly": False}


def test_readonly_post_needs_boolean(server):
    status, body = fetch_auth(server, "/api/readonly", method="POST", data={})
    assert status == 400


def test_kill_through_ui(server):
    engine = PolicyEngine(server["state_dir"])
    status, body = fetch_auth(server, "/api/kill", method="POST",
                              data={"killed": True})
    assert status == 200
    assert json.loads(body) == {"ok": True, "killed": True}
    assert engine.is_killed() is True
    _, body = fetch_auth(server, "/api/status")
    assert json.loads(body)["killed"] is True
    fetch_auth(server, "/api/kill", method="POST", data={"killed": False})
    assert PolicyEngine(server["state_dir"]).is_killed() is False


# -- approvals + audit -------------------------------------------------------

def test_approvals_list_approve_deny(server):
    engine = PolicyEngine(server["state_dir"])
    approval_id = engine.approve("tok-1", "run_command", 600)
    _, body = fetch_auth(server, "/api/approvals")
    approvals = json.loads(body)["approvals"]
    assert any(a["id"] == approval_id and a["tool_name"] == "run_command"
               for a in approvals)
    # Deny (revoke) through the UI.
    status, body = fetch_auth(server, f"/api/approvals/{approval_id}/deny",
                              method="POST", data={})
    assert status == 200
    assert json.loads(body) == {"ok": True, "revoked": approval_id}
    assert engine.has_approval("tok-1", "run_command") is False
    # Denying an unknown id is a 404.
    status, _ = fetch_auth(server, "/api/approvals/nope/deny",
                           method="POST", data={})
    assert status == 404
    # Approve through the UI creates a real approval (human in the UI).
    status, body = fetch_auth(server, "/api/approvals/new/approve",
                              method="POST",
                              data={"token_id": "tok-2", "tool_name": "read_file"})
    assert status == 200
    new_id = json.loads(body)["approval_id"]
    assert engine.has_approval("tok-2", "read_file") is True
    # Approving with no body and an unknown id is a 400.
    status, _ = fetch_auth(server, "/api/approvals/nope/approve",
                           method="POST", data={})
    assert status == 400
    engine.revoke_approval(new_id)


def test_audit_endpoint_shows_actions(server):
    fetch_auth(server, "/api/readonly", method="POST", data={"enabled": True})
    fetch_auth(server, "/api/readonly", method="POST", data={"enabled": False})
    _, body = fetch_auth(server, "/api/audit")
    entries = json.loads(body)["entries"]
    assert any(e.get("type") == "readonly_changed" and e.get("readonly") is True
               for e in entries)
    _, body = fetch_auth(server, "/api/audit?limit=1")
    assert len(json.loads(body)["entries"]) == 1


# -- localhost-only binding ---------------------------------------------------

@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.1", "", "example.com"])
def test_non_localhost_bind_refused(host):
    with pytest.raises(ValueError, match="non-localhost"):
        validate_host(host)
    with pytest.raises(ValueError, match="non-localhost"):
        create_server(Path("/tmp/does-not-matter-opencobot"), host=host, port=0)


def test_localhost_alias_accepted(tmp_path):
    srv = create_server(tmp_path / "state", host="localhost", port=0)
    assert srv.server_address[0] == "127.0.0.1"
    srv.server_close()


# -- `opencobot ui` CLI ---------------------------------------------------------

def _free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@pytest.fixture()
def ui_state(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    yield state
    pid_path = state / "ui.pid"
    if pid_path.exists():
        try:
            pid = int(pid_path.read_text().strip())
            os.kill(pid, signal.SIGTERM)
        except (ValueError, ProcessLookupError, PermissionError):
            pass


def run_cli(state_dir, *args):
    return subprocess.run(
        CLI + ["--state-dir", str(state_dir), *args],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=60)


def test_cli_ui_start_status_stop(ui_state):
    port = _free_port()
    proc = run_cli(ui_state, "ui", "start", "--port", str(port))
    assert proc.returncode == 0, proc.stderr
    assert f"http://127.0.0.1:{port}/" in proc.stdout
    assert "daemon.auth" in proc.stdout
    token = load_auth_token(ui_state)
    assert token not in proc.stdout  # the auth secret is never printed
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/status",
        headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert json.loads(resp.read())["ok"] is True
    proc = run_cli(ui_state, "ui", "status")
    assert proc.returncode == 0
    assert "running" in proc.stdout
    proc = run_cli(ui_state, "ui", "stop")
    assert proc.returncode == 0
    proc = run_cli(ui_state, "ui", "status")
    assert proc.returncode == 1
    assert "not running" in proc.stdout


def test_cli_ui_refuses_non_localhost(ui_state):
    proc = run_cli(ui_state, "ui", "start", "--host", "0.0.0.0",
                   "--port", str(_free_port()))
    assert proc.returncode == 2
    assert "non-localhost" in proc.stderr


def test_cli_web_alias_status(ui_state):
    proc = run_cli(ui_state, "web", "status")
    assert proc.returncode == 1
    assert "not running" in proc.stdout


def test_cli_gateway_providers_and_benchmark_errors(ui_state):
    proc = run_cli(ui_state, "gateway", "providers")
    assert proc.returncode == 0
    assert "ollama-local" in proc.stdout
    assert "openai-compatible" in proc.stdout
    proc = run_cli(ui_state, "gateway", "providers", "--json")
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["count"] == 2
    assert payload["providers"][0]["name"] == "ollama-local"
    proc = run_cli(ui_state, "benchmark", "--provider", "no-such-provider")
    assert proc.returncode != 0
    assert "not configured" in proc.stderr
    # core.benchmark landed with the benchmark slice, so benchmarking a
    # configured provider now runs a real report (ollama-local is not
    # running here, so the score is 0 — still a successful run, exit 0).
    proc = run_cli(ui_state, "benchmark", "--provider", "ollama-local")
    assert proc.returncode == 0
    assert "Benchmark report: ollama-local" in proc.stdout
    assert "Total score:" in proc.stdout
    assert "Recommended profile:" in proc.stdout
