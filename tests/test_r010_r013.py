"""Tests for the Phase 2 risk fixes R-010 - R-013 (branch
agent/wf-risks-010-013).

R-010: CLI providers run with a scrubbed environment (allowlist only).
R-011: CLI stderr is redacted before it can reach errors/logs.
R-012: CLI binaries resolve from pinned dirs, never the ambient PATH.
R-013: web UI auth is a session cookie, never a ?token= URL.

Fake executable scripts stand in for the model CLIs; the web UI
tests drive the real server on an ephemeral localhost port.
"""

from __future__ import annotations

import http.client
import json
import os
import sys
import urllib.parse
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from core.cli_providers import (  # noqa: E402
    CLI_ENV_ALLOWLIST,
    DEFAULT_CLI_BIN_DIRS,
    CliProviderError,
    _pinned_bin_dirs,
    _resolve_binary,
    redact_secrets,
    run_cli_provider,
)
from core.model_gateway import Gateway, ProviderConfig  # noqa: E402
from ui.web import load_auth_token, start_server_in_thread  # noqa: E402


def write_script(bin_dir: Path, name: str, body: str) -> Path:
    path = bin_dir / name
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(0o755)
    return path


@pytest.fixture
def bin_dir(tmp_path, monkeypatch):
    d = tmp_path / "bin"
    d.mkdir()
    monkeypatch.setenv("OPENCOBOT_CLI_BIN_DIRS", str(d))
    return d


def cli_config(name="opencode", **overrides):
    fields = {
        "name": name,
        "kind": "cli",
        "base_url": "",
        "model": name,
        "cli_binary": name,
        "cli_argv_template": ["{prompt}"],
        "cli_prompt_via": "arg",
        "cli_output": "stdout",
    }
    fields.update(overrides)
    return ProviderConfig(**fields)


# ---------------------------------------------------------------- R-010

def test_r010_ambient_secrets_not_inherited(bin_dir, monkeypatch):
    # The script dumps its whole environment; ambient credentials
    # must not be among them even though they are set in this process.
    write_script(bin_dir, "opencode", "env\n")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-ambient-secret-123")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI-ambient")
    monkeypatch.setenv("MY_SERVICE_TOKEN", "tok-ambient-456")
    monkeypatch.setenv("GH_TOKEN", "ghp_ambient789")
    out = run_cli_provider(cli_config(), "hi")
    for leaked in ("sk-ambient-secret-123", "wJalrXUtnFEMI-ambient",
                   "tok-ambient-456", "ghp_ambient789"):
        assert leaked not in out


def test_r010_allowlisted_vars_pass_through(bin_dir, monkeypatch):
    write_script(bin_dir, "opencode", 'printf "home:%s\\n" "$HOME"\n')
    monkeypatch.setenv("HOME", "/tmp/fake-home-r010")
    out = run_cli_provider(cli_config(), "hi")
    assert out == "home:/tmp/fake-home-r010"


def test_r010_child_path_excludes_ambient_path(bin_dir, monkeypatch, tmp_path):
    evil = tmp_path / "evil"
    evil.mkdir()
    write_script(bin_dir, "opencode", 'printf "path:%s\\n" "$PATH"\n')
    monkeypatch.setenv("PATH", str(evil) + os.pathsep + "/tmp/also-evil")
    out = run_cli_provider(cli_config(), "hi")
    child_path = out.removeprefix("path:")
    assert str(evil) not in child_path
    assert "/tmp/also-evil" not in child_path
    # Pinned dirs first, then the default system dirs (standard tools).
    assert child_path.split(os.pathsep)[0] == str(bin_dir)
    assert "/usr/bin" in child_path.split(os.pathsep)


def test_r010_explicit_env_override_passes_through(bin_dir):
    # An operator-supplied per-call env var (explicit opt-in) still
    # reaches the child; only *ambient* credentials are scrubbed.
    write_script(bin_dir, "opencode", 'printf "var:%s\\n" "$MY_CLI_FLAG"\n')
    out = run_cli_provider(cli_config(), "hi",
                           env={"MY_CLI_FLAG": "operator-set"})
    assert out == "var:operator-set"


def test_r010_allowlist_has_no_secret_names():
    secretish = {"API_KEY", "TOKEN", "SECRET", "PASSWORD", "AWS_SECRET"}
    assert not (set(CLI_ENV_ALLOWLIST) & secretish)
    assert "PATH" in CLI_ENV_ALLOWLIST and "HOME" in CLI_ENV_ALLOWLIST


# ---------------------------------------------------------------- R-011

@pytest.mark.parametrize("raw,expected", [
    ("boom api_key=sk-abc123def456", "boom api_key=[REDACTED]"),
    ('token: "ghp_abcdefghij1234567890"',
     'token: "[REDACTED]"'),
    ("Authorization: Bearer abcDEF123456789",
     "Authorization: Bearer [REDACTED]"),
    ("password=hunter2 failed", "password=[REDACTED] failed"),
    ("AWS key AKIAIOSFODNN7EXAMPLE leaked",
     "AWS key [REDACTED] leaked"),
    ("plain boom stderr, nothing secret", "plain boom stderr, nothing secret"),
    ("", ""),
])
def test_r011_redact_secrets(raw, expected):
    assert redact_secrets(raw) == expected


def test_r011_hostile_stderr_redacted_in_error(bin_dir):
    write_script(
        bin_dir, "opencode",
        'echo "login failed: api_key=sk-live-secret-999 and token abc" >&2\n'
        'echo "Bearer tok-xyz-123456789" >&2\n'
        "exit 3\n",
    )
    with pytest.raises(CliProviderError) as excinfo:
        run_cli_provider(cli_config(), "hi")
    message = str(excinfo.value)
    assert "exited with code 3" in message
    assert "sk-live-secret-999" not in message
    assert "tok-xyz-123456789" not in message
    assert "[REDACTED]" in message


# ---------------------------------------------------------------- R-012

def test_r012_path_spoofing_ignored(tmp_path, monkeypatch):
    # A fake `opencode` planted earlier on PATH must NOT win: bare
    # names resolve only against the pinned dirs.
    spoof = tmp_path / "spoof"
    spoof.mkdir()
    write_script(spoof, "opencode", 'printf "SPOOFED\\n"\n')
    monkeypatch.delenv("OPENCOBOT_CLI_BIN_DIRS", raising=False)
    monkeypatch.setenv("PATH", str(spoof) + os.pathsep + os.environ.get("PATH", ""))
    with pytest.raises(CliProviderError, match="not found in pinned binary dirs"):
        run_cli_provider(cli_config(), "hi")


def test_r012_config_binary_dirs_honored(bin_dir, monkeypatch):
    # Per-provider cli_binary_dirs beats the ambient PATH too.
    write_script(bin_dir, "opencode", 'printf "pinned:%s\\n" "$*"\n')
    monkeypatch.delenv("OPENCOBOT_CLI_BIN_DIRS", raising=False)
    monkeypatch.setenv("PATH", "/nonexistent-dir")
    cfg = cli_config(cli_binary_dirs=(str(bin_dir),))
    assert run_cli_provider(cfg, "hi") == "pinned:hi"


def test_r012_env_var_override_honored(bin_dir, monkeypatch):
    write_script(bin_dir, "opencode", 'printf "envdir:%s\\n" "$*"\n')
    monkeypatch.setenv("OPENCOBOT_CLI_BIN_DIRS", str(bin_dir))
    monkeypatch.setenv("PATH", "/nonexistent-dir")
    assert run_cli_provider(cli_config(), "hi") == "envdir:hi"


def test_r012_pinned_dirs_precedence(bin_dir, tmp_path, monkeypatch):
    # config field > env var > defaults.
    other = tmp_path / "other"
    other.mkdir()
    assert _pinned_bin_dirs((str(bin_dir),)) == (str(bin_dir),)
    monkeypatch.setenv("OPENCOBOT_CLI_BIN_DIRS",
                       str(other) + os.pathsep + str(bin_dir))
    assert _pinned_bin_dirs() == (str(other), str(bin_dir))
    monkeypatch.delenv("OPENCOBOT_CLI_BIN_DIRS")
    assert _pinned_bin_dirs() == DEFAULT_CLI_BIN_DIRS


def test_r012_resolve_rejects_unpinned_absolute_path(bin_dir):
    # _resolve_binary still enforces the allowlist for paths.
    script = write_script(bin_dir, "not-allowed", "echo hi\n")
    with pytest.raises(CliProviderError, match="not in the allowlist"):
        _resolve_binary(str(script))


def test_r012_gateway_ping_uses_pinned_dirs(bin_dir, monkeypatch):
    cfg = cli_config()
    write_script(bin_dir, "opencode", "echo hi\n")
    gateway = Gateway(configs=[cfg])
    assert gateway.ping(cfg) is True
    # Spoof on PATH alone does not make the provider "available".
    monkeypatch.delenv("OPENCOBOT_CLI_BIN_DIRS", raising=False)
    assert gateway.ping(cfg) is False


# ---------------------------------------------------------------- R-013

@pytest.fixture()
def server(tmp_path):
    state_dir = tmp_path / "state"
    srv = start_server_in_thread(state_dir, port=0)
    token = load_auth_token(state_dir)
    yield {"server": srv, "state_dir": state_dir, "token": token,
           "port": srv.server_address[1]}
    srv.shutdown()
    srv.server_close()


def raw_request(port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read().decode("utf-8")
    result = (resp.status, dict(resp.getheaders()), data)
    conn.close()
    return result


def login(server, token=None):
    """POST /login with the daemon token; return (status, headers, body)."""
    body = urllib.parse.urlencode(
        {"token": token if token is not None else server["token"]})
    return raw_request(
        server["port"], "POST", "/login", body=body,
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json"})


def session_cookie(headers):
    set_cookie = headers.get("Set-Cookie", "")
    return set_cookie.split(";", 1)[0] if set_cookie else ""


def test_r013_login_sets_httponly_session_cookie(server):
    status, headers, _ = login(server)
    assert status == 200
    set_cookie = headers.get("Set-Cookie", "")
    assert set_cookie.startswith("opencobot_session=")
    assert "HttpOnly" in set_cookie
    assert "SameSite=Lax" in set_cookie
    assert "Path=/" in set_cookie
    # The daemon token itself never appears in the response.
    assert server["token"] not in set_cookie
    assert server["token"] not in json.dumps(headers)


def test_r013_login_redirect_has_no_token_in_location(server):
    body = urllib.parse.urlencode({"token": server["token"]})
    status, headers, _ = raw_request(
        server["port"], "POST", "/login", body=body,
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "text/html"})
    assert status == 303
    assert headers.get("Location") == "/"
    assert server["token"] not in headers.get("Location", "")
    assert "Set-Cookie" in headers


def test_r013_session_cookie_authenticates(server):
    _, headers, _ = login(server)
    cookie = session_cookie(headers)
    assert cookie
    status, _, body = raw_request(
        server["port"], "GET", "/api/status",
        headers={"Cookie": cookie})
    assert status == 200
    assert json.loads(body)["ok"] is True
    # The status page works with the cookie and contains no token.
    status, _, body = raw_request(
        server["port"], "GET", "/",
        headers={"Cookie": cookie, "Accept": "text/html"})
    assert status == 200
    assert "OpenCobot" in body
    assert server["token"] not in body
    assert "?token=" not in body


def test_r013_wrong_token_login_rejected(server):
    status, headers, _ = login(server, token="wrong-token")
    assert status == 401
    assert "Set-Cookie" not in headers


def test_r013_query_token_rejected_everywhere(server):
    for path in ("/api/status", "/"):
        status, _, _ = raw_request(
            server["port"], "GET", f"{path}?token={server['token']}")
        assert status == 401


def test_r013_token_in_api_post_body_rejected(server):
    body = json.dumps({"token": server["token"], "enabled": True})
    status, _, _ = raw_request(
        server["port"], "POST", "/api/readonly", body=body,
        headers={"Content-Type": "application/json"})
    assert status == 401


def test_r013_logout_invalidates_session(server):
    _, headers, _ = login(server)
    cookie = session_cookie(headers)
    assert cookie
    status, out_headers, _ = raw_request(
        server["port"], "POST", "/logout",
        headers={"Cookie": cookie, "Accept": "application/json"})
    assert status == 200
    assert "Max-Age=0" in out_headers.get("Set-Cookie", "")
    # The old session no longer authenticates.
    status, _, _ = raw_request(
        server["port"], "GET", "/api/status",
        headers={"Cookie": cookie})
    assert status == 401


def test_r013_forged_session_cookie_rejected(server):
    status, _, _ = raw_request(
        server["port"], "GET", "/api/status",
        headers={"Cookie": "opencobot_session=forged-session-id"})
    assert status == 401
