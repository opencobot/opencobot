"""Local web UI for OpenCobot (Phase 2).

Stdlib ``http.server`` only -- no JavaScript framework, no external
CDN, no new dependency. Binds 127.0.0.1 ONLY; any other host is
refused. Authentication (R-013): API clients send the daemon auth
token from ``<state-dir>/daemon.auth`` (0600) as an ``Authorization:
Bearer`` or ``X-OpenCobot-Auth`` header. A browser signs in once by
POSTing the token to ``/login`` (token in the request body, never in a
URL) and receives a random session id in an HttpOnly, SameSite
``opencobot_session`` cookie (12h, sliding); the daemon token itself
never appears in a URL, a redirect, a form field, browser history or
a log. Requests without a valid session or header token get 401 --
JSON for API paths, a small login form for ``GET /``.

Endpoints:
  GET  /                              status page (HTML, no JS)
  POST /login                         sign in with the daemon token
                                       (body field ``token``) -> session
                                       cookie + redirect to /
  POST /logout                        invalidate the session cookie
  GET  /api/status                    readonly/killed/tools/providers
  GET  /api/tools                     tool registry (name/level/schema)
  GET  /api/approvals                 current approvals
  POST /api/approvals/{id}/approve    create an approval (human in the
                                       UI; never from model output) or
                                       confirm an existing one
  POST /api/approvals/{id}/deny       revoke approval {id}
  GET  /api/audit                     last audit entries (?limit=, cap 200)
  POST /api/readonly                  {"enabled": bool}
  POST /api/kill                      {"killed": bool} (default true)
  GET  /api/providers                 configured gateway providers
  GET  /api/benchmark                 benchmark report for ?provider=
                                       (501 until core.benchmark lands)

Run: ``python -m ui.web --state-dir DIR [--port 8765]``.
The UI shares the daemon's state dir, so read-only/kill/approvals
take effect for the daemon and policyd immediately (same files).
"""

from __future__ import annotations

import argparse
import html
import json
import os
import secrets
import sys
import threading
import time
import urllib.parse
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

DEFAULT_PORT = 8765
ALLOWED_HOSTS = ("127.0.0.1", "localhost")
MAX_AUDIT_LIMIT = 200

# R-013: browser session cookie. HttpOnly so page scripts cannot read
# it, SameSite=Lax so it is not sent on cross-site requests, Path=/
# so it covers the whole UI. No Secure flag -- deliberately, and
# re-checked 2026-11-24 (Phase 2 follow-ups): the UI serves plain HTTP
# on loopback only, and a Secure cookie is stored but NOT sent back
# over plain http://127.0.0.1 by both the stdlib http.cookiejar and
# httpx (login round-trip breaks with 401), so adding Secure would
# break login for every script/API client that keeps cookies in a jar.
# Browsers do treat localhost as a secure context and would accept it,
# but the gain on loopback is nil -- loopback traffic never leaves
# this machine, and a local attacker who could sniff it could already
# read daemon.auth from the state dir. Sessions are persisted in the
# state dir (see SessionStore) and expire after 12h of inactivity
# (sliding).
SESSION_COOKIE = "opencobot_session"
SESSION_MAX_AGE = 12 * 60 * 60

#: Session store file inside the state dir (see SessionStore).
SESSIONS_FILE = "sessions.json"


class BenchmarkUnavailable(Exception):
    """core.benchmark (Phase 2, Worker B) is not installed yet."""


class SessionStore:
    """Server-side web UI sessions, persisted in the state dir.

    Sessions survive a daemon/UI restart: ``{session_id: expiry}`` is
    stored as JSON in ``<state-dir>/sessions.json``, written atomically
    (temp file + ``os.replace``) with 0600 permissions -- the same
    discipline as ``policyd.auth``/``daemon.auth``, because a session
    id is as sensitive as the daemon token. Persisting sessions does
    not widen the trust boundary: anyone who can read the state dir
    already owns the daemon token itself. A single server normally
    owns the file; concurrent writers are last-writer-wins.
    A missing file means no sessions. A corrupt or tampered file is
    ignored (fail closed, start empty) and never crashes the server;
    expired sessions are pruned on load. Expiry is still enforced
    (sliding 12h window) and logout still invalidates.
    """

    def __init__(self, state_dir: str | Path):
        self.path = Path(state_dir) / SESSIONS_FILE
        self._lock = threading.Lock()
        self._sessions: dict[str, float] = self._load()

    def _load(self) -> dict[str, float]:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except OSError:
            return {}
        try:
            data = json.loads(raw)
        except ValueError:
            return {}
        if not isinstance(data, dict):
            return {}
        now = time.time()
        sessions: dict[str, float] = {}
        for session_id, expiry in data.items():
            if (isinstance(session_id, str)
                    and isinstance(expiry, (int, float))
                    and not isinstance(expiry, bool)
                    and expiry > now):
                sessions[session_id] = float(expiry)
        # Tighten the file if it was created with wider permissions.
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        return sessions

    def _save_locked(self) -> None:
        """Write the store atomically (0600); never raise.

        A failed write only loses restart-survival for this process
        lifetime -- the session stays valid in memory -- so the server
        never crashes over a session file write.
        """
        tmp_path = None
        try:
            tmp_path = self.path.with_name(
                f"{SESSIONS_FILE}.tmp-{os.getpid()}-{threading.get_ident()}")
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, json.dumps(self._sessions).encode("utf-8"))
            finally:
                os.close(fd)
            os.replace(tmp_path, self.path)
        except OSError:
            if tmp_path is not None:
                try:
                    tmp_path.unlink(missing_ok=True)
                except OSError:
                    pass

    def mint(self) -> str:
        """Create a session id, valid for SESSION_MAX_AGE, and persist it."""
        session_id = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions[session_id] = time.time() + SESSION_MAX_AGE
            self._save_locked()
        return session_id

    def touch(self, session_id: str) -> bool:
        """True when the session exists and is live.

        A live session gets its expiry refreshed (sliding window) and
        the refresh is persisted. An expired or unknown id returns
        False and is dropped.
        """
        now = time.time()
        with self._lock:
            expiry = self._sessions.get(session_id)
            if expiry is None or expiry <= now:
                if self._sessions.pop(session_id, None) is not None:
                    self._save_locked()
                return False
            self._sessions[session_id] = now + SESSION_MAX_AGE
            self._save_locked()
            return True

    def invalidate(self, session_id: str) -> None:
        """Drop a session (logout); persists the removal."""
        with self._lock:
            if self._sessions.pop(session_id, None) is not None:
                self._save_locked()


def validate_host(host: str) -> str:
    """Refuse anything but a loopback bind. Returns the host or raises."""
    if host not in ALLOWED_HOSTS:
        raise ValueError(
            f"refusing non-localhost bind: {host!r} "
            f"(web UI binds 127.0.0.1 only)"
        )
    return "127.0.0.1" if host == "localhost" else host


def load_auth_token(state_dir: Path) -> str:
    """Read the daemon auth token, generating it once (0600) if missing.

    Uses the daemon's own loader so both processes agree on the token.
    """
    try:
        from core.daemon import _load_auth_token  # type: ignore[import-not-found]

        return _load_auth_token(Path(state_dir))
    except Exception:
        pass
    import os

    auth_path = Path(state_dir) / "daemon.auth"
    try:
        token = auth_path.read_text(encoding="utf-8").strip()
        if token:
            return token
    except FileNotFoundError:
        pass
    token = secrets.token_hex(32)
    auth_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(auth_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return auth_path.read_text(encoding="utf-8").strip()
    try:
        os.write(fd, token.encode("utf-8"))
    finally:
        os.close(fd)
    return token


def _egress_for(config) -> str:
    """Egress label for a provider config (Phase 2 contract defaults)."""
    egress = getattr(config, "egress", None)
    if isinstance(egress, str) and egress:
        return egress
    kind = getattr(config, "kind", "")
    if kind in ("ollama", "openai-compatible", "cli"):
        return "local-only"
    return "cloud-backed"


def _provider_record(config) -> dict:
    return {
        "name": getattr(config, "name", ""),
        "kind": getattr(config, "kind", ""),
        "egress": _egress_for(config),
        "model": getattr(config, "model", ""),
        "base_url": getattr(config, "base_url", "") or "",
        "cli_binary": getattr(config, "cli_binary", None),
    }


class WebUIBackend:
    """State-dir backed operations behind the HTTP endpoints."""

    def __init__(self, state_dir: str | Path):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)

    # -- policy engine (fresh instance per call: reads files live) -----
    def _engine(self):
        from policy.engine import PolicyEngine  # type: ignore[import-not-found]

        return PolicyEngine(self.state_dir)

    def _tool_level(self, tool_name: str) -> int:
        """Registered permission level of a tool (0 when unknown)."""
        for tool in self.tools():
            if tool.get("name") == tool_name:
                try:
                    return int(tool.get("level", 0))
                except (TypeError, ValueError):
                    return 0
        return 0

    def status(self) -> dict:
        # Reachability is a real answer on the live transport, not
        # the mere existence of a socket file: on Windows the daemon
        # serves on a named pipe and daemon.sock never exists, so the
        # old .exists() check always reported "not running" there. A
        # stale socket file with no listener behind it now also
        # correctly reports False on POSIX. (policyd_socket below is
        # still a file check — the same treatment for policyd is a
        # separate step; see the daemon-transport PR notes.)
        from core.daemon import daemon_reachable  # lazy: heavy import

        engine = self._engine()
        tools = self.tools()
        return {
            "ok": True,
            "readonly": bool(engine.is_readonly()),
            "readonly_source": engine.readonly_source(),
            "killed": bool(engine.is_killed()),
            "tools": len(tools),
            "daemon_running": daemon_reachable(self.state_dir),
            "policyd_socket": (self.state_dir / "policyd.sock").exists(),
            "audit_entries": len(self.audit(limit=MAX_AUDIT_LIMIT * 10)),
            "providers": [p["name"] for p in self.providers()],
        }

    def tools(self) -> list[dict]:
        try:
            from core.runtime import Runtime  # type: ignore[import-not-found]

            return Runtime(self.state_dir, None).list_tools()
        except Exception:
            return []

    def approvals(self) -> list[dict]:
        from policy.engine import _read_json  # type: ignore[import-not-found]

        approvals = _read_json(self.state_dir / "approvals.json", [])
        return list(approvals) if isinstance(approvals, list) else []

    def approve(self, token_id: str, tool_name: str, level: int | None = None,
                args: dict | None = None, duration: int = 600) -> str:
        """Approve exactly one call (R-007): (token, tool, level, args)."""
        return str(self._engine().approve(token_id, tool_name, level,
                                          args, duration))

    def revoke_approval(self, approval_id: str) -> bool:
        return bool(self._engine().revoke_approval(approval_id))

    def audit(self, limit: int = 50) -> list[dict]:
        from policy.audit import AuditLog  # type: ignore[import-not-found]

        entries = AuditLog(self.state_dir / "audit.jsonl").read_all()
        return entries[-max(0, limit):]

    def set_readonly(self, enabled: bool) -> bool:
        return bool(self._engine().set_readonly(bool(enabled)))

    def set_killed(self, killed: bool) -> bool:
        engine = self._engine()
        engine.set_kill(bool(killed))
        return bool(engine.is_killed())

    def providers(self) -> list[dict]:
        try:
            from core.model_gateway import Gateway  # type: ignore[import-not-found]

            gateway = Gateway()
        except Exception:
            return []
        return [_provider_record(c) for c in (gateway.configs or [])]

    def benchmark(self, provider_name: str | None = None) -> dict:
        """Run the benchmark against one configured provider.

        Raises BenchmarkUnavailable until core.benchmark exists, and
        ValueError when the named provider is not configured (never
        invents a provider).
        """
        try:
            from core.benchmark import run_benchmark  # type: ignore[import-not-found]
        except ImportError as exc:
            raise BenchmarkUnavailable(
                "benchmark support is not installed yet "
                "(core.benchmark, Phase 2 Worker B)"
            ) from exc
        from core.model_gateway import Gateway  # type: ignore[import-not-found]

        gateway = Gateway()
        configs = {c.name: c for c in (gateway.configs or [])}
        if provider_name is None:
            if not configs:
                raise ValueError("no gateway provider is configured")
            provider_name = next(iter(configs))
        if provider_name not in configs:
            raise ValueError(
                f"provider {provider_name!r} is not configured "
                "(see GET /api/providers)"
            )

        def call(prompt: str) -> str:
            complete = getattr(gateway, "complete", None)
            if callable(complete):
                result = complete("EXECUTOR", prompt, "public")
            else:
                result = gateway.chat(
                    "EXECUTOR", [{"role": "user", "content": prompt}], "public"
                )
            if isinstance(result, dict):
                if result.get("ok") is False:
                    raise RuntimeError(result.get("error") or "gateway call failed")
                return str(result.get("text") or "")
            return str(result or "")

        report = run_benchmark(call, name=provider_name)
        to_json = getattr(report, "to_json", None)
        if callable(to_json):
            data = to_json()
            return data if isinstance(data, dict) else {"report": data}
        return {"report": str(report)}


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------

def _login_form_html() -> str:
    return """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>OpenCobot — sign in</title></head>
<body>
<h1>OpenCobot</h1>
<p>This UI runs on localhost only. Paste the daemon auth token
(<code>daemon.auth</code> in the state dir) to continue.</p>
<form method="post" action="/login">
<label>Token: <input type="password" name="token" size="70"></label>
<input type="submit" value="Sign in">
</form>
</body></html>
"""


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    backend: WebUIBackend  # set by create_server
    auth_token: str  # set by create_server
    session_store: SessionStore  # set by create_server

    # -- plumbing ------------------------------------------------------
    def log_message(self, *args):  # keep test/server output quiet
        pass

    def _send(self, status: int, body: bytes, content_type: str,
              extra_headers: list[tuple[str, str]] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in extra_headers or []:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, status: int, payload: dict,
                   extra_headers: list[tuple[str, str]] | None = None) -> None:
        self._send(status, json.dumps(payload).encode("utf-8"),
                   "application/json", extra_headers)

    def _send_html(self, status: int, body: str,
                   extra_headers: list[tuple[str, str]] | None = None) -> None:
        self._send(status, body.encode("utf-8"), "text/html; charset=utf-8",
                   extra_headers)

    # -- R-013 session auth ---------------------------------------------
    def _new_session(self) -> str:
        """Mint a random session id, valid for SESSION_MAX_AGE."""
        return self.session_store.mint()

    def _session_cookie_header(self, session_id: str) -> tuple[str, str]:
        return ("Set-Cookie",
                f"{SESSION_COOKIE}={session_id}; HttpOnly; SameSite=Lax; "
                f"Path=/; Max-Age={SESSION_MAX_AGE}")

    def _clear_session_cookie_header(self) -> tuple[str, str]:
        return ("Set-Cookie",
                f"{SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")

    def _session_valid(self) -> bool:
        """True when the request carries a live session cookie.

        Expired sessions are dropped; a valid one gets its expiry
        refreshed (sliding 12h window) and the refresh is persisted.
        """
        raw = self.headers.get("Cookie") or ""
        try:
            cookie = SimpleCookie()
            cookie.load(raw)
        except Exception:
            return False
        morsel = cookie.get(SESSION_COOKIE)
        if morsel is None or not morsel.value:
            return False
        return self.session_store.touch(morsel.value)

    def _invalidate_session(self) -> None:
        raw = self.headers.get("Cookie") or ""
        try:
            cookie = SimpleCookie()
            cookie.load(raw)
        except Exception:
            return
        morsel = cookie.get(SESSION_COOKIE)
        if morsel is not None and morsel.value:
            self.session_store.invalidate(morsel.value)

    def _header_token_matches(self) -> bool:
        """True when a Bearer / X-OpenCobot-Auth header carries the token.

        Headers only: the daemon token is never accepted from a URL
        query parameter, a form field on an API call, or any other
        place where it would land in browser history or logs (R-013).
        """
        auth = self.headers.get("Authorization") or ""
        if auth.startswith("Bearer "):
            if secrets.compare_digest(auth[7:].strip(), self.auth_token):
                return True
        header_token = self.headers.get("X-OpenCobot-Auth") or ""
        if header_token:
            if secrets.compare_digest(header_token.strip(), self.auth_token):
                return True
        return False

    def _is_authenticated(self) -> bool:
        return self._session_valid() or self._header_token_matches()

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        if not raw:
            return {}
        content_type = self.headers.get("Content-Type") or ""
        if "application/json" in content_type:
            try:
                parsed = json.loads(raw.decode("utf-8"))
                return parsed if isinstance(parsed, dict) else {}
            except ValueError:
                return {}
        parsed_qs = urllib.parse.parse_qs(raw.decode("utf-8", "replace"))
        return {k: v[0] for k, v in parsed_qs.items() if v}

    def _wants_html(self) -> bool:
        return "text/html" in (self.headers.get("Accept") or "")

    def _after_post(self, payload: dict) -> None:
        """Browser form posts redirect back to /; API clients get JSON.

        The redirect never carries a token: the browser is already
        authenticated by its session cookie (R-013).
        """
        if self._wants_html():
            self.send_response(303)
            self.send_header("Location", "/")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self._send_json(200, payload)

    def _unauthorized(self, query: dict) -> None:
        if self.path.split("?")[0] == "/" and self.command == "GET":
            self._send_html(401, _login_form_html())
        else:
            self._send_json(401, {"ok": False, "error": "unauthorized"})

    # -- routing -------------------------------------------------------
    def do_GET(self):
        split = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(split.query)
        if not self._is_authenticated():
            self._unauthorized(query)
            return
        path = split.path
        try:
            if path == "/":
                self._send_html(200, self._status_page())
            elif path == "/api/status":
                self._send_json(200, self.backend.status())
            elif path == "/api/tools":
                self._send_json(200, {"ok": True, "tools": self.backend.tools()})
            elif path == "/api/approvals":
                self._send_json(200, {"ok": True,
                                      "approvals": self.backend.approvals()})
            elif path == "/api/audit":
                try:
                    limit = int(query.get("limit", ["50"])[0])
                except ValueError:
                    limit = 50
                limit = max(1, min(MAX_AUDIT_LIMIT, limit))
                self._send_json(200, {"ok": True,
                                      "entries": self.backend.audit(limit)})
            elif path == "/api/providers":
                self._send_json(200, {"ok": True,
                                      "providers": self.backend.providers()})
            elif path == "/api/benchmark":
                provider = query.get("provider", [None])[0]
                try:
                    report = self.backend.benchmark(provider)
                except BenchmarkUnavailable as exc:
                    self._send_json(501, {"ok": False, "error": str(exc)})
                    return
                except ValueError as exc:
                    self._send_json(404, {"ok": False, "error": str(exc)})
                    return
                self._send_json(200, {"ok": True, **report})
            else:
                self._send_json(404, {"ok": False, "error": "not found"})
        except Exception as exc:
            self._send_json(500, {"ok": False, "error": f"handler error: {exc}"})

    def do_POST(self):
        split = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(split.query)
        body = self._read_body()
        path = split.path
        # -- sign-in / sign-out (R-013) ---------------------------------
        if path == "/login":
            # The only place a token in a request body is accepted: a
            # single login exchange that mints a session cookie. The
            # token is compared in constant time and never echoed back
            # or put in a URL.
            supplied = body.get("token")
            if isinstance(supplied, str) and supplied and secrets.compare_digest(
                supplied, self.auth_token
            ):
                session_id = self._new_session()
                if self._wants_html():
                    self.send_response(303)
                    self.send_header("Location", "/")
                    self.send_header(
                        *self._session_cookie_header(session_id))
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                else:
                    self._send_json(
                        200, {"ok": True},
                        [self._session_cookie_header(session_id)])
            else:
                self._unauthorized(query)
            return
        if path == "/logout":
            if not self._is_authenticated():
                self._unauthorized(query)
                return
            self._invalidate_session()
            if self._wants_html():
                self.send_response(303)
                self.send_header("Location", "/")
                self.send_header(*self._clear_session_cookie_header())
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self._send_json(
                    200, {"ok": True},
                    [self._clear_session_cookie_header()])
            return
        # -- everything else needs a session cookie or header token ----
        if not self._is_authenticated():
            self._unauthorized(query)
            return
        try:
            if path == "/api/readonly":
                raw = body.get("enabled", body.get("readonly"))
                if isinstance(raw, str):
                    raw = raw.strip().lower() in ("1", "true", "yes", "on")
                if not isinstance(raw, bool):
                    self._send_json(400, {"ok": False,
                                          "error": "POST /api/readonly needs enabled: true/false"})
                    return
                value = self.backend.set_readonly(raw)
                self._after_post({"ok": True, "readonly": value})
            elif path == "/api/kill":
                raw = body.get("killed", True)
                if isinstance(raw, str):
                    raw = raw.strip().lower() in ("1", "true", "yes", "on")
                killed = self.backend.set_killed(bool(raw))
                self._after_post({"ok": True, "killed": killed})
            elif path.startswith("/api/approvals/"):
                parts = [p for p in path.split("/") if p]
                # /api/approvals/{id}/approve|deny
                if len(parts) != 4 or parts[3] not in ("approve", "deny"):
                    self._send_json(404, {"ok": False, "error": "not found"})
                    return
                approval_id, action = parts[2], parts[3]
                if action == "deny":
                    if self.backend.revoke_approval(approval_id):
                        self._after_post({"ok": True, "revoked": approval_id})
                    else:
                        self._send_json(404, {"ok": False,
                                              "error": f"unknown approval: {approval_id}"})
                    return
                # approve: create from the body, or confirm an existing id.
                # R-007: the approval is bound to the exact level and
                # exact arguments in the body (level defaults to the
                # tool's registered level, args default to {}).
                token_id = body.get("token_id")
                tool_name = body.get("tool_name")
                if isinstance(token_id, str) and token_id and isinstance(tool_name, str) and tool_name:
                    try:
                        duration = int(body.get("duration_seconds", 600))
                    except (TypeError, ValueError):
                        duration = 600
                    raw_args = body.get("args")
                    args: dict = {}
                    if isinstance(raw_args, dict):
                        args = raw_args
                    elif isinstance(raw_args, str) and raw_args.strip():
                        try:
                            parsed = json.loads(raw_args)
                            args = parsed if isinstance(parsed, dict) else {}
                        except ValueError:
                            args = {}
                    level = body.get("level")
                    if level is None:
                        level = self.backend._tool_level(tool_name)
                    else:
                        try:
                            level = int(level)
                        except (TypeError, ValueError):
                            level = self.backend._tool_level(tool_name)
                    new_id = self.backend.approve(token_id, tool_name, level,
                                                  args, duration)
                    self._after_post({"ok": True, "approval_id": new_id,
                                      "token_id": token_id, "tool_name": tool_name,
                                      "level": level})
                elif any(a.get("id") == approval_id for a in self.backend.approvals()):
                    self._after_post({"ok": True, "approval_id": approval_id,
                                      "note": "approval already exists"})
                else:
                    self._send_json(400, {"ok": False,
                                          "error": "approve needs token_id and tool_name in the body, "
                                                   "or an existing approval id in the path"})
            else:
                self._send_json(404, {"ok": False, "error": "not found"})
        except Exception as exc:
            self._send_json(500, {"ok": False, "error": f"handler error: {exc}"})

    # -- status page ---------------------------------------------------
    def _status_page(self) -> str:
        status = self.backend.status()
        approvals = self.backend.approvals()
        entries = self.backend.audit(limit=10)
        tools = self.backend.tools()
        providers = self.backend.providers()
        esc = html.escape
        rows = "".join(
            f"<tr><td>{esc(str(e.get('seq', '')))}</td>"
            f"<td>{esc(str(e.get('ts', '')))}</td>"
            f"<td>{esc(str(e.get('type', '')))}</td>"
            f"<td>{esc(str(e.get('tool', '')))}</td>"
            f"<td>{esc(str(e.get('reason', e.get('readonly', ''))))}</td></tr>"
            for e in entries
        )
        approval_rows = "".join(
            f"<tr><td>{esc(str(a.get('id', '')))}</td>"
            f"<td>{esc(str(a.get('tool_name', '')))}</td>"
            f"<td>{esc(str(a.get('token_id', '')))}</td>"
            f"<td>L{esc(str(a.get('level', '')))} "
            f"{esc(str(a.get('arg_hash', ''))[:12])}</td>"
            f"<td><form method=\"post\" action=\"/api/approvals/{esc(str(a.get('id', '')))}/deny\">"
            "<input type=\"submit\" value=\"Deny / revoke\"></form></td></tr>"
            for a in approvals
        ) or "<tr><td colspan=\"4\">(no approvals)</td></tr>"
        tool_rows = "".join(
            f"<tr><td>{esc(t['name'])}</td><td>L{esc(str(t['level']))}</td>"
            f"<td>{esc(t.get('description', ''))}</td></tr>"
            for t in tools
        )
        provider_rows = "".join(
            f"<tr><td>{esc(p['name'])}</td><td>{esc(p['kind'])}</td>"
            f"<td>{esc(p['egress'])}</td><td>{esc(p['model'])}</td></tr>"
            for p in providers
        ) or "<tr><td colspan=\"4\">(no providers configured)</td></tr>"
        readonly = status["readonly"]
        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>OpenCobot — status</title></head>
<body>
<h1>OpenCobot — local status</h1>
<p>Read-only mode: <strong>{'ON' if readonly else 'OFF'}</strong>
(source: {esc(status['readonly_source'])}) &middot;
Kill switch: <strong>{'ON' if status['killed'] else 'OFF'}</strong> &middot;
Daemon: {'running' if status['daemon_running'] else 'not running'} &middot;
Tools: {status['tools']} &middot; Audit entries: {status['audit_entries']}</p>
<h2>Read-only</h2>
<form method="post" action="/api/readonly">
<input type="hidden" name="enabled" value="{'false' if readonly else 'true'}">
<input type="submit" value="Turn read-only {'OFF' if readonly else 'ON'}">
</form>
<h2>Kill switch</h2>
<form method="post" action="/api/kill">
<input type="hidden" name="killed" value="{'false' if status['killed'] else 'true'}">
<input type="submit" value="Turn kill switch {'OFF' if status['killed'] else 'ON'}">
</form>
<h2>Approve a tool</h2>
<form method="post" action="/api/approvals/new/approve">
<label>Token id: <input name="token_id" size="40"></label>
<label>Tool: <input name="tool_name" size="20"></label>
<label>Level: <input name="level" size="3"></label>
<label>Args (JSON): <input name="args" size="40" value="{{}}"></label>
<input type="submit" value="Approve">
</form>
<h2>Approvals</h2>
<table border="1"><tr><th>id</th><th>tool</th><th>token</th><th>level / arg hash</th><th></th></tr>
{approval_rows}</table>
<h2>Providers</h2>
<table border="1"><tr><th>name</th><th>kind</th><th>egress</th><th>model</th></tr>
{provider_rows}</table>
<h2>Tools</h2>
<table border="1"><tr><th>name</th><th>level</th><th>description</th></tr>
{tool_rows}</table>
<h2>Recent audit</h2>
<table border="1"><tr><th>seq</th><th>time</th><th>type</th><th>tool</th><th>reason</th></tr>
{rows}</table>
<p><a href="/api/status">/api/status</a> &middot;
<a href="/api/tools">/api/tools</a> &middot;
<a href="/api/approvals">/api/approvals</a> &middot;
<a href="/api/audit">/api/audit</a> &middot;
<a href="/api/providers">/api/providers</a> &middot;
<a href="/api/benchmark">/api/benchmark</a></p>
<form method="post" action="/logout">
<input type="submit" value="Sign out">
</form>
</body></html>
"""


def create_server(
    state_dir: str | Path,
    host: str = "127.0.0.1",
    port: int = 0,
) -> ThreadingHTTPServer:
    """Build (but do not start) the web UI server.

    Raises ValueError for a non-localhost host. ``port=0`` picks an
    ephemeral port (useful for tests); the real port is then
    ``server.server_address[1]``.
    """
    host = validate_host(host)
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    token = load_auth_token(state_dir)

    class Handler(_Handler):
        pass

    Handler.backend = WebUIBackend(state_dir)
    Handler.auth_token = token
    Handler.session_store = SessionStore(state_dir)
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server


def start_server_in_thread(
    state_dir: str | Path, host: str = "127.0.0.1", port: int = 0
) -> ThreadingHTTPServer:
    """Start the web UI on a background thread; call ``shutdown()`` to stop."""
    server = create_server(state_dir, host=host, port=port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OpenCobot local web UI")
    parser.add_argument("--state-dir", default=None,
                        help="state directory (default: $OPENCOBOT_STATE or ~/.opencobot)")
    parser.add_argument("--host", default="127.0.0.1",
                        help="bind host; only 127.0.0.1/localhost are allowed")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"port (default {DEFAULT_PORT})")
    args = parser.parse_args(argv)
    try:
        host = validate_host(args.host)
    except ValueError as exc:
        print(f"opencobot web: error: {exc}", file=sys.stderr)
        return 2
    from core.memory import default_state_dir

    state_dir = Path(args.state_dir).expanduser() if args.state_dir else default_state_dir()
    server = create_server(state_dir, host=host, port=args.port)
    actual_port = server.server_address[1]
    print(f"OpenCobot web UI on http://127.0.0.1:{actual_port}/ "
          f"(localhost only; auth token in {state_dir / 'daemon.auth'})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
