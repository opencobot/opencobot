# Web UI (Phase 2)

Local-only status and control page for OpenCobot. Stdlib
`http.server` only — no JavaScript framework, no external CDN, no new
dependency. (The Tauri + React desktop app is deferred; this page is
the interim UI.)

## Start / stop

```sh
opencobot ui start [--port 8765]   # or: opencobot web start
opencobot ui status
opencobot ui stop
```

The server binds **127.0.0.1 only** — any other `--host` is refused.
It shares the daemon's state dir, so read-only mode, the kill switch
and approvals changed here take effect for the daemon and policyd
immediately (same files, no restart needed).

## Authentication

API clients send the daemon auth token from `<state-dir>/daemon.auth`
(0600) as an `Authorization: Bearer` header or an `X-OpenCobot-Auth`
header. A browser signs in once by POSTing the token to `/login` and
receives a random session id in an HttpOnly, SameSite
`opencobot_session` cookie (12h, sliding); sign out with `POST
/logout`. The daemon token is never printed by the CLI — copy it from
the file — and never appears in a URL, a redirect, a form field,
browser history or a log: `?token=` query-parameter auth was removed
(R-013). Without a valid session or header token, API paths return
401 JSON and `GET /` returns a small login form.

## Endpoints

| Method | Path | What it does |
| ------ | ---- | ------------ |
| GET | `/` | Status page (HTML, no JS): read-only/kill state, providers, tools, approvals, recent audit, with forms for the actions below |
| POST | `/login` | Sign in with the daemon token (body field `token`) — sets the `opencobot_session` cookie, redirects to `/` |
| POST | `/logout` | Invalidate the session cookie, redirects to `/` |
| GET | `/api/status` | `{readonly, readonly_source, killed, tools, daemon_running, policyd_socket, audit_entries, providers}` |
| GET | `/api/tools` | Tool registry (name, level, schema, description) |
| GET | `/api/approvals` | Current approvals |
| POST | `/api/approvals/{id}/approve` | Create an approval from a JSON body `{token_id, tool_name, duration_seconds?}`, or confirm an existing id. Approvals come only from this UI or the CLI — never from model output. |
| POST | `/api/approvals/{id}/deny` | Revoke approval `{id}` (404 when unknown) |
| GET | `/api/audit` | Last audit entries (`?limit=`, default 50, cap 200) |
| POST | `/api/readonly` | `{enabled: bool}` — persistent read-only flag; level 1+ tools are then denied with reason "read-only mode" |
| POST | `/api/kill` | `{killed: bool}` (default true) — engage/release the kill switch |
| GET | `/api/providers` | Configured gateway providers (name, kind, egress, model, base URL) |
| GET | `/api/benchmark` | Benchmark report for `?provider=` — 501 until `core.benchmark` lands (Phase 2, Worker B), 404 for an unconfigured provider |

Browser form posts (Accept: text/html) redirect back to `/` after the
action; API clients get JSON.

## Read-only mode

`opencobot readonly on/off/status` does the same thing from the CLI.
The flag lives in `<state-dir>/readonly.json` (0600) and is read from
disk on every policy check, so it survives daemon/policyd restarts.
`OPENCOBOT_READONLY=1/0` (also `true/false`, `yes/no`, `on/off`)
overrides the persisted flag for the process that reads it; an invalid
value is ignored. Kill switch still wins over read-only.
