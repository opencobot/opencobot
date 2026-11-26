# OpenCobot IDE API — the daemon protocol any IDE client speaks

**Status:** implemented (daemon ops) + reference client (VS Code, thin).
**Scope:** the localhost daemon API that IDE extensions use to drive
OpenCobot. This document is the contract: a JetBrains plugin, a
Neovim client, or any other IDE can implement a client from this
document alone, without reading the VS Code extension's source.

**Design rules (ADR-011 (d))**

1. The daemon is the only execution path. An IDE client NEVER calls
   a model, NEVER writes workspace files itself, and NEVER talks to
   `policyd` directly. It sends requests to the daemon; the daemon
   runs the Gateway / Runtime / Orchestrator, and every tool call
   inside a run is authorized by `policyd` exactly as a direct
   `tool run` would be. The workspace files are the ground truth —
   the extension shows orchestrator status and results, it does not
   become a second source of truth.
2. Localhost only. There is no TCP listener, no remote endpoint, no
   cloud relay. The transport is a Unix socket (Linux/macOS) or a
   named pipe (Windows), both local to the machine.
3. Thin clients. A client is framing + auth + request/response
   mapping. All policy, verification, budgets and memory live in
   the daemon. A client that re-implements any of those is wrong.
4. No new dependency. The reference client is Node's stdlib only
   (`net`, `fs`, `os`, `path`); the protocol itself is JSON over a
   byte stream, so any language can speak it.

## Transport

| Platform | Address |
| --- | --- |
| Linux / macOS | Unix socket `<state-dir>/daemon.sock` |
| Windows | Named pipe `\\.\pipe\opencobot-daemon` |

State dir resolution (same as the daemon): the
`OPENCOBOT_STATE` environment variable, else `~/.opencobot`.
The socket file is mode `0600`, owner-only. If the daemon is not
running there is no socket/pipe to connect to — the client reports
"daemon not running" and does nothing else.

## Framing

JSON-lines: one request is one UTF-8 JSON object terminated by `\n`;
one reply is one UTF-8 JSON object terminated by `\n`. A connection
may carry several request/reply pairs in sequence; the reference
client opens one connection per request and closes it after the
reply. A reply that is not valid JSON, or no reply before the
timeout, is a transport error — the client surfaces it, never
retries silently, and never treats a missing reply as success.

## Auth

Every request carries the daemon token:

```json
{"auth": "<token from <state-dir>/daemon.auth>", "op": "...", ...}
```

The token file is mode `0600`, generated once by the daemon and
reused. A client reads it from disk (same user, same machine) —
never from a URL, never from the user typing it into a chat box, and
never written to the client's own logs or settings files. A wrong
or missing token gets `{"ok": false, "error": "unauthorized"}`.
The token authenticates the *caller to the daemon*; it is NOT the
capability token that authorizes tool calls (see `run_tool` /
`orchestrator_run` below — those take a separate `token` field).

## Replies and errors

Every reply is `{"ok": true, ...}` or `{"ok": false, "error": "<string>"}`.
Known errors: `unauthorized`, `invalid request` (not a JSON object),
`unknown op: <op>`, `policyd unavailable` (the op needs `policyd`
and it is down — fail closed, never fall back to an in-process
policy). For `orchestrator_run` / `orchestrator_retry` the outer
`"ok"` says the op executed; the run outcome is the inner
`"run"."ok"` / `"retry"."ok"` (a run whose subtasks failed still
returns outer `"ok": true` with the failure recorded inside).
Servers ignore unknown request fields; clients must ignore unknown
reply fields (ops are added, never changed incompatibly).

## Ops

### `status`
Request: `{"op": "status"}`.
Reply: `{"ok": true, "tools": <n>, "killed": <bool>,
"policyd_reachable": <bool>, "readonly": <bool>}`.
Read-only; no `policyd` needed for the reply itself.

### `readonly_get` / `readonly_set`
Request: `{"op": "readonly_get"}` / `{"op": "readonly_set",
"enabled": <bool>}`.
Reply: `{"ok": true, "readonly": <bool>}`. `readonly_set` with a
non-boolean `enabled` is an error. The write goes through `policyd`
(R-022); when `policyd` is unreachable the set fails closed.

### `list_tools`
Request: `{"op": "list_tools"}`.
Reply: `{"ok": true, "tools": [...]}` — the tool registry
(name/level/schema), same shape the CLI prints.

### `run_tool`
Request: `{"op": "run_tool", "token": <capability token>,
"tool_name": "<name>", "args": {...}, "tainted": <bool>}`.
`token` is the capability token (same shape the CLI mints: an
object with a `folders` scope); `args` defaults to `{}`;
`tainted` defaults to `false`.
Reply: the `Runtime.run_tool` result —
`{"ok": <bool>, "verified": <bool>, "decision": {"allowed": <bool>,
"reason": "<string>", "needs_approval": <bool>}, "result": {...},
"evidence": "<string>"}`.
When `policyd` is unreachable the reply is the fail-closed refusal
(`allowed: false, reason: "policyd unavailable"`), never an
in-process decision.

### `kill` / `unkill`
Request: `{"op": "kill"}` / `{"op": "unkill"}`.
Reply: `{"ok": true, "killed": <bool>}`. Needs `policyd`
(the kill switch lives there).

### `gateway_status`
Request: `{"op": "gateway_status"}`.
Reply: `{"ok": true, "provider": "<name>"|null,
"model": "<model>"|null, "available": <bool>}`.

### `orchestrator_run`
Request: `{"op": "orchestrator_run", "task": "<string>",
"token": <capability token>, "sensitivity": "public"|"personal"|"secret",
"workspace": "<absolute project root>", "architect": "<provider>"?,
"workers": ["<provider>", ...]?, "project": "<name>"?}`.
Only `task` is required. `sensitivity` defaults to `"public"`;
any other value is an error. `workspace` defaults to the daemon's
working directory — an IDE client SHOULD always send it (the
workspace is the project root the user has open). `architect` /
`workers` override the gateway config; an unknown architect is an
error and no model is called. `project` defaults to the workspace
folder name and keys the run in memory.
Reply: `{"ok": true, "run": <summary>}` where the summary is
`{"ok": <bool>, "run_id": "<12 hex>", "task": "...",
"sensitivity": "...", "integrated": [<titles>], "done": [...],
"failed": [...], "queued": [...], "needs_approval": [...],
"conflict_lost": [...], "error": "<string>"|null,
"subtasks": [{title, provider_hint, sensitivity, status, worker,
dispatch, verdict, ...}]}`.
The summary never contains worker output text (R-026).
**Synchronous:** the daemon runs the whole task before replying —
a run can take minutes (model calls). Use a generous timeout
(the reference client defaults to 10 minutes for this op, 10
seconds for the others) and do NOT retry on timeout: a retry
would start a second run. If the client disconnects, the run
still completes server-side and is recorded in memory — poll
`orchestrator_status` with the `run_id` (once the client has it)
or the project name.
When `policyd` is unreachable the reply is
`{"ok": false, "error": "policyd unavailable"}` and no model is
called.

### `orchestrator_status`
Request: `{"op": "orchestrator_status", "run_id": "<id>"}` or
`{"op": "orchestrator_status", "project": "<name>"}`.
Reply: `{"ok": true, "run": <stored run>}` — the stored record
(`run_id`, `task`, `sensitivity`, `ts`, `summary`, `subtasks`
metadata; no output text). Read-only: needs NO `policyd`, so it
answers even when `policyd` is down. One of `run_id` / `project`
is required; an unknown id or project is an error.

### `orchestrator_retry`
Request: `{"op": "orchestrator_retry", "run_id": "<id>",
"token": <capability token>, "sensitivity": ...?,
"workspace": "...", ...}` — same optional fields as
`orchestrator_run`; `run_id` is required.
Reply: `{"ok": true, "retry": {"ok": <bool>, "run_id": "<id>",
"retried": [<titles>], "still_queued": [<titles>],
"error": "<string>"|null}}`.
Same `policyd` and validation rules as `orchestrator_run`.

## Workspace scoping

- A run is confined to ONE workspace: the `workspace` field
  (absolute path). Integration resolves every output path under
  that root and refuses anything outside it (including `..`
  escapes and absolute paths) — the daemon enforces this, the
  client does not need to.
- The capability `token` scopes the inner tool calls
  (`folders: [<workspace>]`); a token scoped to another folder
  cannot write outside it even if the daemon is asked to.
- Memory keys are `orchestrator:run:<run_id>` (one run) and
  `orchestrator:<project>:last_run` (latest run per project).
  A client reads only the runs for its own project — never a
  full dump (ADR-011 memory rule).
- A client MUST send the workspace the user has open, not a
  guessed or cached path. If the user has no folder open, the
  client must not invent one: refuse, and say the run needs an
  open workspace.

## Worked example

1. `{"auth": "<token>", "op": "status"}`
   → `{"ok": true, "tools": 23, "killed": false,
   "policyd_reachable": true, "readonly": false}`
2. `{"auth": "<token>", "op": "orchestrator_run",
   "task": "Add a --json flag to the status command",
   "token": {"folders": ["/home/ayush/code/opencobot"]},
   "workspace": "/home/ayush/code/opencobot",
   "sensitivity": "public"}`
   → `{"ok": true, "run": {"ok": true, "run_id": "a1b2c3d4e5f6",
   "task": "Add a --json flag to the status command", ...,
   "integrated": ["Add --json flag"], "failed": [], "queued": []}}`
3. `{"auth": "<token>", "op": "orchestrator_status",
   "run_id": "a1b2c3d4e5f6"}`
   → `{"ok": true, "run": {"run_id": "a1b2c3d4e5f6", ...}}`

## What a client must NOT do

- No direct model calls, no Gateway access, no `policyd` socket.
- No file writes, deletes or renames of its own — not even
  "helpful" ones. If a file must change, that is an orchestrator
  run (or a `run_tool` call) and the daemon + `policyd` decide.
- No storing the daemon token anywhere except reading
  `<state-dir>/daemon.auth` at call time. Never log it, never
  put it in settings, never send it anywhere except the daemon
  socket/pipe.
- No network egress. The daemon API is local; a client that
  phones home, or proxies requests to a remote host, violates
  the local-first invariant (SECURITY.md 7).
- No blocking the IDE's UI thread on a run: `orchestrator_run`
  is synchronous and slow — run it on a background task and show
  progress, then show the summary.

## Reference client

`extensions/vscode/` — a thin VS Code extension over exactly this
protocol (Node stdlib only). Its `client.js` has no `vscode`
dependency and is unit-tested against a fake daemon
(`node --test test/client.test.js`); `extension.js` is only the
VS Code glue (commands → client → output channel). Another IDE
ports `client.js`'s ~150 lines, not the extension.
