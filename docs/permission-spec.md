# Permission Spec

Derived from the code on `main` (`48be2ef`), not from the design docs.
Where the code and [ARCHITECTURE.md](../ARCHITECTURE.md) disagree, the
disagreement is flagged in §9 instead of silently choosing one side.
Sources: `policy/engine.py`, `policy/tokens.py`, `policy/audit.py`,
`tools/definitions.py`, `core/runtime.py`, `core/model_gateway.py`,
`core/cli_providers.py`, `core/daemon.py`, `ui/web.py`,
`cli/opencobot_cli.py`, `policy/policyd.py`, `policy/client.py`.

Status: the permission model below is **implemented** unless a section
says DESIGNED ONLY. Phone approval, skill signing, sandboxed workers,
an OS keychain and a global hotkey are DESIGNED ONLY — no code exists
for them (see §9).

## 1. Permission levels 0–4

Levels are integers on each tool (`tools/definitions.py`, `_SPECS`
table). The policy engine enforces them in
`policy/engine.py:PolicyEngine.check()`; the decision order is §2.

| Level | Scope (ARCHITECTURE.md §5) | Default policy in code |
|---|---|---|
| 0 | Read and inspect | Allowed within token scope |
| 1 | Basic interaction (open apps, navigate, keyboard/mouse) | Allowed within token scope |
| 2 | Controlled modifications (create, edit, move files in authorized folders) | Allowed within token scope, logged |
| 3 | Sensitive (delete important files, install software, change settings) | Explicit approval for the exact call (§5) |
| 4 | High risk (admin commands, security config, money, bulk data transfer) | Explicit approval for the exact call — **enforced identically to level 3** (see flag F3 in §9) |

Levels 0–2 need no approval. Levels 3 and 4 need a live approval that
matches the exact call (§5). Any other level value is denied
(`"invalid permission level"`).

## 2. Decision order — `PolicyEngine.check()`

`policy/engine.py:PolicyEngine.check(token, tool_name, level, args,
tainted=False, network_call=False)`. First matching rule wins; every
decision — allowed or denied — is appended to the audit log with the
argument hash, never raw arguments (§7 of the audit rules in
`policy/audit.py`).

1. Kill switch active → deny (`"kill switch active"`).
2. Read-only mode and `level >= 1` → deny (`"read-only mode"`).
3. No token → deny (`"no capability token"`).
4. Token expired → deny (`"capability token expired"`).
5. Tool not in the token's tool list → deny.
6. Any path-like argument (`path`, `source`, `destination`,
   `directory`, `folder`, `file`, `cwd`) outside the token's scope
   folders → deny (`"outside capability token scope"`).
7. Network call with a token whose `network` flag is `False` → deny
   (`"network access not allowed by capability token"`).
8. Tainted context and `level >= 3` → deny (`"tainted context:
   level 3+ locked"`) — **even when a live approval exists**.
9. `level == 4` or `level == 3`: allowed only with a live approval
   matching the exact call; otherwise deny with
   `needs_approval=True`.
10. `level in (0, 1, 2)`: allowed.

`Runtime.run_tool()` (`core/runtime.py`) computes `network_call` via
`_is_network_call()` and passes `tainted` through; the daemon refuses
the whole request when `policyd` is unreachable (`"policyd
unavailable"` — no in-process fallback).

## 3. Capability tokens

`policy/tokens.py:CapabilityToken`, minted by
`policy/engine.py:PolicyEngine.issue_token()` (also via
`policy/policyd.py` op `"issue_token"` and `policy/client.py`).

| Field | Type / value |
|---|---|
| `token_id` | `str`, `secrets.token_hex(16)` (32 hex chars) |
| `scope_folders` | `list[str]` — folders the task may touch |
| `tools` | `list[str]` — `"*"` allows any tool |
| `network` | `bool`, default `False` |
| `expires_at` | `float` (epoch seconds), `issued_at + duration_seconds` |
| `issued_at` | `float` (epoch seconds) |

- **Lifetime:** `duration_seconds` defaults to **600 seconds**
  (10 minutes) at every call site (engine, client, policyd, CLI).
- **Expiry:** `CapabilityToken.is_expired()` returns true when
  `now >= expires_at`; enforced in `check()` (rule 4).
- **Tool scope:** `allows_tool(name)` is true when `"*"` is in
  `tools` or the name is listed.
- **Path scope:** `allows_path(path)` resolves the path (relative
  paths against `scope_folders[0]`, so `..` escapes and symlinks
  pointing outside are caught) and requires it inside a scope
  folder. With no scope folders, every path is denied.
- **No signature:** the token carries no MAC/HMAC; trust comes from
  the transport (`policyd.auth` / `daemon.auth`, 0600 files, checked
  with `secrets.compare_digest` in the daemon), not from the token.
- **No `apps` field:** ARCHITECTURE.md §5 says tokens carry
  "folders, apps, tools, network, duration" — the code has no `apps`
  field and no app scoping (flag F2 in §9). There is also no
  user/task id and no per-tool level field.
- **Serialisation:** `to_dict()` / `from_dict()` round-trip via
  `dataclasses.asdict`. The CLI's `public_token_record()`
  (`cli/_compat.py`) exposes `{token_id, expiry (ISO), folders,
  tools, network, duration_seconds}` — never a secret.

## 4. Taint rules

Taint lives in `policy/engine.py` (`mark_tainted()`,
`clear_taint()`, `is_tainted()`); there is no `policy/taint.py`.
State is `state_dir/taint.json` — `{token_id: {"tainted_at":
<epoch>}}`, written 0600. Exposed over IPC as `policyd` ops
`"taint"` / `"untaint"` and `PolicyClient.taint()` / `untaint()`.

- **What gets tainted:** nothing automatically. There is **no code
  that detects untrusted content** — no web/email/PDF/skill
  scanner, no content classifier. Taint is set only by an explicit
  caller: `engine.mark_tainted(token_id)`, `PolicyClient.taint()`,
  the policyd `"taint"` op, or the per-call `tainted=True`
  parameter into `check()` / `Runtime.run_tool()` / CLI
  `--tainted`. `core/cli_providers.py` says "CLI output is
  untrusted, tainted data" in a comment, but `run_cli_provider()`
  returns the text **without calling `mark_tainted`** — the
  comment is not wired to any marking.
- **What is locked while tainted:** `effective_tainted =
  tainted_param or is_tainted(token.token_id)`. If tainted and
  `level >= 3`, the call is denied **even with a live approval**
  (rule 8). Levels 0–2 are unaffected by taint. There is no
  separate taint-based network lock; a network call is denied only
  when `token.network` is `False` — but the only network-capable
  tool (`run_command`) is level 3, so in practice a tainted
  network call is blocked through the level-3 lock.
- **No expiry, no provenance:** taint lasts until an explicit
  `clear_taint()` / `"untaint"`; the record keeps only
  `tainted_at`, not *what* tainted the context.
- **Stricter than the spec:** SECURITY.md invariant 4 says level
  3+ is "locked **or need approval**" while tainted; the code
  locks unconditionally (flag F4 in §9).

## 5. Approvals

`policy/engine.py:PolicyEngine.approve()`, `has_approval()`,
`revoke_approval()`; stored in `state_dir/approvals.json` (JSON
list, 0600). Scope per ADR-005 / R-007.

- **Scope (exact):** `(token_id, tool_name, level, arg_hash)` where
  `arg_hash = argument_hash(args)` — SHA-256 of the canonical JSON
  of the arguments (sorted keys, fixed separators,
  `default=str`; `None` → `{}`). **Only the hash is stored, never
  raw arguments**, so sensitive arguments are not copied into the
  file or the audit log.
- **Record fields:** `{id, token_id, tool_name, level, arg_hash,
  issued_at, expires_at}`; `id = secrets.token_hex(16)`.
- **Lifetime:** `duration_seconds` defaults to **600 seconds**.
  `has_approval()` requires an exact match on all four scope
  fields **and** `expires_at > now`. An approval recorded with
  `level=None` or without args can never match a real check
  (fail-closed: `check()` always supplies a concrete level/args).
- **Who can approve (human only):**
  - Local terminal human via the CLI:
    `cli/opencobot_cli.py:cmd_tool_run()` (`--approve` approves
    the exact run) and `cmd_policy_approve()` (`policy approve
    --tool … --args-json … --duration …`).
  - Local web UI via `ui/web.py:WebUIBackend.approve()` —
    `POST /api/approvals/{id}/approve` creates an approval from
    the body (`token_id` / `tool_name` / `level` / `args` /
    `duration_seconds`; the level defaults to the tool's
    registered level). Deny/revoke is
    `POST /api/approvals/{id}/deny` →
    `PolicyEngine.revoke_approval()`.
  - Any authenticated policyd client via the `"approve"` op
    (`policy/policyd.py:handle_request()`,
    `policy/client.py:PolicyClient.approve()`).
- **The model cannot self-approve:** there is no `approve` or
  `grant` tool in the registry (`evals/redteam.py` case 6 asserts
  this).
- **Phone approval: DESIGNED ONLY.** `remote/` contains only a
  README; there is no relay, pairing, Noise/mTLS or phone-approval
  code. The only mention is a comment in
  `cmd_policy_approve()` ("a task token held by the UI/phone").
  ARCHITECTURE.md §2/§7 and SECURITY.md invariant 1 say approvals
  come "from the UI or the paired phone" — in code the sources are
  the CLI, the web UI and authenticated policyd clients (flag F1
  in §9).
- **No second factor:** no biometric, PIN or second-person step
  exists for any approval, including level 4. Approval ids are
  bearer values stored in plaintext `approvals.json`
  (same-user readable, 0600).
- **CLI quirk:** `cmd_policy_approve()` mints a **fresh token**
  for the approval and prints its `token_id`; a later `tool run`
  mints its own token, so that approval will not match a later
  run unless the caller reuses the printed `token_id` (the code
  comment acknowledges this).
- **Approval creation bypasses policyd auth in two places:** the
  web UI (`ui/web.py:WebUIBackend._engine()`) and the daemon
  (`core/daemon.py:Daemon._readonly_engine()`) construct a
  `PolicyEngine` in-process and write policy state directly,
  instead of going through policyd. See §9 flag F6 and the
  threat model.

## 6. Network and egress flags

- **Tool static flag:** `tools/definitions.py:ToolSpec.network`
  (bool). `NETWORK_CAPABLE_TOOLS = frozenset({"run_command"})` —
  only `run_command` is network-capable.
- **Per-call classification:**
  `tools/definitions.py:is_network_call(tool_name, args)` returns
  true only for `run_command` when argv[0] is a known network
  binary (`curl`, `wget`, `ssh`, `scp`, `sftp`, `rsync`, `nc`,
  `ncat`, `socat`, `aria2c`, `ftp`, `lftp`, `telnet`, `ping`) or
  `git` with a network subcommand (`clone`, `fetch`, `pull`,
  `push`, `ls-remote`, `submodule`, `archive`). Documented bypass
  in the code itself: arbitrary code run through `run_command`
  (e.g. `python3 -c` using urllib) can still reach the network —
  which is why the tool stays level 3 and approval-gated
  regardless of the token flag (R-014).
- **Token flag enforcement:** `PolicyEngine.check()` denies a
  network call when `token.network` is `False` (default — fail
  closed). `policyd` re-classifies every check itself and ORs it
  with the caller's flag, so a caller cannot downgrade a network
  call by sending `network_call=False` (ADR-006).
- **Gateway egress classes:**
  `core/model_gateway.py:ProviderConfig.egress` is `"local-only"`
  or `"cloud-backed"` (`None` derives from kind: `"cloud"` →
  `"cloud-backed"`, everything else → `"local-only"`).
  `Gateway._is_eligible()` allows `secret` data on local-only
  providers only; `personal` on local plus user-approved cloud;
  `public` on any configured provider; any other label fails
  closed as `secret`. `Gateway.complete()` / `escalate()` refuse
  to call a cloud-backed provider without `preapproved=True`
  (returning `{"needs_approval": True, "cost_estimate": …}`
  without calling it). **Gap:** `Gateway.chat()` does **not**
  apply that pre-approval gate — it routes via `route()` and
  calls the first eligible provider after only a budget check.
  There is no OS-level default-deny firewall; egress control is
  the token flag + argv classification + gateway routing only.
- **CLI-model providers:** `core/cli_providers.py` — argv arrays
  only, no `shell=True`; binary from the user-config allowlist
  only (`ALLOWED_BINARIES = {opencode, kiro, gpt, q,
  custom-cli}`); child env built from an allowlist
  (`CLI_ENV_ALLOWLIST`: PATH, HOME, TMPDIR/TEMP/TMP, locale,
  TERM, USER, LOGNAME; secret-like names dropped); bare binary
  names resolve only against pinned dirs (`cli_binary_dirs` >
  `OPENCOBOT_CLI_BIN_DIRS` > `/usr/local/bin:/usr/bin:/bin`);
  stderr passes through `redact_secrets()` before entering an
  error (R-010–R-012, ADR-009).

## 7. Read-only mode

`policy/engine.py:PolicyEngine.set_readonly()`,
`is_readonly()`, `readonly_source()`; persisted flag
`state_dir/readonly.json` = `{"readonly": bool}` (0600); env
override `OPENCOBOT_READONLY` (`1/true/yes/on` → true,
`0/false/no/off` → false, anything else ignored; env wins,
`readonly_source()` returns `"env"` or `"file"`). Default OFF.

- Enforcement: `check()` denies `level >= 1` with
  `"read-only mode"`; **level 0 tools remain allowed**.
- Surfaces: CLI `readonly on|off|status`
  (`cli/opencobot_cli.py:cmd_readonly()`); web UI
  `POST /api/readonly` (`ui/web.py:WebUIBackend.set_readonly()`);
  daemon ops `"readonly_get"` / `"readonly_set"`. `set_readonly()`
  appends a `{"type": "readonly_changed"}` audit entry.
- The daemon constructs a fresh `PolicyEngine` per call so the
  persisted flag is read live.

## 8. Tool table — every tool in `tools/definitions.py`

`TOOLS` is built from the `_SPECS` table at the bottom of
`tools/definitions.py`. Shared rules: args validated against each
tool's JSON Schema inside `execute()` (`additionalProperties`
rejected; bad input returns `ok False`, never raises); every
filesystem path resolved through the dispatched OS adapter's
`safe_resolve()` against the context workdir plus token scope
folders (paths escaping scope — `..`, absolute paths elsewhere,
symlink escapes — are denied); no `shell=True` anywhere;
`MAX_OUTPUT_BYTES = 64 KiB` cap on captured output;
`BLOCKED_BINARIES = {sudo, su, doas, rm}`; `write_file`
snapshots the original first; `delete_to_trash` never
hard-deletes. Every `verify()` first fails when `execute()` failed
(`_verify_failed`).

| Tool | Level | Network | `execute()` | `verify()` — real state checked |
|---|---|---|---|---|
| `list_dir` | 0 | No | Validate, resolve, walk (recursive flag); return entries + count | Re-lists the live directory; reported path set must equal the real set |
| `read_file` | 0 | No | Read up to `max_bytes` (1–1,048,576, default 65536); UTF-8 decode with `replace`; report `truncated` | Re-reads the file; content and size must match byte-for-byte |
| `file_info` | 0 | No | `stat()` size/mtime/`is_dir`, sha256 if a file | Re-stats; size/type must match, file hash must match |
| `file_hash` | 0 | No | Hash file; algorithm enum `sha256`/`sha1`/`md5` | Re-hashes with the same algorithm; exact match |
| `search_files` | 0 | No | `os.walk`; `fnmatch` if the pattern has `*?[` else case-insensitive substring; `max_results` 1–1000 | Each reported match must exist on disk and match the pattern. Does **not** re-run the search or check completeness |
| `system_info` | 0 | No | Adapter `system_info()` (platform, Python, CPU, memory, load, disk) | Fresh adapter call; `cpu_count`, `platform`, `disk.total` must match |
| `list_processes` | 0 | No | Adapter `list_processes(name_filter)` | At least one reported pid must still be alive under the same identity (pid + `/proc` starttime; Windows fallback: name). Vanished pids are ignored, not failures. Filter match also checked |
| `process_info` | 0 | No | Read `/proc/{pid}/comm`, `cmdline`, `status` (name, state, ppid, RSS) | Pid must still exist in `/proc` and name unchanged. **Linux-only: reads `/proc` directly, so it fails on Windows** |
| `git_status` | 0 | No | Require a git repo; `git status --porcelain=v1 -b` via argv array; parse branch/staged/unstaged/untracked | Re-runs git status; branch and `clean` must be unchanged |
| `git_log` | 0 | No | `git log -n{max_count}` (`max_count` 1–100); parse hash/author/date/subject | Re-runs git log; exact commit-list equality |
| `git_diff` | 0 | No | `git diff` (+ `--name-only`, `--stat`), truncated at 64 KiB | Re-runs git diff; exact text equality (after the same truncation) |
| `screenshot` | 0 | No | Fails honestly if the adapter says unavailable; else `scrot`/`import`/`gnome-screenshot` → `state_dir/screenshots/screenshot-<ts>.png`. **On Windows always fails: "screenshot capture is not implemented on Windows"** | File exists, non-empty, size matches execute's report |
| `list_windows` | 0 | No | Linux `wmctrl`/`xdotool`; Windows via adapter PowerShell query | Every reported window id (Linux `id` / Windows `pid`) must still be listed live |
| `launch_app` | 1 | No | Reject `BLOCKED_BINARIES` basename; path form must be an executable file, bare name via `shutil.which`; `subprocess.Popen(..., start_new_session=True, shell=False, DEVNULL stdio)` | Pid must exist in `/proc` and name/cmdline must match the app. **Linux-only (`/proc`)** |
| `write_file` | 2 | No | Snapshot the original first, `write_text`; return size/sha256/`snapshot`/`created` | Re-hashes the file; must equal sha256 of `args["content"]` |
| `create_file` | 2 | No | Fail if the path exists, write content | File exists and sha256 equals sha256 of `args["content"]` |
| `append_file` | 2 | No | Append (create if missing); return new size/hash | File must end with the appended content **and** hash must equal execute's returned hash |
| `mkdir` | 2 | No | `mkdir(parents=…)`; fail if the path exists | Path `is_dir()` |
| `move_file` | 2 | No | `shutil.move`; fail if source missing or destination exists; record pre-move sha256 | Source gone, destination exists, destination hash (files) matches pre-move hash |
| `copy_file` | 2 | No | `shutil.copy2`; fail if source not a file or destination exists | Source and destination both exist and both hashes equal the original hash |
| `delete_to_trash` | 3 | No | Adapter `trash_path(state_dir, path)`, `shutil.move` there | Original gone, trash copy exists, trash hash (files) matches the original |
| `run_command` | 3 | **Yes — only network-capable tool** | Argv array only; reject `BLOCKED_BINARIES`; on Windows additionally `WINDOWS_BLOCKED_COMMANDS` (format, diskpart, del, nested powershell/pwsh/cmd, … — re-enforced by the adapter); reject `--no-preserve-root`; `timeout` 1–60s (default 30); Linux `subprocess.run`, Windows adapter `run_powershell` (never `cmd.exe`). Output capped 64 KiB; non-zero exit → `ok False` | **Weak by design, stated in code** — only checks `returncode == 0` and that stdout/stderr were captured. "It cannot prove the command's claimed side effect. Callers must verify side effects with a follow-up read tool." |

**Level counts:** 0 ×13, 1 ×1 (`launch_app`), 2 ×6, 3 ×2
(`delete_to_trash`, `run_command`), **4 ×0 — no tool is level 4.**

## 9. Where code and ARCHITECTURE.md disagree

Flagged, not silently resolved. Each flag needs a human decision
(ADR or doc fix) — none is fixed in this PR.

- **F1 — Approval source.** ARCHITECTURE.md §2/§5/§7 and
  SECURITY.md invariant 1: "Approvals come only from the UI or
  the paired phone, never from model output." Code: approvals also
  come from the **CLI** (`cmd_tool_run --approve`,
  `cmd_policy_approve`); **phone approval does not exist**
  (`remote/` is a README only).
- **F2 — Token fields.** ARCHITECTURE.md §5: tokens carry
  "folders, apps, tools, network, duration." Code
  (`policy/tokens.py`): `token_id, scope_folders, tools, network,
  expires_at, issued_at` — **no `apps` field**, no app scoping
  anywhere.
- **F3 — Level 4.** ARCHITECTURE.md §5: level 4 = "Strong approval
  or blocked." Code: level 4 requires exactly the same single
  approval as level 3 (`PolicyEngine.check()`); there is no
  "strong" (biometric/PIN/second-person) approval, and **no tool
  is level 4**.
- **F4 — Taint semantics.** ARCHITECTURE.md §5: while tainted,
  "Level 3+ tools and outbound network are locked **or need
  approval**." Code: tainted level 3+ is **locked unconditionally,
  even with an approval** (stricter than the spec). The spec also
  implies taint is a property of content; the code has **no
  automatic tainting** of any content (§4).
- **F5 — Sensitivity authority.** ARCHITECTURE.md §6: "`policyd`
  decides which model may see which data." Code: the **gateway**
  decides (`Gateway._is_eligible()`, `fallback_chain()`);
  policyd never sees sensitivity labels. Also, escalation shows a
  cost estimate first "unless pre-approved" — the code honours
  that in `Gateway.complete()` / `escalate()` but **not in
  `Gateway.chat()`**, which can call an assigned cloud provider
  with no approval check.
- **F6 — Policy-process separation.** ARCHITECTURE.md §2: "The
  model process and `daemon` cannot write to policy files,
  approvals or audit logs"; `policyd` is "separate user where
  possible." Code: the **daemon and web UI construct a
  `PolicyEngine` in-process** and write policy state directly —
  `core/daemon.py:Daemon._readonly_engine()` (writes
  `readonly.json`), `ui/web.py:WebUIBackend._engine()` (writes
  `approvals.json`, `readonly.json`, kill-switch file) — bypassing
  policyd and its auth token. And everything runs as the **same
  OS user**; `policy/audit.py` states the boundary is "a
  same-user boundary, not a real OS boundary" (R-006).
- **F7 — Workers / sandbox.** ARCHITECTURE.md §2/§5: short-lived
  **sandboxed worker** executors (low trust), sandbox option
  (separate user/container/VM). Code: **no worker processes, no
  sandbox** — tools execute in-process in the runtime/daemon
  (`core/runtime.py:Runtime.run_tool()`).
- **F8 — Secrets / keychain.** ARCHITECTURE.md §5: "Secrets: OS
  keychain only. The agent never sees raw keys; the gateway
  attaches them." Code: gateway keys come from **environment
  variables at call time** (`Gateway._headers()`,
  `api_key_env`); there is **no keychain code** —
  `core/memory.py` only mentions the keychain in a comment and
  rejects secret-looking keys from memory.
- **F9 — Kill switch / indicator.** ARCHITECTURE.md §5: "global
  hotkey, tray, CLI and phone button; visible indicator while the
  agent has control." Code: **CLI + web UI + policyd/daemon ops
  only**; no hotkey, tray, phone button, or on-screen indicator.
- **F10 — Screen privacy.** ARCHITECTURE.md §5: block/blur
  password managers, banking, private windows before any image
  leaves the machine. Code: **no screen-privacy code**;
  `screenshot` just captures (or fails headless).
- **F11 — Technology / UI.** ARCHITECTURE.md §12/§14 + ADR-002 /
  ADR-003: Rust policy engine/executor/relay, Tauri + React UI.
  Code: **Python-only policy engine** (per ADR-002, Rust
  deferred) and a **stdlib `http.server` web UI** (`ui/web.py`,
  binds 127.0.0.1, port 8765) instead of Tauri (deferred per
  ADR-003). `ARCHITECTURE.md` itself notes Phase 1 is Linux-first
  (superseding the §4 "Windows is the suggested MVP target" note).

## 10. Tests that cover this spec

- Levels, tokens, taint, approvals, kill switch, read-only:
  `tests/test_policy.py`, `tests/test_approvals_scoped.py`,
  `tests/test_readonly.py`, `tests/test_r006_permissions.py`,
  `tests/test_network_flag.py`.
- Tools and `verify()` on real state: `tests/test_tools.py`,
  `tests/test_verify_list_processes.py`.
- Gateway routing, egress, budgets, CLI providers:
  `tests/test_gateway.py`, `tests/test_gateway2.py`,
  `tests/test_cli_providers.py`, `tests/test_r010_r013.py`,
  `tests/test_live_fixes.py`.
- Red-team behaviour (8 cases): `evals/redteam.py`,
  `tests/test_evals.py`.
- Web UI auth and approvals: `tests/test_webui.py`.
- Audit log: `tests/test_audit.py`, `tests/test_audit_windows.py`.
