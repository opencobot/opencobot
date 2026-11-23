# policy/

Policy engine, capability tokens, taint tracking and audit log.

> ⚠️ **Security-sensitive.** Changes here always require human review (see [AGENTS.md §2.4](../AGENTS.md)).

See [ARCHITECTURE.md §5](../ARCHITECTURE.md) for the safety architecture and [DECISIONS_LOG.md](../docs/DECISIONS_LOG.md) for related ADRs.

## Modules (Phase 1, Linux, Python-only, stdlib only)

| Module | What it does |
| --- | --- |
| `tokens.py` | `CapabilityToken`: short-lived, scoped token (folders, tools, network, expiry). `allows_tool()` / `allows_path()` resolve paths, so `..` and symlink escapes outside the scope are denied. |
| `audit.py` | `AuditLog`: append-only, hash-chained JSON-lines log. Multi-process safe via an exclusive `fcntl` lock held while the next sequence number / previous hash is read and the line is written. `verify()` recomputes the whole chain. |
| `engine.py` | `PolicyEngine` + `Decision`: checks every tool call in order — kill switch, token present/unexpired, tool in token, path args in scope, tainted context locks level 3+, levels 3/4 need a live human approval, levels 0–2 allowed in scope. Owns approvals (`approvals.json`, 0600), taint (`taint.json`), kill switch (`killswitch` file + in-memory flag), and appends every decision to `audit.jsonl`. |
| `policyd.py` | The engine as a separate process: Unix-socket JSON-lines server at `<state-dir>/policyd.sock`, auth token in `<state-dir>/policyd.auth` (0600, generated once, reused). Run: `python -m policy.policyd --state-dir DIR`. |
| `client.py` | `PolicyClient`: same calls as the engine, over the socket. Raises `PolicyUnavailable` (a `FileNotFoundError`) when the daemon is not running and `PolicyAuthError` on auth failure. |

State lives in `$OPENCOBOT_STATE` or `~/.opencobot` by default.

## Rules the engine enforces

1. Kill switch active → everything denied (`"kill switch active"`).
2. No token, or expired token → denied.
3. Tool not listed on the token → denied.
4. Any path-like argument (`path`, `source`, `destination`, `directory`, `folder`, `file`, `cwd`) outside the token's folders → denied (`"outside capability token scope"`).
5. Tainted context + level ≥ 3 → denied (`"tainted context: level 3+ locked"`), even if an approval exists.
6. Level 4 / level 3 → denied with `needs_approval=True` unless a live approval exists for that (token, tool).
7. Levels 0/1/2 in scope → allowed.

Every check — allowed or denied — is appended to the audit log.

## Security notes

- The model never grants itself permission: approvals are recorded only through `approve()` (in production: the UI / paired phone), never from model output.
- No network, no shell, no new dependencies in this slice.
- `policyd.auth` is the only credential here; it is generated with `secrets`, stored mode 0600, and never logged.
