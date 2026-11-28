# Threat Model

Written against the **actual code** on `main` (`48be2ef`), not the
spec. When a control exists only in a design document, it is labelled
DESIGNED ONLY. Mitigation labels used exactly:

- **IMPLEMENTED** — the control exists in code and is covered by tests.
- **PARTIAL** — the control exists in code but has a known gap (the
  gap is stated).
- **DESIGNED ONLY** — described in SPEC/ARCHITECTURE/SECURITY.md, no
  code exists.
- **MISSING** — neither designed nor implemented.

Research notes with sources and dates:
`docs/research/agent-security-incidents-2026-11-25.md`,
`docs/research/owasp-agentic-guidance-2026-11-25.md`.

## 1. Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| User files | Token scope folders, workdir | Read/modify/delete by tools |
| Credentials and API keys | Env vars at call time (`api_key_env`); `policyd.auth` / `daemon.auth` tokens in the state dir | Gateway attaches keys; auth tokens gate policyd/daemon |
| Browser sessions | Not yet accessed by any tool | Future browser adapter surface |
| Screen content | `screenshot` output (headless: unavailable) | Password managers, banking windows (R-018) |
| System integrity | Host OS via `run_command` (level 3) | Arbitrary command execution inside token scope |
| Money | No payment tool exists | Only via `run_command` reaching e.g. cloud CLIs |
| Audit log | `state_dir/audit.jsonl` | Forensic record; tampering hides actions |
| Approvals | `state_dir/approvals.json` | Bearer records that authorise level 3/4 calls |

## 2. Adversaries

From SECURITY.md §4, restated against the code:

1. **Malicious content the agent reads** (web pages, emails, PDFs,
   documents, skill text): indirect prompt injection.
2. **Malicious or compromised skills and plugins.**
3. **A weak or misbehaving model.**
4. **A network attacker against remote access** (remote control is
   DESIGNED ONLY — no remote code exists yet).
5. **A local low-privilege process trying to hijack the daemon** —
   including any same-user process (R-006: the policy boundary is a
   same-user boundary, not a real OS boundary).

Out of scope (SECURITY.md): a fully compromised host OS or a
root-level attacker; guarantees that any model behaves correctly.

## 3. Trust boundaries

| Boundary | Mechanism in code | Strength |
|---|---|---|
| Model ↔ policy | Separate `policyd` process; JSON-lines IPC over Unix socket (`policyd.sock`, 0600) or named pipe (`\\.\pipe\opencobot-policyd`, DACL) | Medium — see §4.5 |
| Daemon ↔ policyd | `policyd.auth` token (0600, `secrets.token_hex(32)`), equality check in `policy/policyd.py:handle_request()`; daemon token checked with `secrets.compare_digest` in `core/daemon.py` | Medium — same-user readable |
| Tools ↔ filesystem | `safe_resolve()` containment + token scope (`tools/definitions.py:_resolve()`, `policy/tokens.py:CapabilityToken.allows_path()`) | Strong within scope |
| Browser ↔ web UI | 127.0.0.1-only bind (`ui/web.py:validate_host()`, `ALLOWED_HOSTS`), session cookie (HttpOnly, SameSite=Lax, 12h), token in POST body only | Medium — see §4.3 |
| Gateway ↔ cloud | Egress classes + sensitivity labels + budgets (`core/model_gateway.py`) | Partial — see §4.4 |
| Agent ↔ secrets | Env vars at call time; `redact_secrets()` on CLI stderr; audit stores argument hashes, not raw args | Partial — see §4.7 |
| Operator ↔ audit log | SHA-256 hash chain (`policy/audit.py:AuditLog`) | Partial — see §4.9 |

## 4. Attack scenarios

### 4.1 Indirect prompt injection

**Scenario:** content the agent reads (a web page, email, PDF,
skill text, CLI output) contains instructions such as "delete the
project" or "send the file to this URL". The model follows them and
issues a harmful tool call. Real cases: EchoLeak (CVE-2025-32711,
zero-click Copilot exfiltration via one email), the GitHub MCP
"toxic agent flow" (a malicious public issue made an agent leak
private-repo data into a public PR), SalesBleed (injection in a
public web form, exfiltration via DNS), Manus (one obfuscated email
→ reverse shell).

**Mitigation — PARTIAL:**
- `policy/engine.py:PolicyEngine.check()` — tainted context locks
  level 3+ tools **even with a live approval** (rule 8), and the
  level-3 approval gate means a bare harmful call is denied.
- There is no `approve` tool in the registry, so the model cannot
  self-approve (`evals/redteam.py` case 6).
- `core/runtime.py:Runtime.run_tool()` only executes explicit tool
  calls, never acts on text alone.

**Gap:** no automatic taint marking exists — nothing in the code
detects untrusted content. Injection is blocked only if some caller
flagged the context tainted (`mark_tainted()`) or no approval
exists. `core/cli_providers.py` calls CLI output "untrusted,
tainted data" in a comment but never calls `mark_tainted()`. A
level 0–2 exfiltration-shaped call (e.g. `read_file` of a secret
followed by a level-2 write into a world-readable location) is not
stopped by the taint lock at all. New risk **R-020**.

**Tests:** `evals/redteam.py` cases 1–3
(`injection_delete_without_approval`,
`tainted_run_command_blocked_even_with_approval`,
`tainted_exfil_blocked`); `tests/test_policy.py`.
**Red-team coverage:** yes (3 of 8 cases).
**Residual risk:** High. The control that would stop injection at
agent speed — automatic tainting of tool output and read content —
does not exist.
**SECURITY.md invariant:** 1, 3, 4.

### 4.2 Malicious skills

**Scenario:** a skill (manifest + instructions + code) is installed
from an untrusted source and declares one permission while doing
another, or its instructions inject commands. Real cases:
ClawHavoc (1,100+ malicious skills flooded OpenClaw's ClawHub
registry in Jan–Feb 2026, delivering macOS stealers); the in-the-
wild `AGENTS.md` attack (a planted instruction file made coding
agents rewrite their own config, Oct 2026).

**Mitigation — DESIGNED ONLY:** ARCHITECTURE.md §8 and SECURITY.md
invariant 10 require signed packages, pinned hashes, static
analysis, permission diffs on install and update, sandboxed
execution and registry tiers. **No code exists:** `skills/`
contains only a README — no manifest parsing, no signature
verification, no permission diff, no sandboxing, no registry.

**Tests:** none. **Red-team coverage:** no (no skill case in
`evals/redteam.py`).
**Residual risk:** High while the skills system is unbuilt — but
the exposure is currently zero because there is no skill loader
at all. The risk materialises the moment a loader lands; signing
and scanning must land with it, not after.
**SECURITY.md invariant:** 10. **Existing risk:** R-002 (Open —
design phase).

### 4.3 Exposed remote access

**Scenario:** the remote-control channel (or the local web UI) is
reachable by an attacker and used to issue commands or disable
approvals. Real cases: OpenClaw CVE-2026-25253 / "ClawJacked"
(Feb 2026) — a crafted link made the Control UI auto-connect to an
attacker URL and send the gateway token, giving 1-click operator
access including disabling confirmations; tens of thousands of
OpenClaw instances were found internet-exposed, most without
authentication.

**Mitigation — DESIGNED ONLY for remote; PARTIAL for the local UI:**
- Remote control: `remote/` contains only a README. No relay,
  pairing, QR, Noise/mTLS or phone channel exists. The "no
  inbound ports, ever" rule holds trivially because nothing
  listens except localhost services.
- Local web UI (`ui/web.py`): binds 127.0.0.1 only
  (`validate_host()`, `ALLOWED_HOSTS = ("127.0.0.1",
  "localhost")`); login is `POST /login` with the token in the
  body only; the session cookie is HttpOnly, SameSite=Lax, 12h
  sliding (`SessionStore`); the daemon token never appears in a
  URL, redirect or log (R-013, ADR-009).

**Gap (web UI part FIXED 2026-11-28, branch
`agent/webui-origin-rate-limit`):** there was **no Origin header
check and no rate limiting** on the web UI, daemon or policyd.
"Bind localhost only" is not a trust boundary by itself —
ClawJacked showed a malicious website reaching a localhost daemon
through the victim's browser. The SameSite=Lax cookie blocks the
session cookie on cross-site POSTs, and the 256-bit daemon token
is not guessable, so this was defence-in-depth rather than an open
hole — but an attacker-controlled page could still probe the UI,
and failed logins were neither throttled nor logged. New risk
**R-025**. The web UI fix: `ui/web.py` now rejects cross-origin
POSTs whose Origin is not the UI's own
`http://127.0.0.1:<port>` / `http://localhost:<port>` (403 +
logged; requests with no Origin are still allowed), and throttles
failed `POST /login` attempts per IP (5 per 15 minutes, then 429
with Retry-After; a successful login resets the counter; failures
are logged, the token never is). SameSite=Lax kept. Still open:
no rate limiting on the daemon or policyd (gap 10, folded into
R-025).

**Tests:** `tests/test_webui.py` (login, session, approval
endpoints; R-025: cross-origin POST rejected, same-origin and
no-Origin POST allowed, login throttling incl. reset and window
expiry). **Red-team coverage:** no.
**Residual risk:** Medium for the local UI; the remote channel
cannot be assessed until it exists.
**SECURITY.md invariant:** 5. **Existing risk:** R-004 (Open —
design phase).

### 4.4 Compromised or misbehaving model

**Scenario:** the model (local or cloud) issues wrong, excessive
or malicious tool calls: wrong files, bulk deletes, or a cloud
call carrying secret data. Real cases: Replit's agent deleting a
production database during an explicit code freeze (July 2025) —
an instruction is a request the model can argue with, not a lock;
SalesBleed's agent posting phishing in its own name with no
confirmation or attribution.

**Mitigation — PARTIAL:**
- The model proposes only: `PolicyEngine.check()` (separate
  process, token scope, taint, approvals) + every tool's
  `verify()` against real state (`tools/definitions.py`).
- `Runtime.run_tool()` fails closed on policy error or
  unreachable policyd (`core/runtime.py:_policy_killed()`).
- Gateway: sensitivity labels (`_is_eligible()` — secret is
  local-only, unknown labels fail closed as secret), daily and
  monthly budgets (`check_budget()`, default 1000 calls/day),
  circuit breaker (60s cooldown, `mark_failure()` /
  `is_available()`), escalation only after 2 schema failures
  (`core/model_gateway.py`).

**Gaps:** the model may freely call all level 0–2 tools in
scope; `Gateway.chat()` bypasses the cloud pre-approval /
cost-estimate gate that `complete()` / `escalate()` enforce
(it routes and calls after only a budget check) — new risk
**R-021**; no independent verifier is enforced in `run_tool`
beyond each tool's own `verify()`; there is no agent-identity or
per-action attribution in the audit log beyond tool + token id.
**Tests:** `tests/test_gateway.py`, `tests/test_gateway2.py`,
`tests/test_runtime.py`, `tests/test_tools.py`.
**Red-team coverage:** partial (taint cases only).
**Residual risk:** High for `chat()` callers; Medium otherwise.
**SECURITY.md invariant:** 1, 3, 7, 11.

### 4.5 Local privilege escalation (named pipe and Unix socket)

**Scenario:** a local process — same user or another local account
— connects to `policyd` or the daemon and issues policy decisions
or tool calls, or reads the auth tokens and impersonates a client.
SECURITY.md adversary 5.

**Mitigation — PARTIAL:**
- POSIX: `policy/policyd.py:serve()` binds
  `state_dir/policyd.sock` (0600); `core/daemon.py:serve_forever()`
  the same for `daemon.sock`; state dir 0700 and private files
  0600 via `policy/audit.py:enforce_state_permissions()` (raises
  `PermissionError` if it cannot tighten).
- Every request must carry the `policyd.auth` / `daemon.auth`
  token (0600, `secrets.token_hex(32)`; daemon checks with
  `secrets.compare_digest`, policyd with an equality check).
- Windows: `core/transport.py:NamedPipeListener` +
  `_pipe_dacl_entries()` — DENY `NT AUTHORITY\NETWORK`
  (S-1-5-2) first, GRANT current user + `BUILTIN\Administrators`
  (S-1-5-32-544), read+write only, `_PIPE_MAX_INSTANCES = 1`;
  fails closed if the ACL cannot be built (R-017, ADR-010).

**Gaps / honest limits:** the boundary is a **same-user
boundary, not a real OS boundary** (`policy/audit.py`, R-006) —
any same-user process can read `policyd.auth` / `daemon.auth`
(0600, same user) and impersonate a client; Administrators are
explicitly granted pipe access. The named-pipe listener is
**implemented-but-unverified** — written and mock-verified on
Linux only, never run on a real Windows host
(`core/transport.py` header, `docs/WINDOWS_TESTING.md` §6).
A different-user DACL negative check has never been run (no
second local account on the test laptop).
**Tests:** `tests/test_windows_pipe_server.py` (20 mock tests),
`tests/test_r006_permissions.py`, `tests/test_daemon_transport.py`,
`tests/test_policyd_reachable.py`.
**Red-team coverage:** no (no IPC/auth/DACL case).
**Residual risk:** High for the same-user case by design (needs a
separate OS user/container for a real boundary); Critical if the
Windows DACL is wrong, which only the laptop run can prove.
**SECURITY.md invariant:** 2, 5. **Existing risks:** R-006, R-017.

### 4.6 Supply chain

**Scenario:** a malicious dependency, a compromised build step, or
a poisoned package ships code (or prompts) that subvert the agent.
Real cases: Amazon Q Developer (CVE-2025-8217) — a malicious commit
shipped a natural-language prompt instructing the agent to wipe
the home directory and cloud resources; ClawHavoc's registry
poisoning (§4.2); MCP tool poisoning (Invariant Labs, Apr 2025;
CVE-2025-54136 "MCPoison") — hidden instructions in a tool
description executed at `tools/list` time, before any approval.

**Mitigation — MISSING in code (policy only):** no dependency
pinning/lockfile verification, no package-signature check, no
skill signing, no release signing in code. Mitigating facts only:
the mapped modules (tools, gateway, transport, policy) are
stdlib-only with no third-party runtime dependencies;
SECURITY.md's dependency policy (justification + license check +
CI scans) is a policy statement, not code; CI runs
`pip install -r requirements.txt` with no hash check.

**Tests:** none for supply chain. **Red-team coverage:** no.
**Residual risk:** Medium — the stdlib-only core limits the
blast radius, but `requirements.txt` is unpinned/unhashed and any
future dependency, skill or MCP tool widens it.
**SECURITY.md invariant:** 10. **Existing risks:** R-002, R-009
(fixed — fallback deleted).

### 4.7 Secret leakage in logs and stderr

**Scenario:** an API key or token reaches a log, the audit log,
memory, an error message or CLI output, and is then read by the
model, exfiltrated, or retained in telemetry. Real cases: Manus
(Oct 2026) — Gmail OAuth and Drive/GitHub credentials sat in
environment variables in the sandbox and were reachable once an
injection succeeded; SalesBleed — exfiltration via DNS, a channel
egress controls did not cover.

**Mitigation — PARTIAL:**
- `core/model_gateway.py:Gateway._headers()` reads the API key
  from the named env var at call time only, never logs it.
- `core/cli_providers.py:redact_secrets()` (R-011) scrubs CLI
  stderr (`key=value`, Bearer tokens, `sk-`/`sk-ant-`/`ghp_`/
  `AKIA`/`xox*` shapes, PEM blocks) before it enters an error.
- `core/cli_providers.py:_scrubbed_env()` (R-010) builds the
  child env from an allowlist; secret-like names are dropped.
- `core/runtime.py:_redact_args()` redacts keys containing
  `secret`/`password`/`token`/`api_key`/`api-key` in the runtime
  audit event; the policy audit stores only the argument hash,
  never raw args (`policy/engine.py:PolicyEngine.check()`).
- The web UI token is never in a URL, redirect or log
  (`ui/web.py`, R-013).

**Gaps:** `redact_secrets()` applies only to CLI stderr on
failure — not to CLI stdout (returned verbatim) or success paths;
`_scrubbed_env()` passes an explicit per-call `env` override
through verbatim; a `run_command` argv that embeds a secret as a
value is stored in the runtime `tool_call` audit event because
the key (`argv`) does not match the redact markers; there is **no
OS-keychain code** — keys come from environment variables at call
time, and `core/memory.py` only mentions the keychain in a
comment. New risk **R-024**.
**Tests:** `tests/test_r010_r013.py`.
**Red-team coverage:** no (no log-content case).
**Residual risk:** Medium.
**SECURITY.md invariant:** 6, 7.

### 4.8 Approval spoofing

**Scenario:** an attacker (or the model) forges, replays or
reuses an approval to run a level 3/4 call the human never
approved, or disables approvals. Real cases: ClawJacked's
attacker changing config to disable confirmations; SalesBleed's
Slack action needing no confirmation at all; Replit showing
per-action consent collapses at agent speed (~5,000 ops/min).

**Mitigation — PARTIAL:**
- Approvals are bound to `(token_id, tool_name, level,
  arg_hash)` with a 600s expiry
  (`policy/engine.py:PolicyEngine.has_approval()`); a different
  level or different arguments needs a fresh approval (R-007,
  ADR-005); only the hash is stored, never raw args.
- There is no `approve` tool, so the model cannot self-approve
  through a tool call.
- Approval creation requires the policyd auth token, the daemon
  auth token, or a valid web session.

**Gaps:** no biometric/PIN/second factor anywhere; approval ids
are bearer values stored in plaintext `approvals.json`
(same-user readable); the web UI
(`ui/web.py:WebUIBackend._engine()`) and the daemon
(`core/daemon.py:Daemon._readonly_engine()`) create approvals
via an **in-process** `PolicyEngine`, bypassing policyd and its
auth check — new risk **R-022**; approval state lives in the
same same-user state dir as everything else (R-006).
**Tests:** `tests/test_approvals_scoped.py`,
`tests/test_policy.py`.
**Red-team coverage:** partial (case 6, no-approve-tool only —
no forged-approval, wrong-args, wrong-level, expired-approval
or cross-token case in redteam; those live in the unit tests).
**Residual risk:** High for the in-process bypass; Medium
otherwise.
**SECURITY.md invariant:** 1. **Existing risk:** R-007 (fixed).

### 4.9 Audit-log tampering

**Scenario:** an attacker who has acted edits, deletes, reorders
or rewrites the audit log so the action disappears from the
record. No public incident of agent audit-log tampering was
found in research — this section rests on design guidance
("Agent Flight Recorder", arXiv:2609.01931, Sep 2026) and should
be read as such.

**Mitigation — PARTIAL:**
- `policy/audit.py:AuditLog.append()` — hash-chained JSONL
  (`seq`, ISO-8601 `ts`, `prev_hash`, `hash = SHA256(prev_hash +
  canonical_json(entry))`, genesis `prev_hash = "0"*64`);
  `AuditLog.verify()` recomputes the whole chain and reports
  per-sequence errors; appends hold an exclusive cross-process
  lock (`fcntl.flock` on POSIX, `msvcrt.locking` on Windows);
  file 0600, state dir 0700; verification exposed via policyd
  op `"audit_verify"` and CLI `audit verify`.

**Gaps:** the locks are advisory/cooperative — a process that
opens the file without locking can still write; there is no
signature/key, so a same-user attacker who can rewrite the file
can recompute the whole chain (the chain detects accidental or
edit-in-place tampering, not a same-user rewrite); no WORM
storage and no external copy; verification is on-demand only,
not continuous. New risk **R-023**.
**Tests:** `tests/test_audit.py`, `tests/test_audit_windows.py`.
**Red-team coverage:** no (no verify-after-edit case).
**Residual risk:** Medium — the log is reliable against
accidents and against attackers who cannot write the file, and
unreliable against a same-user attacker who can.
**SECURITY.md invariant:** 8. **Existing risk:** R-008 (Open).

### 4.10 Kill-switch failure

**Scenario:** the agent is doing harm and the kill switch does
not stop it — because it is hung, the switch itself is
unreachable, or an attacker released it.

**Mitigation — PARTIAL:**
- `policy/engine.py:PolicyEngine.set_kill()` /
  `is_killed()` — in-memory flag plus `state_dir/killswitch`
  file; checked **first** in `check()`, before anything else.
- `core/runtime.py:_policy_killed()` fails closed (no policy or
  policy error → treated as killed).
- Surfaces: policyd ops `"kill"` / `"unkill"`
  (`policy/client.py:PolicyClient.kill()` / `unkill()`), CLI
  `kill` / `unkill`, web `POST /api/kill`, daemon ops
  `"kill"` / `"unkill"`.

**Gaps:** no global hotkey, tray icon, phone button, or visible
"agent has control" indicator exists in code (all ARCHITECTURE.md
§5 claims); the kill file lives in the same same-user state dir
(a same-user process can delete it or call `unkill` if it holds
`policyd.auth`); CLI `kill` requires policyd to be running
(`_require_policyd()`), so the switch cannot be engaged through
the CLI when policyd itself is down (the web UI's in-process
path still works).
**Tests:** `tests/test_policy.py` (kill switch cases).
**Red-team coverage:** no (no kill/unkill case).
**Residual risk:** Medium — the switch works through every
implemented surface, but there is no out-of-band surface and no
indicator that the agent is in control.
**SECURITY.md invariant:** 9.

## 5. Gaps found (ranked by severity)

| # | Gap | Severity | New risk | Proposed fix (not done in this PR) |
|---|---|---|---|---|
| 1 | No automatic taint marking — injection content is only blocked if a caller flagged the context or no approval exists; CLI output is never marked tainted | High | R-020 | Mark tool output and read content tainted at the runtime boundary (`core/runtime.py`), with provenance; ADR proposal |
| 2 | `Gateway.chat()` bypasses the cloud pre-approval / cost-estimate gate | High | R-021 | Route `chat()` through the same gate as `complete()`/`escalate()`; add a test that a cloud-backed provider is not called without pre-approval |
| 3 | Daemon and web UI write policy state via an in-process `PolicyEngine`, bypassing policyd auth | High | R-022 | Route all approval/read-only/kill writes through `PolicyClient` to policyd; add a test that no `PolicyEngine(` construction exists outside `policy/` and tests |
| 4 | Same-user boundary for the whole policy state (R-006) — any same-user process can read `policyd.auth` and impersonate a client, delete the kill file, or rewrite approvals | High | R-006 (existing) | Documented path: run policyd as a separate OS user (README already documents it); longer term: separate user/container by default |
| 5 | Windows named-pipe DACL is implemented-but-unverified; a wrong DACL would be a Critical local-escalation hole | High* | R-017 (existing) | Laptop run of `docs/WINDOWS_TESTING.md` §6, including the different-user negative check (*severity is Critical if the DACL is wrong; High until proven) |
| 6 | No skill signing/sandboxing — DESIGNED ONLY, zero code | High* | R-002 (existing) | Do not ship a skill loader without signing, scanning and sandboxing; *severity is High when a loader lands, currently unexploitable (no loader) |
| 7 | Audit log has no external anchor or signature — a same-user rewrite recomputes the chain | Medium | R-023 | Periodic external anchoring (signed checkpoints / remote copy / WORM); routine `audit verify` |
| 8 | Secrets can reach logs: `redact_secrets()` only on CLI stderr failure; `run_command` argv stored in the runtime audit event; no keychain (env vars at call time) | Medium | R-024 | Redact stdout/success paths too; redact `argv` values that match secret shapes; implement the OS-keychain broker (SPEC §5.2) |
| 9 | Web UI has no Origin validation and no rate limiting | Medium | R-025 | Fixed 2026-11-28 (branch `agent/webui-origin-rate-limit`): Origin allowlist on POSTs + login rate limiting (5 failures/15 min/IP, 429 + Retry-After) + logging in `ui/web.py`; SameSite=Lax kept |
| 10 | No rate limiting anywhere (daemon, policyd, web UI) | Low | — (folded into R-025) | Add per-endpoint limits when the remote channel lands; not urgent for localhost-only |
| 11 | No screen-privacy code (block/blur password managers, banking) | Medium | R-018 (existing) | Required before any screenshot/UI Automation path ships |
| 12 | Red-team suite covers 8 cases but none of: skills, remote/IPC auth, supply chain, secrets-in-logs, approval forgery, audit tampering, kill switch | Medium | — | Extend `evals/redteam.py` with cases for each (propose as issues) |
| 13 | `run_command` network classification is argv-based, not a sandbox — `python3 -c` with urllib bypasses the token network flag | Medium | R-014 (existing, documented) | Documented honest limit; a sandbox/namespace is the real fix, deferred |

## 6. References

- Research notes: `docs/research/agent-security-incidents-2026-11-25.md`,
  `docs/research/owasp-agentic-guidance-2026-11-25.md` (read 2026-11-25).
- SPEC §2, §4, §5, §19; ARCHITECTURE.md §5–§8; SECURITY.md;
  `docs/risks.md` (R-001–R-025); ADRs 005–010.
