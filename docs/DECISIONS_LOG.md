# Decisions Log (ADRs)

**Append-only.** Newest first. Never delete an entry — supersede it and mark the old one.

When a real architectural choice is made (not a styling tweak), add an entry **in the same PR**.

```
## ADR-0XX — <title>
Date · Status: Proposed | Accepted | Superseded by ADR-0YY | Deferred | Open
Context: what forced the decision
Decision: what we chose
Alternatives: what else was considered, and why not
Consequences: what this makes easier or harder later
```

---

## OPEN — needs a human decision

Nobody should build against these until they're resolved.

*(none yet)*

---

---

# Current decisions

## ADR-007 — Gateway config file; provider errors are no longer swallowed
2026-11-23 · Status: Accepted
Context: Live model testing (Ollama qwen2.5:0.5b) found three diagnostics gaps: (1) a failed runtime step reported "step 'list_dir' failed: allowed" because run_task preferred the policy decision reason over the tool's own error; (2) the CLI benchmark with the default model llama3.1 not installed scored 0.00 on all 7 tests with empty outputs, because Gateway.complete() caught the provider exception and returned a generic "no provider available" with no detail, and _call_http's error dict was then read as an "unexpected response"; (3) the gateway had no config-file override, so the default llama3.1 could only be changed in code.
Decision: (a) run_task reports the tool's own error when the step was allowed (decision reason only when the step was denied), and run_tool carries the execution error into its evidence; (b) _call_provider and Gateway.chat() surface an error dict's message (e.g. "model error: HTTP 404"), complete()/escalate() keep every provider error in their final error, and _gateway_complete prefers the gateway's error over "gateway returned no text"; the CLI benchmark probes the provider once before the suite and aborts with a clear error (naming model + cause) when it fails, and accepts a one-run --model override; (c) Gateway() loads ~/.config/opencobot/gateway.json (or $OPENCOBOT_GATEWAY_CONFIG) when present, overriding model/base_url (and timeout, api_key_env, budgets) on same-name providers and adding new named providers that declare a kind; unknown names without a kind fail loudly. Precedence: explicit configs > --model > config file > defaults. API keys are never read from the file.
Alternatives: Adding an "ok" flag to complete()'s result (rejected — the Phase 2 contract has no ok key; consumers now check error/needs_approval/text instead); making the benchmark tolerate a dead provider by scoring 0 (rejected — that was the bug: a missing model looked like a bad model); env-var-only model override (rejected — a file also documents base_url and extra providers, and the CLI already uses env vars for secrets only).
Consequences: A missing or failing model now fails fast with its real cause at every layer (gateway, runtime, CLI); the default model is changeable without code. The config file is a new trusted-local-config input: it can point a provider at any base_url, so it must only ever be written by the machine owner, like the CLI allowlist. Existing tests are unchanged in shape (complete() results gain no new keys).
## ADR-006 — Token `network` flag is enforced by the policy engine
2026-11-23 · Status: Accepted
Context: Capability tokens carried a `network: bool` flag (default False) that nothing checked, so a token issued without network access could still run `run_command` with `curl`/`wget`/`ssh` and exfiltrate data. The flag existed in `policy/tokens.py` since Phase 1 but was dead code.
Decision: Tools declare a static `network` capability (`ToolSpec.network`; only `run_command` is network-capable) and `tools.definitions.is_network_call(tool_name, args)` classifies each individual call from its argv — known network binaries (curl, wget, ssh, scp, sftp, rsync, nc, ncat, socat, aria2c, ftp, lftp, telnet, ping) and `git` network subcommands (clone/fetch/pull/push/ls-remote/submodule). The policy engine denies a network call when the token has `network=False`, with a clear reason, audit-logged. `policyd` re-classifies every check itself (caller's claim OR its own classification) so a caller cannot downgrade a network call by sending `network_call=False`. CLI: `token issue --network`, `tool run --network`, `policy check --network`; the flag defaults to False everywhere (fail closed). The token network flag is recorded as risk R-014 — it had no risk ID before this round.
Alternatives: Static per-tool denial only (rejected — `echo` via `run_command` is not a network call and should not need a network token); a network namespace / sandbox (rejected for this round — heavier, Linux-only, and the approval gate already bounds `run_command`); trusting the caller's `network_call` value (rejected — a compromised caller could lie; policyd now takes the max of both classifications).
Consequences: Network egress is now gated by the token, on top of the Level 3 approval gate — the flag is defence-in-depth, not a replacement for approval. Honest limit, documented in code: argv classification is not a sandbox. Arbitrary code run through `run_command` (e.g. `python3 -c` using urllib) can still reach the network, which is why `run_command` stays Level 3 and approval-gated regardless of the token flag.

## ADR-005 — Approvals are level-scoped and argument-bound
2026-11-23 · Status: Accepted
Context: Approvals were scoped to (token_id, tool_name) with a 600s expiry, so one benign `run_command` approval (e.g. `echo 42`) could be replayed for a different command with the same tool (R-007). That made the human's approval meaningless for the highest-risk tool.
Decision: An approval is now (token_id, tool_name, permission level, argument hash). `argument_hash()` is a stable SHA-256 of the canonical JSON of the arguments (sorted keys, `default=str`); only the hash is stored in `approvals.json` and in audit entries — never raw arguments, so sensitive arguments are not logged. A different level or different arguments needs a fresh approval; an approval recorded without a level can never match a real check (fail closed). The CLI (`policy approve --args-json/--level`, `tool run --approve` for the exact args about to run), the web UI approve path and the `policyd` approve op all bind approvals to the exact call.
Alternatives: Scoping to (tool, argument hash) without the level (rejected — the same arguments at a higher level are a different risk); storing raw arguments in the approval record (rejected — would leak sensitive arguments into a file and the audit log); keeping (token, tool) scoping and relying on expiry (rejected — the replay window was the bug).
Consequences: Every Level 3/4 call now needs an approval for exactly that call; existing tests and evals were updated to the exact-args flow. Approval replay for a different command is closed; the residual is that the approving human must still read the arguments they approve.

## ADR-004 — CLI-model providers and hybrid local/cloud routing division
2026-11-23 · Status: Accepted
Context: SPEC §8 requires the platform to work with any model, and the maintainer clarified Phase 2 must be powerable by ANY AI/model that runs in a CLI — opencode, kiro-cli, gpt cli, Amazon Q CLI, OpenCode — not just HTTP Ollama/OpenAI-compatible endpoints. SPEC §8.4 also requires an explicit work division ("tool kaam ko divide kr sake, kon ka kaam kise handle kre"), not just "local first, cloud fallback".
Decision: The gateway gains a generic CLI-model provider (`core/cli_providers.py`): subprocess, argv arrays only, no `shell=True`, binary from a user-config allowlist only (never from model output), prompt passed as data. Every provider — HTTP or CLI — declares an egress class: `local-only` or `cloud-backed` (Amazon Q CLI is `cloud-backed` by default; opencode/kiro/gpt default `local-only`; a `custom-cli` pointing at a cloud CLI must set `egress="cloud-backed"`). Routing is a real, testable table (`DEFAULT_ROLE_ASSIGNMENT`, `ROUTING_TABLE` in `core/model_gateway.py`): router/classifier, grounder and summarizer stay local; planner uses the strongest available and is the only role that escalates on high complexity; executor uses a reliable local tool-caller; verifier is a separate model or pure code check. Cloud escalation happens only if the user configured a cloud provider, only for public/personal data, never secret, and only on: JSON/schema fails twice, agent loops, verification fails, high complexity, or low confidence — with a cost estimate first unless pre-approved. Sensitivity: secret = local-only always; personal = user-approved cloud; public = any configured provider; unknown label fails closed as secret. See docs/GATEWAY.md for the full matrix.
Alternatives: HTTP-only gateway (rejected — excludes the maintainer's CLI models); per-provider free-form routing with no table (rejected — the division would be implicit and untestable); cloud-by-default escalation (rejected — violates SECURITY.md invariant 7, secret data never leaves the machine).
Consequences: Any CLI-running model can power OpenCobot with the same policy/budget/taint rules as HTTP models; CLI output is treated as untrusted/tainted data. New risks are recorded as R-010–R-012 (ambient env inheritance by CLI binaries, stderr leakage into logs, PATH spoofing). Built-in CLI argv templates are plausible defaults, not verified against real CLI versions — users can override `cli_argv_template`.

## ADR-003 — Tauri desktop UI deferred; simple web UI first
2026-11-23 · Status: Accepted
Context: SPEC §15 Phase 2 includes a Tauri desktop UI and approval UI. The maintainer approved the suggestion to do gateway + benchmark + read-only first and defer Tauri: a Tauri app needs Rust + Node + a display server, and the build/test server is headless Linux, so its UI could not be tested here; it is also the largest Phase 2 item.
Decision: Phase 2 ships a simple web UI instead (`ui/web.py`, stdlib-only `http.server`, binds 127.0.0.1 only, daemon auth token required, no JS framework, no external CDN): status, tools list, approvals (approve/deny), audit view, read-only toggle, kill switch, gateway providers, benchmark report. The Tauri + React desktop app stays on the roadmap for a later phase, when there is a machine with a display to test it on.
Alternatives: Tauri in Phase 2 (rejected for now — untestable here, would dominate the phase); no UI at all, CLI-only approvals (rejected — the maintainer asked for a browser-openable UI now, and approvals need a human-friendly surface).
Consequences: Approvals and monitoring are usable from any local browser today with no new dependency; the web UI is a stopgap, not the final desktop experience, and its `?token=` query-param auth (browser-history exposure) should be replaced by a session cookie before it is relied on widely (R-013).

## ADR-002 — Python-only policy engine for Phase 1, Rust deferred
2026-11-23 · Status: Accepted
Context: SPEC §6/§18 lists Rust as the candidate for the policy engine, executor and relay client, but leaves Python-only vs Python+Rust an open decision. The Phase 1 MVP must be built and fully tested on a Linux server overnight, with no live model.
Decision: Phase 1 ships a Python-only policy engine (`policyd` as a separate Python process, Unix-socket IPC, same permission/token/taint/audit semantics as the spec). Rust is deferred to a later phase, when the policy interface is stable and there is time to validate a second implementation against the same test suite.
Alternatives: Rust from day one (rejected for Phase 1 — slower to build/test, two implementations to keep in sync, no Rust test harness on the server); Python policy in-process (rejected — violates SECURITY.md invariant 2, the policy engine must be a separate process).
Consequences: Faster, fully testable MVP; the policy IPC protocol becomes the stable boundary, so a Rust `policyd` can replace the Python one later without changing the daemon, CLI or MCP server. The Python implementation must be treated as security-critical and human-reviewed despite being "only" Phase 1.

## ADR-001 — Linux-first MVP (Windows adapter deferred to a stub)
2026-11-23 · Status: Accepted
Context: SPEC §15 suggests Windows as the MVP OS, but the build/test server available for Phase 1 is Linux (no Windows, no display server, Docker containers cannot run on it). The user (maintainer) chose "Linux first — server pe poora test hoga" on 2026-11-23.
Decision: Phase 1 targets Linux: all 22 tools are implemented against the Linux adapter and verified by tests on Linux. The Windows adapter exists only as a stub raising NotImplementedError, behind the same tool interface, so Windows work later does not redo the core, policy, tools or gateway.
Alternatives: Windows-first per the spec suggestion (rejected for Phase 1 — code could be written but not executed or tested here); both OSes at once (rejected — doubles the untested surface).
Consequences: Phase 1 is genuinely runnable and testable end-to-end on Linux; Windows, macOS and GUI grounding (screenshot/windows) remain explicitly out of scope until a Windows machine is available to test on. ARCHITECTURE.md §4 platform note ("Windows is the suggested MVP target") is superseded for Phase 1 by this ADR, not silently ignored.
