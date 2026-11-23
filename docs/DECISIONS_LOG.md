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
