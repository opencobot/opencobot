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
