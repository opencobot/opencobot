# OpenCobot Architecture

Status: Draft v0.1. Phase 1 (Linux MVP) is merged per ADR-001 (Linux-first; the §4 note "Windows is the suggested MVP target" is superseded for Phase 1) and ADR-002 (Python-only policy engine; Rust deferred). Phase 2 (gateway roles, hybrid local/cloud routing, CLI-model providers, capability benchmark, read-only mode, simple web UI) is implemented on branch `agent/phase2-gateway` per ADR-003 (Tauri deferred, web UI first) and ADR-004 (CLI providers + hybrid routing division). This document remains the design source of truth; if code and this document disagree, add an ADR entry in [docs/DECISIONS_LOG.md](docs/DECISIONS_LOG.md) before changing either.

## 1. Goals and non-goals

**Goals:** local-first operation; any compatible model; one tool interface across Windows, Linux and macOS; enforced safety independent of the model; verified outcomes; usable by developers (MCP, CLI, SDK) and non-technical users (desktop app, phone, voice).

**Non-goals:** defending against a fully compromised host or a root attacker; guaranteeing that any arbitrary model completes any task; being an operating system (OpenCobot is an automation layer on top of one).

## 2. Process model

| Process | Role | Trust |
|---|---|---|
| `daemon` | Agent runtime, model gateway, scheduler, local API (socket or named pipe, authenticated) | Medium |
| `policyd` | Policy engine: permissions, capability tokens, taint tracking, approvals, audit log | High, minimal privileges, separate user where possible |
| `workers` | Short-lived sandboxed executors that run individual tools | Low |
| `ui` | Tauri + React desktop app (client of the daemon) | Medium |
| `mcp-server`, `cli` | Other clients of the same daemon API | Medium |
| `relay client` | Outbound connection for phone remote control | Medium |

The model process and `daemon` cannot write to policy files, approvals or audit logs. Approvals come only from the UI or the paired phone, never from model output.

## 3. Request flow

1. Input (text, voice, phone) reaches the Input Processor.
2. The Agent Runtime builds a plan using the Model Gateway and available skills.
3. For each step the runtime asks the Tool Registry for a typed tool call.
4. `policyd` checks the call against permission level, capability token (including the `network` flag — network calls are denied on tokens without it, ADR-006), taint state and user approval rules. Each approval is bound to one exact call: the same tool, the same level and the same arguments (ADR-005).
5. If allowed, a sandboxed worker executes the tool through an OS adapter.
6. The tool's `verify()` reads real system state. The result (success, failure, evidence) goes back to the runtime and into the audit log.
7. The runtime recovers, escalates or reports to the user.

## 4. Computer-control layer

Action hierarchy (try in order):

1. Direct program state, CLI and APIs (shell, git, file APIs, app APIs, MCP tools).
2. Native accessibility APIs (Windows UI Automation, Linux AT-SPI, macOS AXUIElement).
3. Browser DOM automation (Playwright).
4. Vision and screenshot grounding.
5. Raw coordinate mouse and keyboard as the last resort.

Every tool declares `execute()` and `verify()`. Verification reads actual state (file hash, process list, command output, window title), never the model's claim.

Platform notes: Windows is the suggested MVP target. macOS needs Accessibility and Screen Recording permissions granted per binary. Linux X11 is straightforward; Wayland needs xdg-desktop-portal with a one-time user prompt and not every compositor supports it, so publish a supported-desktop matrix.

## 5. Safety architecture

### Permission levels

| Level | Scope | Default policy |
|---|---|---|
| 0 | Read and inspect | Allowed within scope |
| 1 | Basic interaction (open apps, navigate, keyboard and mouse) | Allowed within scope |
| 2 | Controlled modifications (create, edit, move files in authorized folders) | Allowed in scope, logged, reversible where possible |
| 3 | Sensitive (delete important files, install software, change settings) | Explicit approval |
| 4 | High risk (admin commands, security config, money, bulk data transfer) | Strong approval or blocked |

### Mechanisms

- **Capability tokens:** each task gets a short-lived, scoped token (folders, apps, tools, network, duration). The `network` flag is enforced, not just carried: a network call on a token without it is denied (ADR-006, R-014).
- **Taint tracking:** content from outside (web, email, PDF, skill text, tool output derived from them) is untrusted. While untrusted data is in context, Level 3+ tools and outbound network are locked or need approval.
- **Sandbox option:** run the agent in a separate OS user, container, VM or virtual desktop session.
- **Egress control:** default-deny network for the agent; allowlist model endpoints and the relay.
- **Secrets:** OS keychain only. The agent never sees raw keys; the gateway attaches them.
- **Screen privacy:** block or blur password managers, banking and private windows, especially before any image leaves the machine.
- **Kill switch and indicator:** global hotkey, tray, CLI and phone button; visible indicator while the agent has control; read-only mode.
- **Audit log:** append-only, hash-chained: tool calls, arguments, permission decisions, results, model used.
- **Undo:** trash instead of delete, snapshots before modification, operation journals.

## 6. Model Gateway

Providers: Ollama, LM Studio, llama.cpp, vLLM, any OpenAI-compatible endpoint, optional cloud APIs. Third-party routers (for example LiteLLM or OmniRoute) work as OpenAI-compatible upstreams but are never required.

**Roles:** router/classifier, planner, executor, grounder (vision), verifier, summarizer. Each role can use a different model.

**Capability benchmark:** on connecting a model, test instruction following, JSON output, tool calling, planning, context handling, vision, error recovery and consistency; produce a report and a recommended profile (safe tasks only, supervised, full).

**Routing policy:**

- Local first for classification, simple tool calls, summaries and grounding.
- Escalate on repeated schema failures, loops, failed verification, high complexity or low confidence; show a cost estimate first unless pre-approved.
- Sensitivity labels (public, personal, secret): `policyd` decides which model may see which data. Secret data never goes to cloud.
- Daily and monthly budgets, per-provider quotas, fallback chains with circuit breakers, graceful local-only mode.
- Save tokens: prefer accessibility-tree text over screenshots, downscale images, summarize context, cache prompts.
- Compile solved tasks into deterministic scripts so repeat runs need no LLM.

Multi-user: accounts, per-user model pools and keys, shared home-server mode, role-based access, usage metering.

## 7. Remote control

Rule: no inbound ports, ever. Default bind is localhost.

- The laptop daemon connects outbound to a relay (self-hosted or hosted) or through the user's own Tailscale or WireGuard network.
- Pairing by QR code exchanges public keys; the channel is end-to-end encrypted (Noise or mutual TLS); the relay sees only ciphertext.
- Task mode first (send task, receive progress, approvals, result). Live view (WebRTC) later.
- Level 3 and 4 approvals happen on the phone with biometric or PIN.
- Short-lived sessions, device revocation, phone kill switch, replay protection, rate limits, audit of every remote command.

## 8. Skills

One folder per skill with a manifest: name, description, supported OS, required tools, declared permissions, workflows, input and output schema, error handling, verification steps, examples and tests.

Supply-chain rules: signed packages, pinned hashes, static analysis, permission diff on install and update, sandboxed execution, registry tiers (local, community, verified). Skill text is untrusted until verified. No public registry until signing, scanning and sandboxing exist.

## 9. Workflow recording

Record accessibility, DOM, file and process events rather than pixels. Generate parameterized scripts with robust selectors. Detect UI drift, stop on unexpected state, ask the user, optionally let a model repair the step. Never record passwords or secrets; destructive steps always need approval at replay time.

## 10. Memory, scheduler, voice

- **Memory:** local SQLite; preferences, project context, saved workflows; fully viewable, editable, exportable, deletable; no secrets.
- **Scheduler:** recurring and event-triggered tasks under the same policy engine and capability tokens as interactive runs.
- **Voice:** push-to-talk by default, microphone and wake word opt-in, Whisper.cpp and Piper locally, English first, then Hindi and Hinglish after testing on real recordings. Voice goes through the same policy path as text.

## 11. Evaluation

- Per-OS task suites verifying real state (open app, create or rename file, organize folder, git status, blocked delete, approved workflow).
- Metrics: completion rate, tool-call accuracy, recovery, verification accuracy, permission enforcement, cross-platform consistency, model compatibility.
- **Injection red-team suite:** malicious web pages, emails, PDFs, documents and skills; pass means the policy engine blocked the harmful action. Run on every release and publish results.
- Reference benchmarks: OSWorld and OSWorld 2.0 for capability, a safety-focused benchmark such as OS-Harm.

## 12. Technology candidates

Python for agent runtime and tools; Rust for policy engine, executor and relay client; Tauri + React for UI; SQLite; Pydantic and JSON Schema; Playwright; Whisper.cpp and Piper; MCP SDKs. These are candidates, to be validated against reliability, cross-platform support, performance, maintainability and licensing.

## 13. Build, reuse, delay

**Build:** policy engine, capability tokens, taint tracking, audit log, tool registry with `verify()`, policy-aware gateway, remote pairing and approvals, skill signing.

**Reuse or integrate:** Playwright, Whisper.cpp, Piper, MCP SDKs, Ollama and other runtimes, existing open GUI-grounding models and agents as optional backends, an existing router as an optional upstream.

**Delay:** public marketplace, live remote desktop, voice, additional OS adapters, training our own grounding model.

## 14. Planned repository layout

```text
/docs        vision, architecture, threat model, ADRs, research notes, risk register
/core        agent runtime, model gateway, scheduler
/policy      policy engine, capability tokens, taint tracking, audit log
/tools       tool definitions (JSON Schema) and implementations
/adapters    windows/ linux/ macos/ browser/
/skills      built-in skills with manifests and tests
/mcp-server  MCP interface
/cli         command-line client
/ui          Tauri + React app
/remote      relay client, pairing, approval protocol
/evals       task suite, red-team suite, model capability tests
```
