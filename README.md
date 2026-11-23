# OpenCobot

**Local-first, model-agnostic computer control for AI. Safe by design, verified by default.**

> **Status: Phase 2 — in progress on branch `agent/phase2-gateway`, not merged. Phase 1 (Linux MVP) is merged.**
> The Phase 0 spec and design are complete. Phase 1 adds runnable Linux code: a headless daemon, a separate policy process (`policyd`), 22 tools with `execute()` + `verify()`, capability tokens, a hash-chained audit log, a kill switch, an MCP server and a CLI. Phase 2 adds a policy-aware model gateway (roles, hybrid local/cloud routing, budgets, circuit breakers), generic CLI-model providers (opencode, kiro-cli, gpt cli, Amazon Q CLI, OpenCode, …), a capability benchmark, read-only mode and a simple localhost web UI. There is still no tagged release — do not use anything here to control a real machine until a tagged release says it is ready. See [docs/DECISIONS_LOG.md](docs/DECISIONS_LOG.md) (ADR-001 Linux-first, ADR-002 Python-only policy, ADR-003 Tauri deferred / web UI first, ADR-004 CLI providers + hybrid routing) and [docs/GATEWAY.md](docs/GATEWAY.md) for the routing matrix.

## Quick start (Linux, Phase 1)

Requires Python 3.10+ (3.12 tested). No model, no API key and no Docker needed — the tool engine, policy and audit log all work with no LLM running.

```bash
python3 -m venv .venv-opencobot
.venv-opencobot/bin/pip install -r requirements.txt
.venv-opencobot/bin/python -m pytest -q          # full test suite
.venv-opencobot/bin/python -m cli.opencobot_cli doctor
.venv-opencobot/bin/python -m cli.opencobot_cli tools list
.venv-opencobot/bin/python -m cli.opencobot_cli tool run list_dir --args-json '{"path": "."}'
```

Start the policy engine and daemon (Unix sockets under `~/.opencobot/`, localhost only, no network port):

```bash
.venv-opencobot/bin/python -m cli.opencobot_cli daemon start
.venv-opencobot/bin/python -m cli.opencobot_cli daemon status
.venv-opencobot/bin/python -m cli.opencobot_cli audit verify
.venv-opencobot/bin/python -m cli.opencobot_cli kill   # kill switch: blocks the next tool call
```

MCP server (stdio, for MCP-compatible clients):

```bash
.venv-opencobot/bin/python mcp-server/server.py
```

Level 3 tools (for example `run_command`, `delete_to_trash`) need an explicit human approval — use `policy check` / the CLI approval flow; approvals never come from model output. `delete_to_trash` never hard-deletes. On a headless server `screenshot` and `list_windows` honestly report "unavailable" instead of faking success. The Windows adapter is a stub in Phase 1 (ADR-001).

## Phase 2 — gateway, CLI models, benchmark, read-only, web UI

Any model that runs in a CLI can power OpenCobot — opencode, kiro-cli, gpt
cli, Amazon Q CLI, OpenCode — as well as HTTP providers (Ollama, LM Studio,
llama.cpp, vLLM, OpenAI-compatible, optional cloud). Cloud is optional: a
cloud provider works only if you configure it; secret data never leaves the
machine. Full routing matrix, provider config and benchmark details:
[docs/GATEWAY.md](docs/GATEWAY.md).

```bash
.venv-opencobot/bin/python -m cli.opencobot_cli gateway providers
.venv-opencobot/bin/python -m cli.opencobot_cli benchmark --provider opencode
.venv-opencobot/bin/python -m cli.opencobot_cli benchmark --provider ollama-local --json
.venv-opencobot/bin/python -m cli.opencobot_cli readonly on    # observe-only mode
.venv-opencobot/bin/python -m cli.opencobot_cli ui start       # simple web UI on 127.0.0.1
```

The web UI (localhost only, daemon token required) shows status, tools,
approvals, the audit log, gateway providers, benchmark reports, a read-only
toggle and the kill switch. The Tauri desktop app is deferred to a later
phase (ADR-003).

## What is OpenCobot?

A *cobot* is a collaborative robot, built to work safely next to people. OpenCobot aims to be the same for your computer: an open-source platform that lets any AI model (local first, cloud optional) operate Windows, Linux and macOS through natural language and voice, while a safety layer that the model cannot override stays in charge.

OpenCobot separates three things that most agent projects mix together:

1. **Intelligence**: any model you choose (Ollama, llama.cpp, LM Studio, vLLM, any OpenAI-compatible endpoint, optional cloud APIs).
2. **Capability**: typed, verifiable tools and skills exposed through MCP, a CLI and a local API.
3. **Safety**: a separate policy engine that decides what is allowed, independent of the model.

## Why another computer-use agent?

Good open projects already exist (for example OpenComputer, opendesk, Agent S, UI-TARS, Open Interpreter). MCP, record and replay, scheduling and local vision models are becoming common. OpenCobot focuses on what is still missing:

- **Enforced, model-independent safety.** The model proposes; it never authorizes. Capability tokens, taint tracking for untrusted content, a separate low-privilege policy process, tamper-evident audit logs.
- **Verified execution.** Every tool checks real system state (file exists, process running, command output). The agent never reports success on its own word.
- **Policy-aware multi-model router.** Use local models for most work and escalate hard steps to cloud models, by capability, cost, quota and data sensitivity. Secret data never leaves the machine.
- **Safe remote control.** Control your laptop from your phone through an outbound-only, end-to-end encrypted channel. No open inbound ports, approvals on the phone.
- **Signed, sandboxed skills.** Skills declare permissions and are verified before they run.

## Principles

Open source and community driven. Local-first and privacy focused. No mandatory API or subscription. Windows, Linux and macOS. Model independent. Modular and extensible. Security enforced outside the model. Verified execution. Friendly for non-technical users.

## Architecture at a glance

```text
User (text / voice / phone)
        |
   Agent Runtime  <-->  Memory
        |
   Model Gateway  -->  Local models | Optional cloud models
        |
   Tool Registry  -->  Policy Engine (separate process)
        |
   Sandboxed Execution Workers
        |
   OS Adapters (Windows | Linux | macOS | Browser)
        |
   Verification -->  Result
```

Details: [ARCHITECTURE.md](ARCHITECTURE.md). Decisions: [DECISIONS_LOG.md](docs/DECISIONS_LOG.md).

## Roadmap

| Phase | Goal |
|---|---|
| 0 | Threat model, permission spec, tool schema spec, audit log format, repo scaffolding and CI (docs only) |
| 1 | MVP on one OS: headless daemon, 20-30 core tools, separate policy process, capability tokens, audit log, kill switch, MCP server and CLI — **merged (Linux)** |
| 2 | Model gateway (roles, escalation, budgets, privacy labels), capability benchmark, desktop UI, approval UI — **in progress; Tauri desktop UI deferred (ADR-003), simple web UI + CLI-model providers instead (ADR-004)** |
| 3 | Phone remote (task mode), signed skills, scheduler, workflow-to-script compiler |
| 4 | Live view, voice (English, then Hindi and Hinglish), macOS and Linux adapters |
| 5 | Public skill registry, SDK, published red-team benchmark |

## Safety notice

Software that can click, type and run commands on your computer is powerful and risky. Read [SECURITY.md](SECURITY.md) before running anything, and start in read-only mode once it exists.

## Contributing

Humans and AI coding agents are both welcome, under the same rules. Read [AGENTS.md](AGENTS.md) first. Security-sensitive areas (`/policy`, `/remote`, skill signing, permissions) always need human review.

## License

[MIT](LICENSE).
