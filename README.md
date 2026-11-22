# OpenCobot

**Local-first, model-agnostic computer control for AI. Safe by design, verified by default.**

> **Status: Phase 0 (spec and design).** There is no runnable code yet. This repository currently holds the vision, architecture and safety model. Do not use anything here to control a real machine until a tagged release says it is ready.

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
| 1 | MVP on one OS: headless daemon, 20-30 core tools, separate policy process, capability tokens, audit log, kill switch, MCP server and CLI |
| 2 | Model gateway (roles, escalation, budgets, privacy labels), capability benchmark, desktop UI, approval UI |
| 3 | Phone remote (task mode), signed skills, scheduler, workflow-to-script compiler |
| 4 | Live view, voice (English, then Hindi and Hinglish), macOS and Linux adapters |
| 5 | Public skill registry, SDK, published red-team benchmark |

## Safety notice

Software that can click, type and run commands on your computer is powerful and risky. Read [SECURITY.md](SECURITY.md) before running anything, and start in read-only mode once it exists.

## Contributing

Humans and AI coding agents are both welcome, under the same rules. Read [AGENTS.md](AGENTS.md) first. Security-sensitive areas (`/policy`, `/remote`, skill signing, permissions) always need human review.

## License

[MIT](LICENSE).
