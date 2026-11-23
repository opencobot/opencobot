# OpenCobot

**Local-first, model-agnostic computer control for AI. Safe by design, verified by default.**

> **Status: Phase 3 — Windows adapter landed on branch `agent/windows-adapter`, not merged. Phase 2 (gateway, CLI-model providers, benchmark, read-only mode, web UI) is merged. Phase 1 (Linux MVP) is merged.**
> The Phase 0 spec and design are complete. Phase 1 adds runnable Linux code: a headless daemon, a separate policy process (`policyd`), 22 tools with `execute()` + `verify()`, capability tokens, a hash-chained audit log, a kill switch, an MCP server and a CLI. Phase 2 adds a policy-aware model gateway (roles, hybrid local/cloud routing, budgets, circuit breakers), generic CLI-model providers (opencode, kiro-cli, gpt cli, Amazon Q CLI, OpenCode, …), a capability benchmark, read-only mode and a simple localhost web UI. Phase 3 adds the Windows adapter (`adapters/windows/windows.py`, mirroring the Linux adapter function for function, per-call dispatch in `tools/definitions.py`): PowerShell `run_command`, `tasklist` process listing, PowerShell window listing, Windows path handling — **mock-verified on Linux only (80 Windows tests); live verification on a Windows laptop is still pending, see [docs/WINDOWS_TESTING.md](docs/WINDOWS_TESTING.md)**. Deferred this round: screenshots / UI Automation (honestly unavailable), Recycle Bin (state-dir trash instead), Windows Credential Manager secrets, and the named-pipe server — the pipe listener fails closed until a `ctypes` ACL implementation lands, so `policyd` refuses to serve on Windows and end-to-end `tool run` / `daemon start` / `doctor` are blocked until then (ADR-008, risks R-015–R-019). There is still no tagged release — do not use anything here to control a real machine until a tagged release says it is ready. See [docs/DECISIONS_LOG.md](docs/DECISIONS_LOG.md) (ADR-001 Linux-first, ADR-002 Python-only policy, ADR-003 Tauri deferred / web UI first, ADR-004 CLI providers + hybrid routing, ADR-008 Windows adapter) and [docs/GATEWAY.md](docs/GATEWAY.md) for the routing matrix.

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

Level 3 tools (for example `run_command`, `delete_to_trash`) need an explicit human approval — use `policy check` / the CLI approval flow; approvals never come from model output. Each approval is bound to one exact call — the same tool, the same permission level and the same arguments (ADR-005) — so an approval for `echo 42` cannot be replayed for a different command. Capability tokens also carry a `network` flag (default off): a network call such as `run_command` with `curl` is denied unless the token was issued with `--network` (ADR-006). `delete_to_trash` never hard-deletes. On a headless server `screenshot` and `list_windows` honestly report "unavailable" instead of faking success. The Windows adapter was a stub in Phase 1 (ADR-001); the real adapter landed in Phase 3 (ADR-008) — mock-verified on Linux, live verification pending on a Windows laptop.

## Running policyd as a separate user

By default `policyd` and the daemon run as your user, so the policy boundary is a **same-user boundary, not a real OS boundary**: any process running as your UID can read the state dir (which is why it is locked down to `0700`, with the auth secret, audit log, approvals and sockets at `0600` — enforced on startup, and reported by `opencobot doctor`). For a real OS boundary, run `policyd` under a dedicated system user with its own state dir:

```bash
sudo useradd --system --home-dir /var/lib/opencobot --no-create-home opencobot
sudo mkdir -p /var/lib/opencobot
sudo chown opencobot:opencobot /var/lib/opencobot
sudo chmod 0700 /var/lib/opencobot
# Start policyd as that user (it listens on /var/lib/opencobot/policyd.sock):
sudo -u opencobot /path/to/opencobot/.venv-opencobot/bin/python \
  -m policy.policyd --state-dir /var/lib/opencobot
# Point the CLI / daemon at the same state dir:
opencobot --state-dir /var/lib/opencobot doctor
```

The state dir is tightened to `0700` on startup, so the CLI and daemon must run as the same `opencobot` user to reach the socket — run them with `sudo -u opencobot` too (or run the whole service, daemon + policyd, as that user). A group-shared state dir does not work with the current 0700 enforcement. See `docs/risks.md` (R-006) for exactly what is enforced and what still requires a separate user or container.

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

## Phase 3 — Windows adapter (mock-verified on Linux; live verification pending)

The Windows adapter is implemented (`adapters/windows/windows.py`) and
wired in via per-call dispatch in `tools/definitions.py`, so the same
22 tools run on Windows: PowerShell `run_command` (argv-only,
single-quote doubling, blocklist), `tasklist` process listing,
PowerShell window listing, Windows path handling (`safe_resolve` with
drive letters, UNC paths, case-insensitive containment). The named-pipe
client transport exists (`core/transport.py`); the pipe **server**
fails closed until a `ctypes` listener with a current-user-only ACL
lands, so `policyd` refuses to serve on Windows and end-to-end
`tool run` / `daemon start` / `doctor` are blocked this round.
Deferred: screenshots / UI Automation (honestly unavailable), Recycle
Bin (state-dir trash), Windows Credential Manager secrets,
`process_info` / `launch_app` (still Linux-shaped). Full status,
install steps and the laptop verification checklist:
[docs/WINDOWS_TESTING.md](docs/WINDOWS_TESTING.md) and
[adapters/windows/README.md](adapters/windows/README.md); decision
record ADR-008, risks R-015–R-019.

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
| 2 | Model gateway (roles, escalation, budgets, privacy labels), capability benchmark, desktop UI, approval UI — **merged; Tauri desktop UI deferred (ADR-003), simple web UI + CLI-model providers instead (ADR-004)** |
| 3 | **Windows adapter — landed on branch `agent/windows-adapter`, mock-verified on Linux (80 tests), live verification pending on a Windows laptop ([docs/WINDOWS_TESTING.md](docs/WINDOWS_TESTING.md), ADR-008)**; phone remote (task mode), signed skills, scheduler, workflow-to-script compiler — not started |
| 4 | Live view, voice (English, then Hindi and Hinglish), macOS and Linux adapters |
| 5 | Public skill registry, SDK, published red-team benchmark |

## Safety notice

Software that can click, type and run commands on your computer is powerful and risky. Read [SECURITY.md](SECURITY.md) before running anything, and start in read-only mode once it exists.

## Contributing

Humans and AI coding agents are both welcome, under the same rules. Read [AGENTS.md](AGENTS.md) first. Security-sensitive areas (`/policy`, `/remote`, skill signing, permissions) always need human review.

## License

[MIT](LICENSE).
