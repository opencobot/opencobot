# Model Gateway — routing, CLI models, benchmark, read-only mode

Phase 2 (SPEC §8, ADR-003, ADR-004). The gateway routes model work to HTTP
providers (Ollama / LM Studio / llama.cpp / vLLM / any OpenAI-compatible
endpoint, plus optional cloud) **and** to any AI/model that runs in a CLI
(opencode, kiro-cli, gpt cli, Amazon Q CLI, OpenCode, …). Cloud providers are
**optional**: one is usable only if the user configures it. No cloud provider
is configured by default and no API key is read or stored by default.

## Routing / work-division matrix

The division is a real, testable table in `core/model_gateway.py`
(`DEFAULT_ROLE_ASSIGNMENT`, `ROUTING_TABLE`), config-overridable per role —
not just "local first, cloud fallback".

| Role / task | Default provider class | Why | Escalation trigger |
|---|---|---|---|
| ROUTER / classification | small local | cheap, latency-sensitive, prompts stay on-machine | none — fall back to another local provider |
| PLANNER / planning | strongest available | hardest reasoning step | high complexity, low confidence, schema-fail ×2, verification-fail, agent loop |
| EXECUTOR / simple tool calls | reliable local tool-caller | tool calls must be reliable + cheap | schema-fail ×2, agent loop |
| GROUNDER / grounding | vision / local | screenshots & UI trees stay on-machine | none — stays local |
| VERIFIER / verification | separate model or pure code check | must be independent of the model being checked | verification failure escalates the *task* (planner), not the verifier |
| SUMMARIZER / summaries | small local | cheap, often personal context | none — stays local |

### Sensitivity labels decide eligibility

| Label | May use |
|---|---|
| `secret` | local-only providers only, always (HTTP local or local-only CLI) |
| `personal` | local, plus user-approved cloud |
| `public` | any configured provider |
| anything else | fails closed as `secret` |

### Escalation rules

Escalate to cloud **only if** a cloud provider is user-configured **and** the
data is public/personal (never secret), when one of these happens:
JSON/schema fails twice, the agent loops, verification fails, task complexity
is high, or model confidence is low. A cost estimate is returned first unless
the escalation is pre-approved in config; without pre-approval a
cloud/cloud-backed call is **not** made — the gateway returns
`needs_approval: true` with the estimate instead.

Budgets (daily **and** monthly caps per provider), per-provider quotas,
circuit breakers (a failing provider is skipped for 60s, then retried) and
fallback chains apply per role. Budgets are checked **before** the model is
called. Compiled/deterministic workflows (no LLM on repeat runs) remain the
biggest token saver.

## CLI-model providers

Configured in the gateway config (see `core/cli_providers.py`,
`builtin_cli_config(name)`). A provider declares: binary name, argv template
(`{prompt}` placeholder), how the prompt is passed (stdin / argument / file),
how output is extracted (stdout or a JSON field), timeout, working directory,
and its egress class (`local-only` or `cloud-backed`).

Built-ins:

| Name | Binary | Egress (default) |
|---|---|---|
| `opencode` | `opencode` | local-only |
| `kiro` | `kiro` | local-only |
| `gpt` | `gpt` | local-only |
| `q` (Amazon Q CLI) | `q` | **cloud-backed** |
| `custom-cli` | user-supplied | local-only (set `cloud-backed` yourself if it talks to a cloud) |

Rules: argv arrays only, never `shell=True`; the binary comes from the user
config allowlist only — model output can never choose or alter the binary or
argv template; the prompt is passed as data, never as shell; CLI output is
untrusted/tainted data and goes through the same taint rules as any external
content. The built-in argv templates are plausible defaults, not verified
against real CLI versions — override `cli_argv_template` for your version.

Example (Python):

```python
from core.model_gateway import Gateway, ProviderConfig
from core.cli_providers import builtin_cli_config

gw = Gateway(configs=[
    builtin_cli_config("opencode"),
    builtin_cli_config("q"),
    ProviderConfig("ollama-local", "ollama",
                   "http://localhost:11434", "llama3.1"),
])
result = gw.complete("EXECUTOR", "list files in /tmp", "public")
```

## Capability benchmark

`core/benchmark.py` — on connecting a provider (HTTP or CLI), run 7 tests:
instruction following, structured JSON output, tool calling, multi-step
planning, context handling, error recovery, consistency. Output: per-test
pass/fail + score, total score 0–1, and a recommended automation profile:

| Total score | Recommended profile |
|---|---|
| < 0.50 | safe tasks only |
| < 0.80 | supervised |
| ≥ 0.80 | full |

```sh
opencobot benchmark --provider opencode
opencobot benchmark --provider ollama-local --json
python evals/benchmark_run.py          # mock providers, no model needed
```

Vision is not covered by this text-only benchmark yet; a separate vision
benchmark is needed once a grounder exists.

## Read-only mode

The daemon can run in read-only mode: the agent may observe and explain
(Level 0 tools only); Level 1+ tools are denied by the policy engine with
reason `"read-only mode"` and the denial is audit-logged. Default is OFF;
the flag is persisted and survives daemon restarts (an
`OPENCOBOT_READONLY` env var can override it temporarily — the persisted
file is the source of truth).

```sh
opencobot readonly on
opencobot readonly status
opencobot readonly off
```

Start in read-only mode for the first days of use (SPEC §5).

## Web UI

`opencobot ui start` serves a simple stdlib-only web UI on **127.0.0.1
only** (no inbound ports, ever), protected by the daemon auth token.
It shows status, tools, approvals (approve/deny), the audit log, gateway
providers, benchmark reports, a read-only toggle and the kill switch.
