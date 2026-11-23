# core/

Agent runtime, model gateway, daemon and memory (Phase 1, Linux MVP).

- `runtime.py` — `Runtime`: the plan → policy check → execute → verify → audit loop. Kill switch is checked first; a tool call succeeds only if `execute()` succeeds **and** `verify()` confirms real system state.
- `daemon.py` — headless daemon (`python -m core.daemon`): Unix-socket JSON-lines server, localhost only, auth token in `daemon.auth` (0600). Never falls back to in-process policy — if `policyd` is unreachable, `run_tool` fails closed.
- `memory.py` — `Memory`: local SQLite key/value store. Secrets are rejected (keys/values containing `secret`, `password`, `token`, `api_key` raise `ValueError`).
- `model_gateway.py` — `Gateway`: OpenAI-compatible client, Ollama default `http://localhost:11434`. Local-first routing; `secret` sensitivity never routes to a cloud provider. Budgets and fallback chains are implemented; no live model is required — a missing model returns `ok: False, "model unavailable"` instead of crashing.

See [ARCHITECTURE.md §2–3, §6, §10](../ARCHITECTURE.md) and [SPEC.md §6, §8](../docs/SPEC.md).
