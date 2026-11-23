# cli/ — OpenCobot command-line client

Command-line client for the OpenCobot daemon (Phase 1, Linux MVP).
See [ARCHITECTURE.md §2](../ARCHITECTURE.md) and [SPEC.md §6, §15](../docs/SPEC.md).

## Install / run

No runtime dependencies (Python 3.10+ stdlib only). From the repo root:

```bash
# from a checkout
python -m cli.opencobot_cli --help
python -m cli                 # same thing

# after `pip install -e .` (console script, see ../pyproject.toml)
opencobot --help
```

State lives in `$OPENCOBOT_STATE` or `~/.opencobot` by default; override
per invocation with `--state-dir DIR`. Pass `--json` (before the
subcommand, or after most leaf subcommands) for machine-readable output.

## Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | OK — and for `tool run`, the result was verified |
| 1 | The action failed, was denied, or was not verified |
| 2 | Usage error, or the policy engine is unavailable |

## Commands

```bash
# Tools (no daemon needed)
opencobot tools list
opencobot tools list --json

# Run one tool through policy + runtime.
# Issues a 600s capability token scoped to the cwd (+ paths in --args-json),
# for this one tool only. Level 3+ tools need an explicit approval first:
# either `policy approve` for a task token, or --approve for this run
# (you, the human at the terminal, approving this one run).
opencobot tool run list_dir --args-json '{"path": "/tmp"}'
opencobot tool run read_file --args-json '{"path": "README.md"}'
opencobot tool run write_file --args-json '{"path": "/tmp/note.txt", "content": "hi"}'
opencobot tool run run_command --args-json '{"argv": ["echo", "hi"]}'   # denied: needs approval
opencobot tool run run_command --approve --args-json '{"argv": ["echo", "hi"]}'

# Daemon
opencobot daemon start
opencobot daemon status
opencobot daemon stop

# Policy (no execution)
opencobot policy check --tool run_command --level 3
opencobot policy check --tool list_dir            # level from the registry
opencobot policy approve --tool run_command --duration 600

# Capability tokens (prints token_id + expiry + scope only —
# never the token secret, never the policyd auth secret)
opencobot token issue --folders /home/you/work,/tmp --tools list_dir,read_file --duration 600

# Audit log (hash-chained, append-only)
opencobot audit verify
opencobot audit show --limit 20

# Kill switch
opencobot kill      # blocks all tool runs
opencobot unkill

# Environment check (exit 0 iff the essential checks pass;
# Ollama and the display server are informational only)
opencobot doctor
opencobot doctor --json
```

## How it works

* `tool run` first ensures `policyd` is running: if
  `<state-dir>/policyd.sock` is missing it starts
  `python -m policy.policyd --state-dir DIR` detached (log:
  `<state-dir>/policyd.log`) and waits up to 5s for the socket.
  While the real `policy.policyd` module is not installed yet, the
  in-process fallback policy engine is used instead and no separate
  process is started — the CLI says so in `doctor` output.
* The tool itself runs in this process via `core.runtime.Runtime`
  with the policy client; policy still lives in the separate
  `policyd` process when it exists.
* `daemon start` launches `python -m core.daemon --state-dir DIR`
  detached (PID file `<state-dir>/daemon.pid`, log
  `<state-dir>/daemon.log`); `daemon status` queries the daemon
  Unix socket with the auth token from `<state-dir>/daemon.auth`.
* `doctor` checks: Python ≥ 3.10, pytest available, state dir
  writable, policyd reachable, daemon reachable, Ollama reachable
  (`localhost:11434`, 1s timeout), display server present.
