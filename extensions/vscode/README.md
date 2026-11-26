# OpenCobot VS Code extension (thin client)

Drive the local OpenCobot daemon from VS Code: run an orchestrator
task in the open workspace, and show the last run's status. That is
all it does — the daemon plans, verifies and integrates; this
extension only asks and displays.

## Install

No marketplace release yet. Manual install:

```sh
cp -r extensions/vscode ~/.vscode/extensions/opencobot-0.1.0
# then reload VS Code (Developer: Reload Window)
```

Packaging a `.vsix` later uses `npx @vscode/vsce package` from this
directory (`vsce` is not vendored here).

## Use

- Command Palette → **OpenCobot: Run orchestrator task** — prompts
  for the task, runs it in the open workspace folder, prints the
  run summary (integrated / done / failed / queued /
  needs_approval) to the `OpenCobot` output channel. A run can take
  minutes; do not start a second run for the same task while one is
  going — if the request times out, the run still completes
  server-side; check the last run instead.
- Command Palette → **OpenCobot: Show last orchestrator run** —
  the stored summary for the open workspace's project.

## Setup

The daemon must be running (`opencobot daemon start`, or the
daemon started by the CLI). The extension reads the daemon token
from `<state-dir>/daemon.auth` and talks to the daemon over its
Unix socket (Linux/macOS) or named pipe (Windows). State dir:
`$OPENCOBOT_STATE`, else `~/.opencobot`, or the
`opencobot.stateDir` setting.

## What it does NOT do

No model calls, no file writes, no policy decisions, no network.
If a file must change, the orchestrator run does it through the
daemon and `policyd` — the extension never writes workspace files
itself. See `docs/IDE_API.md` for the full protocol contract.

## Porting to another IDE

`client.js` is the portable part: Node stdlib only, no `vscode`
dependency, unit-tested in plain Node
(`node --test test/client.test.js`). Another IDE ports those ~150
lines (framing + auth + the three orchestrator calls); `extension.js`
is only the VS Code glue and is not portable by design.
