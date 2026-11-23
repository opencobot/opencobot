# Windows laptop testing checklist

For Abhay (Windows laptop). The Windows adapter was built and
mock-verified on Linux only — this checklist is how it gets
live-verified. Work top to bottom; **paste the full failing output**
for anything that does not match "pass". Nothing here needs a cloud
account or API key.

Prerequisites: Windows 10/11, Python 3.12, Git, Ollama for Windows
([ollama.com](https://ollama.com)). All commands run in PowerShell
from the repo root. Call the venv Python directly
(`.\.venv-opencobot\Scripts\python.exe ...`) instead of activating
the venv — `Activate.ps1` can be blocked by a restrictive execution
policy.

## 1. Clone, venv, install

```powershell
git clone https://github.com/opencobot/opencobot.git
cd opencobot
git checkout agent/windows-adapter
py -3.12 -m venv .venv-opencobot
.\.venv-opencobot\Scripts\python.exe -m pip install -r requirements.txt
```

**Pass:** `pip install` finishes with no errors; `python --version`
inside the venv reports 3.12.x.

## 2. Windows tests (must pass)

```powershell
.\.venv-opencobot\Scripts\python.exe -m pytest tests/test_windows_adapter.py tests/test_windows_transport.py tests/test_windows_wiring.py tests/test_windows_pipe_server.py tests/test_doctor_windows.py -q
```

**Pass:** 102 passed (46 adapter + 17 transport + 17 wiring + 20 pipe-server + 2 doctor). These are the mock-based Windows tests; they
must be green on Windows too.

## 3. Full test suite (report, don't fix)

```powershell
.\.venv-opencobot\Scripts\python.exe -m pytest tests/ -q
```

**Pass (expected, not guaranteed):** the suite was written on Linux,
so Linux-only tests (Unix sockets, `/proc`, `DISPLAY`) may fail on
Windows. That is expected this round — **paste the failing test
names and the last 20 lines of output** and move on.

## 4. Adapter smoke test (works now — no policyd needed)

```powershell
.\.venv-opencobot\Scripts\python.exe -c "from adapters.windows.windows import safe_resolve, list_processes, system_info, list_windows_available; print(safe_resolve(r'C:\Users\Public', 'test.txt')); print(list_processes('explorer')[:2]); print(system_info()['windows_edition']); print(list_windows_available())"
```

**Pass:** prints a resolved `C:\Users\Public\test.txt` path, one or
two explorer processes, a Windows edition string (e.g.
`Microsoft Windows 11 Pro`), and `(True, 'PowerShell window query
works (N windows)')`. If `wmic` is missing on your build,
`windows_edition` may be `None` — report it, that is the guarded
fallback (R-019).

Also check the execution policy:

```powershell
Get-ExecutionPolicy -List
```

**Pass / report:** paste the table. The adapter runs `-Command`
strings, not script files, so policy should not block it — but a
GPO-locked policy is worth knowing about (R-015).

## 5. PowerShell hostile-input check (the quoting proof)

```powershell
.\.venv-opencobot\Scripts\python.exe -c 'from adapters.windows.windows import run_powershell; r = run_powershell(["Write-Output", "hello; $(whoami) `pwned`"]); print("rc=", r.returncode); print("out=", r.stdout.strip())'
```

(Note the outer single quotes: in PowerShell a single-quoted string
is literal, so `$(...)` and the backticks reach Python untouched —
with double quotes PowerShell itself would interpolate them first
and the check would prove nothing.)

**Pass:** `rc= 0` and `out= hello; $(whoami) `pwned`` — the
metacharacters come back as literal text. **Fail:** if the output
shows your username (meaning `$(whoami)` executed) or an error
other than a blocked-command refusal, stop and paste the output.

And the blocklist check:

```powershell
.\.venv-opencobot\Scripts\python.exe -c 'from adapters.windows.windows import run_powershell; run_powershell(["format", "C:"])'
```

**Pass:** `ValueError: blocked command: 'format'`.

## 6. Named-pipe server (ACL listener — live verification)

The `ctypes` listener with a current-user + Administrators DACL
landed in ADR-010 (R-017) and is mock-verified on Linux — this
section is what proves it on a real Windows host. Until this
section passes, the listener counts as implemented-but-unverified.

### 6a. `policyd` starts and stays up on the pipe

```powershell
.\.venv-opencobot\Scripts\python.exe -m policy.policyd --state-dir $env:USERPROFILE\.opencobot
```

**Pass:** stderr shows `listening on named pipe
\\.\pipe\opencobot-policyd` and the process **stays running**
(it used to exit immediately with `NotImplementedError` — that
was the old fail-closed behaviour, ADR-008). **Fail:** if it
exits at once, paste the full traceback — an ACL-build or
`CreateNamedPipeW` failure must refuse to start, never serve an
unprotected pipe, so the exact error matters. Leave this
`policyd` running for 6b; stop it with Ctrl+C afterwards.

### 6b. Same-user client connects; another user cannot

With `policyd` still running from 6a, in a second PowerShell
window from the repo root:

```powershell
.\.venv-opencobot\Scripts\python.exe -c "from policy.client import PolicyClient; from pathlib import Path; c = PolicyClient(Path($env:USERPROFILE) / '.opencobot'); print(c.status())"
```

**Pass:** prints a status dict (`{'ok': True, 'killed': False,
...}`) — the pipe, the DACL and the JSON-lines protocol all work
end to end for the user who started `policyd`.

Then the negative check (the DACL proof). If you have a second
local account on this machine, run the same one-liner as that
user (e.g. `runas /user:<other-user> ...` from an elevated
prompt, or Shift + right-click → "Run as different user" on a
PowerShell shortcut and paste the command there):

**Pass:** the connect fails with `cannot connect to named pipe`
(or an access-denied error) — the DACL grants only the user who
started `policyd` plus local Administrators, so any other
account gets no access. **Fail:** if the other user connects
successfully, stop and paste the output — that would mean the
pipe is effectively ACL-less. If you have no second account,
say so in your report and skip this check; the same-user
connect above plus the unit tests are the fallback evidence.

### 6c. Stopping `policyd` removes the pipe

Stop the `policyd` from 6a (Ctrl+C), then re-run the 6b
one-liner.

**Pass:** it fails with `cannot connect to named pipe` — no
stale pipe is left listening after the server stops.

> Note on step 9 below: it still says "expected to fail" — that
> was written when the pipe server was fail-closed (ADR-008).
> Now that the listener exists, re-run step 9 expecting success:
> `tool run` should complete instead of failing at the policyd
> step. If it still fails there, paste the exact error.

## 7. Ollama + gateway ping + benchmark

```powershell
ollama pull llama3.1:8b
ollama list
.\.venv-opencobot\Scripts\python.exe -m cli.opencobot_cli gateway providers --ping
```

**Pass:** `ollama list` shows `llama3.1:8b`; the ping reports
`ollama-local` available. Model sizes / RAM (approximate, Ollama
needs the model resident in RAM): `llama3.1:8b` ~5 GB,
`qwen2.5:7b` ~4–5 GB. If the laptop cannot spare that, use the
small fallback instead: `ollama pull qwen2.5:0.5b` (~0.5 GB) and
point the gateway at it — see the config-file note below.

```powershell
.\.venv-opencobot\Scripts\python.exe -m cli.opencobot_cli benchmark --provider ollama-local --model llama3.1:8b
```

**Pass:** a score per capability test and a recommended profile
(Linux live run with `qwen2.5:0.5b` scored 0.86, 6/7 — only
instruction-following failed on the tiny model). A bigger model
should score higher; paste the full report either way.

Config-file note: the default model is `llama3.1`. To use a
different model without code changes, create
`%USERPROFILE%\.config\opencobot\gateway.json` (or set
`$OPENCOBOT_GATEWAY_CONFIG` to its path) — see
[docs/GATEWAY.md](GATEWAY.md) §"Gateway config file". The CLI
also takes a one-run `--model` override.

## 8. `opencobot doctor`

```powershell
.\.venv-opencobot\Scripts\python.exe -m cli.opencobot_cli doctor
```

**Expected:** the python / pytest / state-dir checks print PASS, and
the `policy boundary` check reports INFO — "unavailable on Windows
(no os.getuid): same-user identity check skipped". `doctor` no longer
crashes on Windows: the identity check is skipped there because
`os.getuid` has no Windows equivalent. `policyd` is still reported
FAIL — that is the known gap of this round (named-pipe server,
step 6), not a setup mistake on your side — so expect exit code 1
until policyd starts. Do not treat this as "the install is broken":
steps 2, 4, 5 and 7 above are the real verification.

## 9. Live task via the CLI (expected to fail this round)

```powershell
.\.venv-opencobot\Scripts\python.exe -m cli.opencobot_cli tool run list_dir --args-json '{"path": "."}'
.\.venv-opencobot\Scripts\python.exe -m cli.opencobot_cli tool run run_command --args-json '{"argv": ["Write-Output", "hello windows"]}' --approve
```

**Expected:** both fail at the policyd step (`policyd did not
start`) because the named-pipe server is fail-closed (step 6).
That is the known blocker, not a setup error. **Paste the exact
error** — it confirms the failure mode. A direct adapter-level
`run_command` already works (step 5); the end-to-end CLI path
needs the `ctypes` pipe listener first.

Until that lands, the closest live end-to-end check is the
in-process tool call (no policyd involved):

```powershell
.\.venv-opencobot\Scripts\python.exe -c "from tools.definitions import get_tool; t = get_tool('list_dir'); print(t.execute({'path': '.'}, {'workdir': '.'})['data'].keys())"
```

**Pass:** prints the `list_dir` result keys with real entries
from the repo root.

## What to report back

For each step: step number, PASS/FAIL, and the pasted output for
anything unexpected — especially the `doctor` output if the
policy-boundary check is anything other than the expected INFO skip
(step 8), the `tool run` error (step 9), the execution-policy table (step 4),
and any full-suite failures (step 3). Also report: Windows
version/edition, Python version, Ollama model used, and available
RAM.
