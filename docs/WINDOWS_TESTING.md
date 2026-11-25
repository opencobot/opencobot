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

## Recording a test run (do this for every run)

`evals/record_run.py` runs the suite and writes a results file with
measured output only — OS and Python version, git commit and whether
the tree was dirty, the exact command, pass/fail/skip counts, the
failed and skipped tests with reasons, duration, and who ran it.
Never hand-edit a results file; re-run the tool to regenerate it.
`docs/STATUS.md` only counts a "tested" claim when it links to one
of these files.

```powershell
# Windows (PowerShell, repo root):
.\.venv-opencobot\Scripts\python.exe -m evals.record_run --by human
```

```bash
# Linux:
.venv-opencobot/bin/python -m evals.record_run --by human
```

The file lands in `docs/test-results/<YYYY-MM-DD>-<os>-<shortsha>.md`
— commit it with your run. A chat message saying "it passed" is not
evidence; the committed file is.

## 1. Clone, venv, install

```powershell
git clone https://github.com/opencobot/opencobot.git
cd opencobot
git pull
git log --oneline -1
py -3.12 -m venv .venv-opencobot
.\.venv-opencobot\Scripts\python.exe -m pip install -r requirements.txt
```

**Pass:** `pip install` finishes with no errors; `python --version`
inside the venv reports 3.12.x; `git log --oneline -1` shows
`f119660` or newer — everything (Windows adapter, pipe server,
doctor fix, CI fix) is on `main` now. Do **not** check out the old
`agent/windows-adapter` branch: it was deleted after its PR merged,
and it predates the pipe server and doctor fixes.

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
`os.getuid` has no Windows equivalent. The `policyd` check reports
FAIL only while `policyd` is not running — that just means it is not
up yet, not that the install is broken: start it (step 6) and re-run
`doctor`. Do not treat a policyd FAIL with no server running as
"the install is broken": steps 2, 4, 5 and 7 above are the real
verification.

## 9. Live task via the CLI (should succeed now)

```powershell
.\.venv-opencobot\Scripts\python.exe -m cli.opencobot_cli tool run list_dir --args-json '{"path": "."}'
.\.venv-opencobot\Scripts\python.exe -m cli.opencobot_cli tool run run_command --args-json '{"argv": ["Write-Output", "hello windows"]}' --approve
```

**Pass:** both commands complete — the named-pipe server landed in
PR #8, so the end-to-end CLI path is unblocked now. This step used
to say "expected to fail" when the pipe server was fail-closed
(ADR-008); that no longer applies. If either command still fails
at the policyd step, **paste the exact error** — that is the one
failure worth chasing. A direct adapter-level `run_command` already
works (step 5).

Extra check, no policyd involved — the in-process tool call:

```powershell
.\.venv-opencobot\Scripts\python.exe -c "from tools.definitions import get_tool; t = get_tool('list_dir'); print(t.execute({'path': '.'}, {'workdir': '.'})['data'].keys())"
```

**Pass:** prints the `list_dir` result keys with real entries
from the repo root.

## 10. Behaviours only a human run can prove

Automated tests (even the mock-based Windows tests in step 2) cannot
prove the items below — they need a real Windows host, a real user
session and real processes. Fill in each box from your run and commit
the results file from the recording section above alongside it.

- [ ] **Real named-pipe ACL behaviour** — the different-user
  negative check in §6b (another local account must NOT connect).
  Result: _NOT RUN (different-user check skipped: second local account `Ayush` exists in `Get-LocalUser`, alongside current user `Ayush Kumar`, disabled `Administrator`/`Guest`, and `CodexSandbox*` accounts, but no password is available to run non-interactive `runas /user:Ayush` in this automated session). Same-user §6b connect PASSED: `PolicyClient.status()` -> `{'killed': False, 'socket': '\\\\.\\pipe\\opencobot-policyd', 'audit_entries': 15}`; live pipe DACL SDDL via `GetSecurityInfo`: `D:(D;;0x12019f;;;SU)(A;;0x12019f;;;S-1-5-21-683957593-4088474031-550077339-1001)(A;;0x12019f;;;BA)`; §6c after stopping `policyd`: `cannot connect to named pipe: \\.\pipe\opencobot-policyd`._
- [x] **PowerShell tool execution** — §5 hostile-input check
  (metacharacters stay literal) and the blocklist check
  (`format` refused).
  Result: _PASS — `run_powershell(["Write-Output", "hello; $(whoami) `pwned`"])` -> `rc=0 out='hello; $(whoami) `pwned`'` (literal, `whoami` did not execute); `run_powershell(["format", "C:"])` -> `ValueError: blocked command: 'format'`._
- [x] **Daemon start / stop / status over the named pipe** — §9 and
  `daemon start` → `daemon status` → `daemon stop` → `daemon
  status` (see `docs/STATUS.md` daemon row).
  Result: _PASS — `daemon start` rc=0 (pid 24872, pipe `\\.\pipe\opencobot-daemon`); `daemon status` while up rc=0 (`daemon running (pid 24872)`); `daemon stop` rc=0 (`daemon stopped (pid 24872)`); after stop, running server procs `(none)` — both the `.venv` launcher (24872) and its child `C:\Program Files\Python312\python.exe` (19240) terminated via `taskkill /T /F`; `daemon.pid` removed; `daemon status` after stop rc=1 `daemon not running`. Also §9 `tool run list_dir` and `tool run run_command --approve` both rc=0 (previously FAIL — fixed by PR #32)._
- [x] **Web UI session login** — `opencobot ui start`, open
  http://127.0.0.1:8765, sign in with `POST /login` (token in the
  body only), confirm the status page loads, then `POST /logout`
  and confirm the session is gone.
  Result: _PASS (login/status/logout) — `ui start` -> `rc=0 web UI started (pid 25128) at http://127.0.0.1:8765/`; unauth `GET /` -> HTTP `401` with login form; `POST /login` (token in form body, `Accept: text/html`) -> HTTP `200` at `/` (`OpenCobot — local status`, `opencobot_session` cookie set); `POST /logout` -> redirected to `/` HTTP `401` (login form); post-logout `GET /` -> HTTP `401`. `ui stop` now also fixed by PR #33 (confirmation run: `ui stop` rc=0, both the `.venv` launcher (25432) and child (23976) terminated, `ui.pid` removed, `ui status` rc=1 `web UI not running`, port 8765 stopped serving)._
- [x] **Kill switch** — with `policyd` running, `opencobot kill`,
  then a `tool run list_dir` must be denied ("kill switch
  active"); `opencobot unkill` must let it run again.
  Result: _PASS — `opencobot kill` rc=0 (`kill switch ON`); `tool run list_dir` while killed rc=1, denied (`"kill switch active"`); `opencobot unkill` rc=0 (`kill switch OFF`); `tool run list_dir` after unkill rc=0._

## What to report back

For each step: step number, PASS/FAIL, and the pasted output for
anything unexpected — especially the `doctor` output if the
policy-boundary check is anything other than the expected INFO skip
(step 8), the `tool run` output (step 9), the execution-policy table (step 4),
and any full-suite failures (step 3). Also report: Windows
version/edition, Python version, Ollama model used, and available
RAM. And commit the results file: a run without
`docs/test-results/<date>-windows-<shortsha>.md` does not count as
tested in `docs/STATUS.md`.
