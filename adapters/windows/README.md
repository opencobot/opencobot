# adapters/windows/

Windows adapter — real implementation in `windows.py`, mirroring
`adapters/linux/linux.py` function for function so the wiring layer
(`tools/definitions.py`, per-call `_is_windows()` / `_os_adapter()`
dispatch) can use either adapter identically. Stdlib only; no new
dependencies. No Windows-only API is called unguarded on a non-Windows
host, so the module imports and its pure path logic is testable on
Linux (see `tests/test_windows_adapter.py`,
`tests/test_windows_transport.py`, `tests/test_windows_wiring.py` —
80 Windows tests, mock-verified on Linux).

**Verification status: mock-verified on Linux only. Nothing here is
live-verified on Windows yet.** The laptop checklist is
[docs/WINDOWS_TESTING.md](../../docs/WINDOWS_TESTING.md). See also
ADR-008 in [docs/DECISIONS_LOG.md](../../docs/DECISIONS_LOG.md) and
risks R-015–R-019 in [docs/risks.md](../../docs/risks.md).

## What works (mock-verified on Linux)

- `safe_resolve` — Windows semantics: drive letters, UNC paths,
  backslashes, case-insensitive containment, `~` expansion to the user
  profile, lexical `..` collapsing plus symlink/junction/8.3 resolution
  via `os.path.realpath` on a real Windows host (injectable `resolver`
  seam for tests).
- `read_text` / `write_text` / `sha256_file` — same semantics as Linux.
- `trash_path` — state-dir trash (see below), never a hard delete.
- `list_processes` — parses `tasklist /FO CSV /NH`.
- `system_info` — `platform` + `sys.getwindowsversion` + `wmic`
  parsing, all guarded with `None` fallbacks (see wmic note below).
- `list_windows` / `list_windows_available` — PowerShell
  `Get-Process | Where-Object {$_.MainWindowTitle}`.
- `run_powershell` — argv-only PowerShell execution (see rules below).
  `run_command` on Windows goes through it; `git` tools resolve
  `git.exe` via `shutil.which` (explicit `git.exe` first).

## What is deferred (honest limits)

- **Screenshots:** `screenshot_available()` returns `(False, reason)`.
  Capture needs UI Automation / the Windows Graphics Capture API and
  is deferred. It is never faked (R-018).
- **Recycle Bin:** `trash_path` uses the state-dir trash pattern (same
  as the Linux fallback). Real Recycle Bin integration
  (`SHFileOperation` / `IFileOperation`) is a later step.
- **Secrets:** Windows Credential Manager storage (SPEC §6) is **not**
  implemented this round. Do not put secrets in the adapter or in
  tool arguments.
- **Named-pipe server:** the client transport exists, but the server
  (`core.transport.NamedPipeListener`) fails closed with
  `NotImplementedError` until a `ctypes` `CreateNamedPipeW` listener
  with a current-user-only DACL lands (R-017). `policyd` therefore
  refuses to serve on Windows, so end-to-end `tool run`, `daemon
  start` and `doctor` are blocked this round — the adapter functions
  themselves work when called directly (see the smoke test in
  `docs/WINDOWS_TESTING.md`).
- **`process_info` / `launch_app`:** still Linux-shaped (`/proc`,
  `start_new_session`); on Windows they fail cleanly via the tool
  guard and need a Windows process API later.
- **Windows CLI:** `cli/opencobot_cli.py` still hard-codes
  `daemon.sock`; the Windows CLI path (named-pipe daemon address) is
  a later step.
- **`ctypes` fallbacks** for process/window listing (Toolhelp32 /
  `EnumWindows`) are design notes in the module docstring only, not
  implemented this round.

## Install / run on Windows

Requires Python 3.12 (project minimum is 3.10; 3.12 is what is
tested) and Git. No new dependencies — stdlib only.

```powershell
git clone https://github.com/opencobot/opencobot.git
cd opencobot
py -3.12 -m venv .venv-opencobot
.\.venv-opencobot\Scripts\python.exe -m pip install -r requirements.txt
.\.venv-opencobot\Scripts\python.exe -m pytest tests/test_windows_adapter.py tests/test_windows_transport.py tests/test_windows_wiring.py -q
```

Call the venv Python directly (as above) instead of activating it:
`Activate.ps1` is a script, so a restrictive execution policy can
block it — the direct path avoids that trap. Full laptop checklist,
including Ollama and the live-model steps:
[docs/WINDOWS_TESTING.md](../../docs/WINDOWS_TESTING.md).

## PowerShell rules

`run_powershell(argv)` builds exactly:

```text
powershell.exe -NoProfile -NonInteractive -Command "& '<arg1>' '<arg2>' ..."
```

- **Argv only, never a shell string.** No `shell=True`, never
  `cmd.exe`. The OS never re-splits the command.
- **Quoting:** every argument is wrapped in PowerShell single quotes;
  a single quote inside an argument is escaped by doubling it
  (`'` → `''`). Single-quoted strings are literal in PowerShell — no
  variable expansion, no backtick escapes. The `&` call operator is
  required because a quoted command name would otherwise be a string
  literal, not an invocation.
- **Consequence:** an argument containing `;`, `|`, `$()`, backticks
  or quotes stays literal data. The hostile-input check in
  `docs/WINDOWS_TESTING.md` verifies this on the laptop.
- **Blocklist (defence-in-depth, enforced in the adapter and again in
  the tool layer):** unconditional `WINDOWS_BLOCKED_COMMANDS` —
  `sudo`, `su`, `doas`, `rm` (parity) plus `format`, `diskpart`,
  `bcdedit`, `del`, `erase`, `takeown`, `powershell`, `pwsh`, `cmd`
  (compared case-insensitively, `.exe` stripped) — and conditional
  blocks: `reg delete`, `shutdown /r /s /g /h /p /l`, `rmdir /s`,
  `icacls /grant /deny /remove /setowner /reset /inheritance`.
  The policy engine still gates `run_command` at Level 3 + approval
  (ADR-005/ADR-006); the blocklist is a second layer, not a
  replacement.
- **Execution policy (R-015):** the adapter runs a `-Command` string,
  not a script file, so script-file policy does not apply — but check
  the effective policy on the laptop anyway
  (`Get-ExecutionPolicy -List`); a GPO-locked policy may still
  interfere. Do not weaken the host policy to make OpenCobot work.

## Named-pipe transport + ACL requirement

`policyd` and the daemon speak the same JSON-lines protocol on both
transports (`core/transport.py`): one JSON object per line, auth token
per request. On Windows the addresses are
`\\.\pipe\opencobot-policyd` and `\\.\pipe\opencobot-daemon`.

- The **client** side (`NamedPipeTransport`, stdlib `open` in `r+b`
  mode) is implemented.
- The **server** side (`NamedPipeListener`) is shape-only and fails
  closed: the stdlib cannot create a named pipe with a restrictive
  ACL, and an ACL-less pipe would let any local process talk to
  `policyd` (SECURITY.md adversary 5). The real listener must use
  `ctypes` `CreateNamedPipeW` with a `SECURITY_ATTRIBUTES` whose DACL
  allows only the current user's SID, then `ConnectNamedPipe` /
  `ReadFile` / `WriteFile` / `DisconnectNamedPipe` per connection,
  speaking the same JSON-lines framing. It must be verified on a real
  Windows host before `policyd`/the daemon serve on Windows (R-017).

## Other Windows notes

- **PATH spoofing (R-016):** `git.exe` and `powershell.exe` are found
  via `shutil.which`, so a malicious binary earlier on PATH wins.
  Keep PATH trusted; pinning absolute paths in config is a later
  step. Same residual as R-012 for CLI-model providers.
- **wmic deprecation (R-019):** `wmic` is deprecated/removed on newer
  Windows builds. `system_info` treats a missing `wmic` as `None`
  for those fields instead of crashing; CIM / `Get-CimInstance` is
  the later replacement.
- **State dir:** `~/.opencobot` (`%USERPROFILE%\.opencobot`); the
  gateway config file is `~/.config/opencobot/gateway.json`
  (`%USERPROFILE%\.config\opencobot\gateway.json`, or
  `$OPENCOBOT_GATEWAY_CONFIG`) — see
  [docs/GATEWAY.md](../../docs/GATEWAY.md).

## Needs a Windows laptop to verify

Everything above was verified on Linux with mocks/fakes only. On a
real Windows host, verify (full checklist in
[docs/WINDOWS_TESTING.md](../../docs/WINDOWS_TESTING.md)):

1. `safe_resolve` against real symlinks, junctions and 8.3 short
   names.
2. `tasklist` / `wmic` / PowerShell output parsing against live
   output; `Get-ExecutionPolicy -List`.
3. `run_powershell` quoting against arguments with spaces, quotes,
   `;`, `$()` and backticks — they must stay literal.
4. `list_windows_available()` returns True and lists real titled
   windows.
5. The named-pipe smoke test: the listener refuses to start
   (`NotImplementedError`) — fail-closed proof.
6. `opencobot gateway providers --ping` and the capability benchmark
   against a live Ollama model.
