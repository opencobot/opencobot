"""Shared fake-CLI fixtures for CLI-provider tests.

The fake scripts stand in for opencode / q / gpt / custom-cli. Each
fake is written twice -- a #!/bin/sh body for POSIX and a .bat body
for Windows -- and ``write_cli_fake`` writes the twin for the current
platform, so the same tests run on both (a #!/bin/sh script fails on
Windows with WinError 193: CreateProcess cannot run a text file).

Batch notes (Windows): only cmd.exe builtins may be used in the
bodies (echo, type, set, for, rem, exit) -- the child environment is
scrubbed (R-010), so external commands (find, timeout, ping) do not
resolve. ``%*`` keeps the quotes cmd.exe put around each argument.
Bodies echo them via ``!ARGS!`` (delayed expansion): it expands AFTER
cmd.exe parses the line, so metacharacters in an argument (& | < > ^)
are literal data and can never become a second command -- the old
preamble stripped the quotes (``%ARGS:"=%``) and a hostile argument
like ``hello & whoami`` really executed ``whoami`` (laptop round 4).
Quotes are stripped by delayed-expansion substitution
(``!ARGS:"=!``, also post-parse, so the stripped value is never
re-parsed) so the echoed output matches the POSIX twin exactly.
Bodies that need one argument re-quote it ("%1").
"""

from __future__ import annotations

import sys
from pathlib import Path

# Batch preamble: capture the raw argument string (%*, quotes intact)
# into %ARGS%, then strip the quotes with delayed-expansion
# substitution. Both the substitution and the !ARGS! expansion in
# bodies happen AFTER cmd.exe parses the line, so a metacharacter in
# an argument is never re-parsed as a command separator. Never go back
# to %ARGS:"=% (percent-expansion stripping) or %ARGS% (percent
# expansion): both re-expose & and | to cmd.exe execution.
# NOTE the capture line has NO quotes around ARGS=: cmd.exe pairs
# quotes left-to-right, so `set "ARGS=%*"` with a quoted metachar
# argument (`"hello & whoami"`) pairs `"ARGS=` with `"hello`, leaving
# ` & whoami` outside quotes during line parsing -- whoami really
# executes (laptop round 5). %* is already quoted by
# _batch_command_line, so `set ARGS=%*` keeps the argument's own
# quotes paired correctly and the & stays inside them.
_WINDOWS_PREAMBLE = (
    "setlocal EnableDelayedExpansion\n"
    "set ARGS=%*\n"
    'set ARGS=!ARGS:"=!\n'
)


def write_cli_fake(bin_dir: Path, name: str, sh_body: str, bat_body: str) -> Path:
    """Write the fake CLI for the current platform; return its path.

    POSIX: ``name`` with a ``#!/bin/sh`` body, 0755. Windows:
    ``name.bat`` with an ``@echo off`` body, 0755 (the exec bit is
    meaningless on Windows but lets the Windows resolution path --
    shutil.which + PATHEXT -- be exercised on Linux by patching
    sys.platform). The returned path is what an absolute-path
    ``cli_binary`` would point at.
    """
    if sys.platform == "win32":
        path = bin_dir / f"{name}.bat"
        path.write_text("@echo off\n" + _WINDOWS_PREAMBLE + bat_body,
                        encoding="utf-8")
        path.chmod(0o755)
        return path
    path = bin_dir / name
    path.write_text("#!/bin/sh\n" + sh_body, encoding="utf-8")
    path.chmod(0o755)
    return path
