"""Windows OS adapter for OpenCobot.

Stdlib only. Mirrors :mod:`adapters.linux.linux` function for function so
the wiring layer can dispatch to either adapter identically.

Windows notes and honest limits (see also ``adapters/windows/README.md``):

* All path handling goes through :func:`safe_resolve`, which enforces
  containment on ``PureWindowsPath`` with case-insensitive comparison, so
  it is testable on Linux. Drive letters, UNC paths, backslashes and
  ``..`` traversal are all handled lexically (``ntpath.normpath``); on a
  real Windows host an injectable ``resolver`` (default: ``os.path.realpath``
  when ``platform.system() == "Windows"``) additionally resolves symlinks,
  junctions and 8.3 short names before the containment check. Windows-only
  APIs are never called unguarded on a non-Windows host.
* The Recycle Bin is not reachable from the stdlib, so :func:`trash_path`
  uses the same state-dir trash pattern as the Linux fallback. Real
  Recycle Bin integration (``SHFileOperation`` / ``IFileOperation``) is a
  later step.
* :func:`screenshot_available` honestly returns ``(False, reason)`` until
  a real capture path exists. Screenshot capture needs UI Automation /
  the Windows Graphics Capture API and is deferred.
* :func:`list_windows` uses PowerShell
  ``Get-Process | Where-Object {$_.MainWindowTitle}``; a ``ctypes``
  fallback via ``EnumWindows`` / ``GetWindowText`` is a later step and is
  NOT implemented here.
* :func:`list_processes` parses ``tasklist /FO CSV /NH``; a ``ctypes``
  fallback via ``NtQuerySystemInformation`` / Toolhelp32 is a later step
  and is NOT implemented here.
"""

from __future__ import annotations

import csv
import hashlib
import io
import ntpath
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath

__all__ = [
    "WINDOWS_BLOCKED_COMMANDS",
    "safe_resolve",
    "read_text",
    "write_text",
    "trash_path",
    "list_processes",
    "system_info",
    "screenshot_available",
    "list_windows_available",
    "list_windows",
    "run_powershell",
    "sha256_file",
]

# Unconditional argv[0] blocks (compared case-insensitively, ".exe"
# stripped). Includes the Linux dangerous set (sudo/su/doas/rm) for parity
# plus Windows-dangerous commands. The policy engine still gates
# run_command at Level 3 + approval; this list is a defence-in-depth
# refusal inside the adapter itself.
WINDOWS_BLOCKED_COMMANDS = frozenset({
    # Linux dangerous set, kept for parity (meaningless but harmful if
    # present via WSL / Git Bash shims on a Windows host).
    "sudo", "su", "doas", "rm",
    # Destructive / privilege-escalating Windows commands.
    "format",      # wipes a volume
    "diskpart",    # partitions / wipes disks (scriptable, no confirmation)
    "bcdedit",     # boot configuration — can brick boot
    "del", "erase",  # rm-equivalent file deletion
    "takeown",     # seizes ownership of files/objects
    # Nested shells: a second shell inside the PowerShell command would
    # defeat the argv-only quoting boundary, so refuse them outright.
    "powershell", "pwsh", "cmd",
})

# Conditional blocks: argv[0] is allowed only without the listed arguments
# (compared case-insensitively; leading "/" or "-" both accepted).
#   reg:      only "delete" (and "add"/"import" would also mutate, but
#             delete is the destructive form named in the task; "query"
#             and "export" remain allowed, still Level 3 gated upstream).
#   shutdown: /r /s /g /h /p /l restart, shut down, hybrid boot, hibernate,
#             power off or log off the user. "/a" (abort a pending
#             shutdown) is the only form left allowed.
#   rmdir:    only "/s" (recursive delete). Plain rmdir removes empty dirs.
#   icacls:   only the ACL-mutating verbs /grant /deny /remove /setowner
#             /reset /inheritance. A bare "icacls <path>" query is allowed.
_BLOCKED_WITH_ARGS = {
    "reg": {"delete"},
    "shutdown": {"/r", "/s", "/g", "/h", "/p", "/l"},
    "rmdir": {"/s"},
    "icacls": {"/grant", "/deny", "/remove", "/setowner", "/reset",
               "/inheritance"},
}

_POWERSHELL_EXE = "powershell.exe"
_WINDOWS_LIST_COMMAND = (
    "Get-Process | Where-Object {$_.MainWindowTitle} | "
    "Select-Object Id, ProcessName, MainWindowTitle | "
    "ConvertTo-Csv -NoTypeInformation"
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run(argv: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    """Run an argv array. No shell, ever. Patchable seam for tests."""
    return subprocess.run(
        argv, capture_output=True, text=True, timeout=timeout, shell=False,
    )


def _basename(argv0: str) -> str:
    """Lower-cased command name, drive/path and ".exe" stripped."""
    name = ntpath.basename(argv0.replace("/", "\\")).lower()
    if name.endswith(".exe"):
        name = name[:-4]
    return name


def _check_blocked(argv: list[str]) -> None:
    """Refuse dangerous argv[0] values (see module docstring)."""
    if not argv:
        raise ValueError("argv must be a non-empty list")
    name = _basename(str(argv[0]))
    if name in WINDOWS_BLOCKED_COMMANDS:
        raise ValueError(f"blocked command: {argv[0]!r}")
    blocked_args = _BLOCKED_WITH_ARGS.get(name)
    if blocked_args:
        lowered = {str(a).lower().lstrip("-") for a in argv[1:]}
        # Normalise "/s" vs "-s" vs "s": compare with a leading "/" added.
        normalised = {a if a.startswith("/") else f"/{a}" for a in lowered}
        hit = blocked_args & (lowered | normalised)
        if hit:
            raise ValueError(
                f"blocked command form: {argv[0]!r} with argument(s) "
                f"{sorted(hit)}"
            )


def _quote_powershell_arg(arg: str) -> str:
    """Quote one argument for a PowerShell ``-Command`` string.

    Quoting rule (documented): PowerShell single-quoted strings are
    literal — no variable expansion, no backtick escapes — and a single
    quote inside is escaped by doubling it (``'`` -> ``''``). Every
    argument is therefore wrapped in single quotes with internal quotes
    doubled, and the whole command is prefixed with the call operator
    ``&`` (a quoted string at statement start would otherwise be a
    literal, not an invocation). The joined string is passed as ONE
    ``-Command`` argument, so the operating system never re-splits it
    and no shell is involved. This keeps the command as data: an argument
    containing ``;``, ``|``, ``$()`` or backticks stays a literal string
    inside PowerShell.
    """
    return "'" + str(arg).replace("'", "''") + "'"


def _is_windows_host() -> bool:
    return platform.system() == "Windows"


def _default_resolver(path: str) -> str:
    """Resolve symlinks/junctions/8.3 names — Windows host only.

    Returns the path unchanged on a non-Windows host (there is nothing a
    Linux ``realpath`` could meaningfully resolve for a Windows path).
    """
    if _is_windows_host():
        return os.path.realpath(path)
    return path


def _norm_parts(path: PureWindowsPath) -> tuple[str, ...]:
    """Casefolded (anchor, *parts) tuple for containment comparison."""
    return tuple([path.anchor.casefold()] +
                 [p.casefold() for p in path.parts[1:] if p not in ("", "\\")])


def _expand_user_windows(user_path: str) -> str:
    """Expand a leading ``~`` to the Windows user profile.

    Uses %USERPROFILE%, else %HOMEDRIVE%%HOMEPATH%, else
    ``os.path.expanduser``. Tests can set USERPROFILE to a Windows path.
    """
    if not (user_path == "~" or user_path.startswith("~/")
            or user_path.startswith("~\\")):
        return user_path
    profile = os.environ.get("USERPROFILE")
    if not profile:
        drive = os.environ.get("HOMEDRIVE", "")
        homepath = os.environ.get("HOMEPATH", "")
        profile = (drive + homepath) if (drive or homepath) else ""
    if not profile:
        profile = os.path.expanduser("~")
    rest = user_path[1:].lstrip("/\\")
    return ntpath.join(profile, rest) if rest else profile


# ---------------------------------------------------------------------------
# Paths and files
# ---------------------------------------------------------------------------

def safe_resolve(base, user_path: str, allowed_roots=None,
                 resolver=None) -> PureWindowsPath:
    """Resolve ``user_path`` against ``base`` with Windows semantics.

    Drive letters (``C:\\...``), UNC paths (``\\\\server\\share``),
    backslashes and forward slashes are handled; comparison is
    case-insensitive, so ``c:\\work\\..\\windows`` cannot bypass a root
    of ``C:\\Work``. Relative paths are joined to ``base``; ``~`` expands
    to the user profile. ``..`` segments are collapsed lexically, then
    ``resolver`` (default: ``os.path.realpath`` on a real Windows host,
    identity elsewhere) resolves symlinks, junctions and 8.3 short names
    where possible. Raises :class:`ValueError` if the resolved path is
    not under ``base`` or one of ``allowed_roots``. ``base`` itself is
    allowed.

    ``resolver`` is an injectable ``str -> str`` seam for tests; pass a
    fake mapping short names / symlink targets to their real targets.
    """
    if not isinstance(user_path, str) or not user_path:
        raise ValueError("path must be a non-empty string")
    if base is None or (isinstance(base, str) and not base):
        raise ValueError("base must be a non-empty path")
    base = PureWindowsPath(str(base))
    if not base.is_absolute():
        raise ValueError(f"base must be an absolute Windows path: {base!r}")
    candidate = PureWindowsPath(_expand_user_windows(user_path))
    if not candidate.is_absolute():
        candidate = base.joinpath(candidate)
    # Lexical normalisation: collapse "." and ".." (ntpath works on Linux).
    collapsed = PureWindowsPath(ntpath.normpath(str(candidate)))
    resolve = resolver if resolver is not None else _default_resolver
    resolved = PureWindowsPath(ntpath.normpath(resolve(str(collapsed))))
    roots = [base]
    for root in allowed_roots or []:
        r = PureWindowsPath(str(root))
        if not r.is_absolute():
            raise ValueError(f"allowed root must be absolute: {root!r}")
        roots.append(r)
    candidate_parts = _norm_parts(resolved)
    for root in roots:
        root_parts = _norm_parts(PureWindowsPath(ntpath.normpath(str(root))))
        if candidate_parts[:len(root_parts)] == root_parts:
            return resolved
    raise ValueError(f"path outside allowed scope: {user_path!r}")


def read_text(path, max_bytes: int | None = None) -> str:
    """Read a file as UTF-8 (replacement characters for undecodable bytes)."""
    data = Path(path).read_bytes()
    if max_bytes is not None:
        data = data[:max_bytes]
    return data.decode("utf-8", errors="replace")


def write_text(path, content: str, create_parents: bool = False) -> Path:
    """Write ``content`` as UTF-8. Returns the path written."""
    path = Path(path)
    if create_parents:
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def trash_path(state_dir, original) -> Path:
    """Destination for a trashed file under the state-dir trash.

    The Windows Recycle Bin is NOT reachable from the stdlib, so this
    uses the same state-dir pattern as the Linux fallback: the original
    path (drive/UNC anchor stripped) is preserved under
    ``<state_dir>/trash`` and a UTC timestamp is appended to the filename
    so repeated trashes of the same path never collide. Real Recycle Bin
    integration (``SHFileOperation`` / ``IFileOperation``) is a later step.
    """
    original = PureWindowsPath(str(original))
    # Strip the drive/UNC anchor: C:\Users\a\f.txt -> Users\a\f.txt
    rel_parts = [p for p in original.parts[1:] if p not in ("", "\\")]
    rel = PureWindowsPath(*rel_parts) if rel_parts else PureWindowsPath(original.name)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    return Path(state_dir) / "trash" / rel.parent / f"{rel.name}.{stamp}"


# ---------------------------------------------------------------------------
# Processes
# ---------------------------------------------------------------------------

def parse_tasklist_csv(text: str) -> list[dict]:
    """Parse ``tasklist /FO CSV /NH`` output.

    Rows: ``"Image Name","PID","Session Name","Session#","Mem Usage"``,
    e.g. ``"chrome.exe","1234","Console","1","123,456 K"``. Returns
    ``[{"pid": int, "name": str, "memory_kb": int}]``. Rows with an
    unparsable PID are skipped; unparsable memory becomes ``None``.
    """
    processes: list[dict] = []
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if len(row) < 5:
            continue
        name, pid_raw, _session, _num, mem_raw = row[:5]
        try:
            pid = int(pid_raw.strip().strip('"'))
        except ValueError:
            continue
        mem = None
        try:
            mem = int(mem_raw.replace(",", "").replace(" K", "")
                      .replace("K", "").strip())
        except ValueError:
            mem = None
        processes.append({"pid": pid, "name": name.strip().strip('"'),
                          "memory_kb": mem})
    processes.sort(key=lambda p: p["pid"])
    return processes


def list_processes(name_filter: str | None = None,
                   runner=None) -> list[dict]:
    """List processes via ``tasklist /FO CSV /NH`` (no new dependency).

    Each entry: ``{"pid": int, "name": str, "memory_kb": int}``.
    ``runner`` is an injectable ``argv -> CompletedProcess`` seam for
    tests; the default runs the real ``tasklist``. A ``ctypes`` fallback
    (Toolhelp32 / ``NtQuerySystemInformation``) is a later step and is
    NOT implemented here.
    """
    run = runner if runner is not None else _run
    result = run(["tasklist", "/FO", "CSV", "/NH"], timeout=30)
    processes = parse_tasklist_csv(result.stdout or "")
    if name_filter:
        needle = name_filter.lower()
        processes = [p for p in processes if needle in p["name"].lower()]
    return processes


# ---------------------------------------------------------------------------
# System info
# ---------------------------------------------------------------------------

def _parse_wmic_value_output(text: str) -> dict[str, str]:
    """Parse ``wmic ... /value`` output (``Key=Value`` lines) into a dict."""
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip()
            if key and value:
                out[key] = value
    return out


def system_info(workdir=None, runner=None) -> dict:
    """Host facts: Windows version/edition/build, machine, CPUs, RAM.

    Uses :mod:`platform` (plus ``sys.getwindowsversion`` when on Windows)
    and parses ``wmic`` output where needed. Every external call is
    guarded: a missing ``wmic`` or a failed query yields ``None`` for
    that field instead of crashing. Keys mirror the Linux adapter where
    possible, plus ``windows_version``, ``windows_build`` and
    ``windows_edition``.
    """
    run = runner if runner is not None else _run
    windows_version = windows_build = windows_edition = None
    mem_total = None
    if _is_windows_host():
        try:
            ver = sys.getwindowsversion()  # type: ignore[attr-defined]
            windows_version = f"{ver.major}.{ver.minor}"
            windows_build = str(ver.build)
        except (AttributeError, OSError):
            pass
    # wmic is the fallback / primary source for edition + RAM; guarded.
    try:
        result = run(["wmic", "os", "get",
                      "Caption,Version,BuildNumber", "/value"], timeout=15)
        if result.returncode == 0:
            parsed = _parse_wmic_value_output(result.stdout or "")
            windows_version = parsed.get("Version") or windows_version
            windows_build = parsed.get("BuildNumber") or windows_build
            windows_edition = parsed.get("Caption") or windows_edition
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        result = run(["wmic", "computersystem", "get",
                      "TotalPhysicalMemory", "/value"], timeout=15)
        if result.returncode == 0:
            parsed = _parse_wmic_value_output(result.stdout or "")
            raw = parsed.get("TotalPhysicalMemory")
            if raw is not None:
                mem_total = int(raw)
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    disk = None
    if workdir is not None:
        try:
            usage = shutil.disk_usage(str(workdir))
            disk = {"path": str(workdir), "total": usage.total,
                    "used": usage.used, "free": usage.free}
        except OSError:
            disk = None
    return {
        "platform": platform.system(),
        "platform_release": platform.release(),
        "machine": platform.machine(),
        "python_version": sys.version.split()[0],
        "cpu_count": os.cpu_count(),
        "memory_total_bytes": mem_total,
        "memory_available_bytes": None,
        "load_average": None,
        "disk": disk,
        "windows_version": windows_version,
        "windows_build": windows_build,
        "windows_edition": windows_edition,
    }


# ---------------------------------------------------------------------------
# Screenshots and windows
# ---------------------------------------------------------------------------

def screenshot_available() -> tuple[bool, str]:
    """Honestly (False, reason): no capture path exists yet.

    Screenshot capture on Windows needs UI Automation / the Windows
    Graphics Capture API, which is deferred. This must NOT be faked:
    callers must treat screenshots as unavailable until a real capture
    implementation lands and is verified on a Windows host.
    """
    return False, (
        "screenshot capture is deferred: no UI Automation / Windows "
        "Graphics Capture path is implemented yet"
    )


def list_windows_available(runner=None) -> tuple[bool, str]:
    """(True, reason) only if PowerShell is present AND the window query runs.

    On a Linux host (no powershell.exe) this is (False, reason).
    """
    if shutil.which(_POWERSHELL_EXE) is None and runner is None:
        return False, "powershell.exe not found"
    try:
        windows = list_windows(runner=runner)
    except (FileNotFoundError, subprocess.SubprocessError, OSError) as exc:
        return False, f"PowerShell window query failed: {exc}"
    return True, f"PowerShell window query works ({len(windows)} windows)"


def list_windows(runner=None) -> list[dict]:
    """List windows with titles via PowerShell Get-Process.

    Returns ``[{"pid": int, "title": str, "process": str}]`` parsed from
    the CSV output of the query. Raises :class:`FileNotFoundError` if
    ``powershell.exe`` is not found. ``runner`` is an injectable
    ``argv -> CompletedProcess`` seam for tests.
    """
    run = runner if runner is not None else _run
    if runner is None and shutil.which(_POWERSHELL_EXE) is None:
        raise FileNotFoundError("powershell.exe not found")
    result = run(
        [_POWERSHELL_EXE, "-NoProfile", "-NonInteractive", "-Command",
         _WINDOWS_LIST_COMMAND],
        timeout=30,
    )
    if result.returncode != 0:
        raise OSError(
            f"PowerShell window query failed (exit {result.returncode}): "
            f"{(result.stderr or '').strip()}"
        )
    windows: list[dict] = []
    reader = csv.DictReader(io.StringIO(result.stdout or ""))
    for row in reader:
        try:
            pid = int((row.get("Id") or "").strip())
        except ValueError:
            continue
        title = (row.get("MainWindowTitle") or "").strip()
        if not title:
            continue
        windows.append({"pid": pid, "title": title,
                        "process": (row.get("ProcessName") or "").strip()})
    windows.sort(key=lambda w: w["pid"])
    return windows


# ---------------------------------------------------------------------------
# PowerShell execution
# ---------------------------------------------------------------------------

def run_powershell(argv: list[str], timeout: int = 30,
                   runner=None) -> subprocess.CompletedProcess:
    """Run a PowerShell command built from an argv array only.

    Builds ``["powershell.exe", "-NoProfile", "-NonInteractive",
    "-Command", <command>]`` where ``<command>`` is ``&`` followed by
    the argv array joined with the documented quoting rule (each
    argument single-quoted, inner quotes doubled — see
    :func:`_quote_powershell_arg`). The ``&`` call operator is required
    because a quoted command name would otherwise be a string literal,
    not an invocation. Never uses ``shell=True`` and never builds a
    command string from model input except through that quoting rule, so
    metacharacters (``;``, ``|``, ``$()``, backticks) stay literal data.
    Commands in :data:`WINDOWS_BLOCKED_COMMANDS` (or the conditional
    forms in ``_BLOCKED_WITH_ARGS``) raise :class:`ValueError` before
    anything runs. The policy engine still gates run_command at Level 3
    + approval.
    """
    if not argv or not all(isinstance(a, str) and a for a in argv):
        raise ValueError("argv must be a non-empty list of non-empty strings")
    _check_blocked(argv)
    command = "& " + " ".join(_quote_powershell_arg(a) for a in argv)
    full_argv = [_POWERSHELL_EXE, "-NoProfile", "-NonInteractive",
                 "-Command", command]
    run = runner if runner is not None else _run
    return run(full_argv, timeout=timeout)


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def sha256_file(path) -> str:
    """SHA-256 hex digest of a file, streamed (no whole-file read)."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
