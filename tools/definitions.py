"""Tool definitions for OpenCobot Phase 1 Linux MVP.

Every tool declares ``execute()`` and ``verify()`` (SPEC §5/§7,
ARCHITECTURE §4). ``execute()`` performs the action and returns
``{"ok": bool, "data": dict, "error": str | None}``; ``verify()`` re-reads
real system state and returns ``(bool, evidence)`` — it never trusts the
model's claim or ``execute()``'s own word.

Safety rules enforced here (not by the caller):

* Args are validated against each tool's JSON Schema inside ``execute()``:
  required keys, types, enums; ``additionalProperties`` rejected. Bad input
  returns ``ok False`` with an error, never raises.
* Every filesystem path is resolved through the dispatched OS
  adapter's ``safe_resolve`` (Linux: :mod:`adapters.linux.linux`;
  Windows: :mod:`adapters.windows.windows`, selected by
  :func:`_os_adapter`) against the context workdir (plus token scope
  folders when a capability token is present). Paths escaping that
  scope — ``..`` segments, absolute paths elsewhere, symlink
  escapes — are denied.
* No ``shell=True`` anywhere; all subprocess calls use argv arrays.
  On Windows ``run_command`` goes through the Windows adapter's
  ``run_powershell`` (argv arrays only, quoted as PowerShell data),
  never ``cmd.exe``.
* ``delete_to_trash`` never hard-deletes; ``write_file`` snapshots the
  original first (undo support).
* Stdlib only. No network access in any tool.

Context (``ctx``) is a dict::

    {"state_dir": Path, "workdir": Path, "token": object | None}

``token`` may be a dict (keys ``folders`` / ``allowed_roots`` / ``scope`` /
``roots`` holding path lists), an object with one of those attributes, or a
single path. When absent, only ``workdir`` is in scope.
"""

from __future__ import annotations

import copy
import fnmatch
import functools
import hashlib
import ntpath
import os
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

try:
    from core import window_control as _window_control
except ImportError:  # allow import without the repo root on sys.path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from core import window_control as _window_control

try:
    from adapters.linux import linux as linux_adapter
except ImportError:  # allow import without the repo root on sys.path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from adapters.linux import linux as linux_adapter


def _is_windows() -> bool:
    """True on a Windows host (``platform.system() == "Windows"``)."""
    return platform.system() == "Windows"


def _os_adapter():
    """Return the OS adapter module for this platform.

    Selected per call, not cached: the import is already in
    ``sys.modules`` after the first call, so this is cheap, and
    per-call selection lets tests patch ``platform.system`` without
    cache invalidation. POSIX returns :mod:`adapters.linux.linux`;
    Windows returns :mod:`adapters.windows.windows`. The Windows
    module imports cleanly on Linux (stdlib only) but is only
    imported on a Windows host, so a Linux process never touches
    Windows-only code paths.
    """
    if _is_windows():
        from adapters.windows import windows as windows_adapter

        return windows_adapter
    return linux_adapter


def _windows_command_name(argv0: str) -> str:
    """Lower-cased argv[0] basename, drive/path and ``.exe`` stripped.

    ``ntpath`` is used (not ``pathlib``) so the normalisation is
    correct for Windows spellings even when this code is read on
    Linux, e.g. ``C:\\Windows\\FORMAT.EXE`` -> ``format``.
    """
    name = ntpath.basename(str(argv0).replace("/", "\\")).lower()
    if name.endswith(".exe"):
        name = name[:-4]
    return name

__all__ = ["ToolSpec", "TOOLS", "get_tool", "list_tools"]

MAX_OUTPUT_BYTES = 64 * 1024  # 64 KiB cap on captured command/file output
DEFAULT_MAX_BYTES = 65536
BLOCKED_BINARIES = frozenset({"sudo", "su", "doas", "rm"})
_HASH_ALGORITHMS = ("sha256", "sha1", "md5")


# ---------------------------------------------------------------------------
# Shared interface
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ToolSpec:
    """One tool: schema, permission level, execute() and verify().

    ``network`` says whether this tool is *capable* of network access
    (only ``run_command`` is, because it can run a network binary).
    Whether one particular call actually uses the network is decided
    by :func:`is_network_call` — e.g. ``run_command`` with ``echo``
    does not, with ``curl`` it does. The policy engine enforces the
    token's ``network`` flag against the per-call answer, not the
    static capability.
    """

    name: str
    description: str
    level: int
    schema: dict
    execute: Callable[[dict, dict], dict]
    verify: Callable[[dict, dict, dict], tuple[bool, str]]
    network: bool = False


# Binaries whose execution is, by itself, network access. `git` is
# handled separately below: only its network subcommands count.
NETWORK_BINARIES = frozenset(
    {"curl", "wget", "ssh", "scp", "sftp", "rsync", "nc", "ncat", "socat",
     "aria2c", "ftp", "lftp", "telnet", "ping"}
)

# `git` subcommands that touch the network (status/log/diff do not).
NETWORK_GIT_SUBCOMMANDS = frozenset(
    {"clone", "fetch", "pull", "push", "ls-remote", "submodule", "archive"}
)

# Tools capable of network access at all (see ToolSpec.network).
NETWORK_CAPABLE_TOOLS = frozenset({"run_command"})


def is_network_call(tool_name: str, args: dict | None) -> bool:
    """True when this exact call performs network access.

    Today only ``run_command`` can: its argv is inspected (argv[0]
    basename against :data:`NETWORK_BINARIES`, `git` network
    subcommands). Every other tool performs no network I/O. This is
    an argv-based classification, not a sandbox: arbitrary code run
    through ``run_command`` (e.g. ``python3 -c`` using urllib) can
    still reach the network, which is why the tool stays Level 3 and
    approval-gated regardless of the token flag — the flag is
    defence-in-depth on top of approval, not a replacement for it.
    """
    if tool_name != "run_command" or not isinstance(args, dict):
        return False
    argv = args.get("argv")
    if not isinstance(argv, list) or not argv or not argv[0]:
        return False
    binary = Path(str(argv[0])).name
    if binary in NETWORK_BINARIES:
        return True
    if binary == "git" and len(argv) > 1 and argv[1] in NETWORK_GIT_SUBCOMMANDS:
        return True
    return False


# ---------------------------------------------------------------------------
# Context / scope helpers
# ---------------------------------------------------------------------------

def _default_state_dir() -> Path:
    return Path(os.environ.get("OPENCOBOT_STATE") or "~/.opencobot").expanduser()


def _state_dir(ctx: dict) -> Path:
    if isinstance(ctx, dict) and ctx.get("state_dir"):
        return Path(ctx["state_dir"]).expanduser()
    return _default_state_dir()


def _workdir(ctx: dict) -> Path:
    if isinstance(ctx, dict) and ctx.get("workdir"):
        return Path(ctx["workdir"]).expanduser().resolve()
    return Path.cwd()


def _token_roots(ctx: dict) -> list[Path]:
    token = ctx.get("token") if isinstance(ctx, dict) else None
    if token is None:
        return []
    if isinstance(token, (str, Path)):
        return [Path(token)]
    candidates: list = []
    keys = ("scope_folders", "folders", "allowed_roots", "allowed_folders", "scope", "roots")
    if isinstance(token, dict):
        for key in keys:
            value = token.get(key)
            if isinstance(value, (list, tuple)):
                candidates.extend(value)
            elif isinstance(value, (str, Path)):
                candidates.append(value)
    else:
        for key in keys:
            value = getattr(token, key, None)
            if isinstance(value, (list, tuple)):
                candidates.extend(value)
            elif isinstance(value, (str, Path)):
                candidates.append(value)
    roots = []
    for candidate in candidates:
        if isinstance(candidate, (str, Path)) and str(candidate):
            roots.append(Path(candidate))
    return roots


def _allowed_roots(ctx: dict) -> list[Path]:
    return [_workdir(ctx), *_token_roots(ctx)]


def _resolve(ctx: dict, user_path: str) -> Path:
    """Resolve a user-supplied path inside the allowed scope (raises ValueError).

    The dispatched adapter returns a Linux ``Path`` on POSIX and a
    ``PureWindowsPath`` on Windows; wrapping in ``Path(...)`` yields a
    concrete, filesystem-capable path on the host platform.
    """
    resolved = _os_adapter().safe_resolve(_workdir(ctx), user_path,
                                          allowed_roots=_allowed_roots(ctx))
    return Path(str(resolved))


def _git_binary() -> str | None:
    """Resolved git executable for this platform, or None if absent.

    Git tools need git installed; no new dependency is introduced.
    ``shutil.which("git")`` already resolves ``git.exe`` via PATHEXT
    on Windows, but ``git.exe`` is checked first there so the lookup
    is explicit about the Windows binary name.
    """
    if _is_windows():
        return shutil.which("git.exe") or shutil.which("git")
    return shutil.which("git")


def _run_git(path: Path, argv: list[str], timeout: int = 15):
    """Run git with an argv array only, cwd=path (dispatch by platform).

    POSIX keeps the Linux adapter's ``run_git``; Windows runs the
    resolved ``git.exe`` the same way (argv array, no shell).
    """
    if _is_windows():
        git = _git_binary()
        if git is None:
            raise FileNotFoundError("git binary not found")
        return subprocess.run(
            [git, *argv], cwd=str(path), capture_output=True,
            text=True, timeout=timeout, shell=False,
        )
    return _os_adapter().run_git(path, argv, timeout=timeout)


def _is_git_repo(path: Path) -> bool:
    """True iff ``path`` is inside a git working tree (either platform)."""
    try:
        result = _run_git(Path(path), ["rev-parse", "--git-dir"], timeout=10)
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return False
    return result.returncode == 0


def _run_powershell(argv: list[str], timeout: int, cwd: Path | None):
    """Run ``argv`` through the Windows adapter's ``run_powershell``.

    ``run_powershell`` takes no cwd, so when a cwd is given it is
    passed through the adapter's injectable ``runner`` seam: the
    adapter still builds the full PowerShell argv (argv array only,
    quoted as data), and the runner only adds ``cwd=`` to the
    ``subprocess.run`` call. No shell is involved at any point.
    """
    adapter = _os_adapter()
    if cwd is None:
        return adapter.run_powershell(argv, timeout=timeout)

    def _runner(full_argv, timeout: int = 30):
        return subprocess.run(
            full_argv, cwd=str(cwd), capture_output=True, text=True,
            timeout=timeout, shell=False,
        )

    return adapter.run_powershell(argv, timeout=timeout, runner=_runner)


# ---------------------------------------------------------------------------
# Validation + result helpers
# ---------------------------------------------------------------------------

_TYPE_CHECKS = {
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "array": lambda v: isinstance(v, list),
    "object": lambda v: isinstance(v, dict),
    "null": lambda v: v is None,
}


def _validate(args: dict, schema: dict) -> str | None:
    """Validate ``args`` against a JSON Schema subset. Returns error or None."""
    if not isinstance(args, dict):
        return "args must be an object"
    properties = schema.get("properties", {})
    required = schema.get("required", [])
    if schema.get("additionalProperties") is False:
        unknown = sorted(set(args) - set(properties))
        if unknown:
            return f"unexpected arguments: {', '.join(unknown)}"
    for key in required:
        if key not in args:
            return f"missing required argument: {key}"
    for key, value in args.items():
        spec = properties.get(key)
        if spec is None:
            continue
        expected = spec.get("type")
        if expected and not _TYPE_CHECKS[expected](value):
            return f"argument {key!r} must be {expected}"
        if "enum" in spec and value not in spec["enum"]:
            return f"argument {key!r} must be one of {spec['enum']}"
        items = spec.get("items")
        if items and isinstance(value, list):
            item_type = items.get("type")
            if item_type and any(not _TYPE_CHECKS[item_type](v) for v in value):
                return f"argument {key!r} items must be {item_type}"
    return None


def _ok(data: dict) -> dict:
    return {"ok": True, "data": data, "error": None}


def _fail(error: str, data: dict | None = None) -> dict:
    return {"ok": False, "data": data or {}, "error": error}


def _guard(fn):
    """Never let bad input / environment failure raise out of execute()."""
    @functools.wraps(fn)
    def wrapper(args, ctx):
        try:
            return fn(args, ctx)
        except Exception as exc:  # noqa: BLE001 - tools must report, not raise
            return _fail(f"{type(exc).__name__}: {exc}")
    return wrapper


def _guard_verify(fn):
    @functools.wraps(fn)
    def wrapper(args, result, ctx):
        try:
            return fn(args, result, ctx)
        except Exception as exc:  # noqa: BLE001 - verification failure, not crash
            return False, f"verify error: {type(exc).__name__}: {exc}"
    return wrapper


def _hash_file(path: Path, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _snapshot(ctx: dict, path: Path) -> Path | None:
    """Copy the current file into state_dir/snapshots/ before overwrite.

    Returns the snapshot path, or None if there was nothing to snapshot.
    """
    if not path.is_file():
        return None
    try:
        rel = path.relative_to(_workdir(ctx))
    except ValueError:
        rel = Path(*path.parts[1:]) if path.is_absolute() else path
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    dest = _state_dir(ctx) / "snapshots" / rel.parent / f"{rel.name}.{stamp}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, dest)
    return dest


def _verify_failed(result: dict) -> tuple[bool, str] | None:
    """Common verify preamble: a failed execute() can never verify True."""
    if not isinstance(result, dict) or not result.get("ok"):
        error = result.get("error") if isinstance(result, dict) else None
        return False, f"execute failed, nothing to verify: {error}"
    return None

# ---------------------------------------------------------------------------
# Schema helper
# ---------------------------------------------------------------------------

def _schema(properties: dict, required: list[str] | None = None) -> dict:
    return {
        "type": "object",
        "properties": properties,
        "required": required or [],
        "additionalProperties": False,
    }


_STR = {"type": "string"}
_BOOL = {"type": "boolean"}
_INT = {"type": "integer"}

# ---------------------------------------------------------------------------
# 1-5. File reading / discovery (level 0)
# ---------------------------------------------------------------------------

def _list_dir_entries(path: Path, recursive: bool) -> list[dict]:
    entries = []
    if recursive:
        for root, dirs, files in os.walk(path):
            dirs.sort()
            for name in sorted(files):
                full = Path(root) / name
                entries.append({"name": str(full.relative_to(path)), "path": str(full),
                                "is_dir": False, "size": full.stat().st_size})
            for name in sorted(dirs):
                full = Path(root) / name
                entries.append({"name": str(full.relative_to(path)), "path": str(full),
                                "is_dir": True, "size": None})
    else:
        for entry in sorted(path.iterdir(), key=lambda e: e.name):
            entries.append({"name": entry.name, "path": str(entry),
                            "is_dir": entry.is_dir(),
                            "size": entry.stat().st_size if entry.is_file() else None})
    return entries


@_guard
def _exec_list_dir(args, ctx):
    err = _validate(args, _SCHEMAS["list_dir"])
    if err:
        return _fail(err)
    path = _resolve(ctx, args["path"])
    if not path.is_dir():
        return _fail(f"not a directory: {args['path']!r}")
    entries = _list_dir_entries(path, bool(args.get("recursive", False)))
    return _ok({"path": str(path), "entries": entries, "count": len(entries)})


@_guard_verify
def _verify_list_dir(args, result, ctx):
    failed = _verify_failed(result)
    if failed:
        return failed
    path = _resolve(ctx, args["path"])
    if not path.is_dir():
        return False, f"directory no longer exists: {path}"
    expected = {e["path"] for e in _list_dir_entries(path, bool(args.get("recursive", False)))}
    actual = {e["path"] for e in result["data"].get("entries", [])}
    if expected == actual:
        return True, f"directory listing matches real state ({len(actual)} entries)"
    return False, f"listing mismatch: real={sorted(expected)} vs reported={sorted(actual)}"


@_guard
def _exec_read_file(args, ctx):
    err = _validate(args, _SCHEMAS["read_file"])
    if err:
        return _fail(err)
    max_bytes = args.get("max_bytes", DEFAULT_MAX_BYTES)
    if max_bytes <= 0 or max_bytes > 1024 * 1024:
        return _fail("max_bytes must be between 1 and 1048576")
    path = _resolve(ctx, args["path"])
    if not path.is_file():
        return _fail(f"not a file: {args['path']!r}")
    raw = path.read_bytes()
    truncated = len(raw) > max_bytes
    content = raw[:max_bytes].decode("utf-8", errors="replace")
    return _ok({"path": str(path), "content": content, "size": len(raw),
                "bytes_read": min(len(raw), max_bytes), "truncated": truncated})


@_guard_verify
def _verify_read_file(args, result, ctx):
    failed = _verify_failed(result)
    if failed:
        return failed
    max_bytes = args.get("max_bytes", DEFAULT_MAX_BYTES)
    path = _resolve(ctx, args["path"])
    if not path.is_file():
        return False, f"file no longer exists: {path}"
    raw = path.read_bytes()
    content = raw[:max_bytes].decode("utf-8", errors="replace")
    if content != result["data"].get("content") or len(raw) != result["data"].get("size"):
        return False, "file content/size changed since read"
    return True, f"content matches file on disk ({len(raw)} bytes)"


@_guard
def _exec_file_info(args, ctx):
    err = _validate(args, _SCHEMAS["file_info"])
    if err:
        return _fail(err)
    path = _resolve(ctx, args["path"])
    if not path.exists():
        return _fail(f"no such file or directory: {args['path']!r}")
    stat = path.stat()
    return _ok({"path": str(path), "size": stat.st_size, "mtime": stat.st_mtime,
                "is_dir": path.is_dir(),
                "sha256": _hash_file(path) if path.is_file() else None})


@_guard_verify
def _verify_file_info(args, result, ctx):
    failed = _verify_failed(result)
    if failed:
        return failed
    path = _resolve(ctx, args["path"])
    if not path.exists():
        return False, f"path no longer exists: {path}"
    stat = path.stat()
    data = result["data"]
    if stat.st_size != data.get("size") or path.is_dir() != data.get("is_dir"):
        return False, "size or type changed since file_info"
    if path.is_file() and _hash_file(path) != data.get("sha256"):
        return False, "file hash changed since file_info"
    return True, f"stat matches real file ({stat.st_size} bytes)"


@_guard
def _exec_file_hash(args, ctx):
    err = _validate(args, _SCHEMAS["file_hash"])
    if err:
        return _fail(err)
    path = _resolve(ctx, args["path"])
    if not path.is_file():
        return _fail(f"not a file: {args['path']!r}")
    algorithm = args.get("algorithm", "sha256")
    return _ok({"path": str(path), "algorithm": algorithm,
                "hash": _hash_file(path, algorithm)})


@_guard_verify
def _verify_file_hash(args, result, ctx):
    failed = _verify_failed(result)
    if failed:
        return failed
    path = _resolve(ctx, args["path"])
    if not path.is_file():
        return False, f"file no longer exists: {path}"
    algorithm = args.get("algorithm", "sha256")
    actual = _hash_file(path, algorithm)
    if actual == result["data"].get("hash"):
        return True, f"{algorithm} hash matches: {actual}"
    return False, f"hash mismatch: real={actual} vs reported={result['data'].get('hash')}"


def _matches_pattern(name: str, pattern: str) -> bool:
    if any(ch in pattern for ch in "*?["):
        return fnmatch.fnmatchcase(name, pattern)
    return pattern.lower() in name.lower()


@_guard
def _exec_search_files(args, ctx):
    err = _validate(args, _SCHEMAS["search_files"])
    if err:
        return _fail(err)
    if not args["pattern"]:
        return _fail("pattern must not be empty")
    max_results = args.get("max_results", 100)
    if max_results <= 0 or max_results > 1000:
        return _fail("max_results must be between 1 and 1000")
    path = _resolve(ctx, args["path"])
    if not path.is_dir():
        return _fail(f"not a directory: {args['path']!r}")
    pattern = args["pattern"]
    results: list[str] = []
    truncated = False
    for root, dirs, files in os.walk(path):
        dirs.sort()
        for name in sorted(files):
            if _matches_pattern(name, pattern):
                results.append(str(Path(root) / name))
                if len(results) >= max_results:
                    truncated = True
                    break
        if truncated:
            break
    return _ok({"path": str(path), "pattern": pattern, "results": results,
                "count": len(results), "truncated": truncated})


@_guard_verify
def _verify_search_files(args, result, ctx):
    failed = _verify_failed(result)
    if failed:
        return failed
    pattern = args["pattern"]
    for item in result["data"].get("results", []):
        path = Path(item)
        if not path.is_file():
            return False, f"reported match no longer exists: {item}"
        if not _matches_pattern(path.name, pattern):
            return False, f"reported match does not match pattern: {item}"
    return True, f"all {len(result['data'].get('results', []))} matches exist on disk"


# ---------------------------------------------------------------------------
# 6-8. System / process inspection (level 0)
# ---------------------------------------------------------------------------

@_guard
def _exec_system_info(args, ctx):
    err = _validate(args, _SCHEMAS["system_info"])
    if err:
        return _fail(err)
    return _ok(_os_adapter().system_info(_workdir(ctx)))


@_guard_verify
def _verify_system_info(args, result, ctx):
    failed = _verify_failed(result)
    if failed:
        return failed
    fresh = _os_adapter().system_info(_workdir(ctx))
    data = result["data"]
    if data.get("cpu_count") != fresh["cpu_count"]:
        return False, "cpu count changed"
    if data.get("platform") != fresh["platform"]:
        return False, "platform changed"
    disk = data.get("disk") or {}
    if disk.get("total", 0) <= 0 or disk.get("total") != (fresh["disk"] or {}).get("total"):
        return False, "disk info missing or inconsistent"
    return True, f"system info matches live state ({fresh['platform']}, {fresh['cpu_count']} CPUs)"


@_guard
def _exec_list_processes(args, ctx):
    err = _validate(args, _SCHEMAS["list_processes"])
    if err:
        return _fail(err)
    processes = _os_adapter().list_processes(args.get("name_filter"))
    return _ok({"processes": processes, "count": len(processes)})


@_guard_verify
def _verify_list_processes(args, result, ctx):
    failed = _verify_failed(result)
    if failed:
        return failed
    fresh = {p["pid"]: p for p in _os_adapter().list_processes()}
    reported = result["data"].get("processes", [])
    # Processes may legitimately exit between execute() and verify(); a pid
    # that vanished is not evidence of a lie. A pid's NAME, however, is not
    # a sound identity check either: a process that exec()s a new program
    # keeps its pid but gets a new comm (``sh`` -> ``sleep``), which happens
    # constantly on a busy CI runner — the old strict name check failed the
    # main-branch CI run on f302c87 for exactly this reason. Identity is
    # therefore pid + starttime (``/proc`` stat field 22, invariant across
    # exec): same starttime means the same process even if it renamed
    # itself, a different starttime means the pid was reused by a new
    # process and confirms nothing. Entries without a starttime (Windows
    # shape) fall back to name equality — sound there, because on Windows
    # exec creates a new process (new pid) instead of reusing one.
    # What we can check strictly: at least one reported process must still
    # be alive under the same identity (a wholly fabricated list fails).
    still_alive = 0
    for proc in reported:
        pid = proc.get("pid")
        live = fresh.get(pid)
        if live is None:
            continue
        reported_st = proc.get("starttime")
        live_st = live.get("starttime")
        if reported_st is not None and live_st is not None:
            if reported_st != live_st:
                continue  # pid reuse: a different process owns this pid now
        elif live.get("name") != proc.get("name"):
            continue  # no starttime to compare: name is the only identity
        still_alive += 1
    if reported and still_alive == 0:
        return False, "none of the reported processes exist anymore"
    name_filter = args.get("name_filter")
    if name_filter:
        for proc in reported:
            hay = f"{proc.get('name', '')} {proc.get('cmdline', '')}".lower()
            if name_filter.lower() not in hay:
                return False, f"process {proc.get('pid')} does not match filter {name_filter!r}"
    return True, f"{still_alive}/{len(reported)} reported processes confirmed in /proc"


@_guard
def _exec_process_info(args, ctx):
    err = _validate(args, _SCHEMAS["process_info"])
    if err:
        return _fail(err)
    pid = args["pid"]
    if pid <= 0:
        return _fail("pid must be a positive integer")
    return _ok(_read_process(pid))


def _read_process(pid: int) -> dict:
    proc = Path(f"/proc/{pid}")
    if not proc.is_dir():
        raise FileNotFoundError(f"no such process: {pid}")
    name = (proc / "comm").read_text(encoding="utf-8", errors="replace").strip()
    raw = (proc / "cmdline").read_bytes()
    cmdline = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
    status = (proc / "status").read_text(encoding="utf-8", errors="replace")
    fields = {}
    for line in status.splitlines():
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    rss = None
    if fields.get("VmRSS"):
        try:
            rss = int(fields["VmRSS"].split()[0]) * 1024
        except ValueError:
            rss = None
    return {"pid": pid, "name": name, "state": fields.get("State", ""),
            "ppid": int(fields["PPid"]) if fields.get("PPid", "").isdigit() else None,
            "cmdline": cmdline, "rss_bytes": rss}


@_guard_verify
def _verify_process_info(args, result, ctx):
    failed = _verify_failed(result)
    if failed:
        return failed
    pid = args["pid"]
    if not Path(f"/proc/{pid}").is_dir():
        return False, f"process {pid} no longer exists"
    fresh = _read_process(pid)
    if fresh["name"] != result["data"].get("name"):
        return False, f"process {pid} name changed: {fresh['name']!r}"
    return True, f"process {pid} ({fresh['name']}) confirmed in /proc"


# ---------------------------------------------------------------------------
# 9-11. Git (level 0) — subprocess argv arrays only, cwd=path, timeout 15
# ---------------------------------------------------------------------------

def _require_git_repo(ctx, args) -> tuple[Path | None, str | None]:
    path = _resolve(ctx, args["path"])
    if not path.is_dir():
        return None, f"not a directory: {args['path']!r}"
    if _git_binary() is None:
        return None, "git binary not found"
    if not _is_git_repo(path):
        return None, "not a git repository"
    return path, None


@_guard
def _exec_git_status(args, ctx):
    err = _validate(args, _SCHEMAS["git_status"])
    if err:
        return _fail(err)
    path, repo_err = _require_git_repo(ctx, args)
    if repo_err:
        return _fail(repo_err)
    result = _run_git(path, ["status", "--porcelain=v1", "-b"])
    if result.returncode != 0:
        return _fail(f"git status failed: {result.stderr.strip()}")
    branch = ""
    staged, unstaged, untracked = [], [], []
    for line in result.stdout.splitlines():
        if line.startswith("## "):
            branch = line[3:].split("...")[0]
            continue
        if len(line) < 4:
            continue
        x, y, filename = line[0], line[1], line[3:]
        if x == "?" and y == "?":
            untracked.append(filename)
        else:
            if x not in (" ", "?"):
                staged.append(filename)
            if y not in (" ", "?"):
                unstaged.append(filename)
    return _ok({"path": str(path), "branch": branch,
                "clean": not (staged or unstaged or untracked),
                "staged": staged, "unstaged": unstaged, "untracked": untracked})


def _git_status_again(path: Path) -> dict:
    result = _run_git(path, ["status", "--porcelain=v1", "-b"])
    branch = ""
    changed = []
    for line in result.stdout.splitlines():
        if line.startswith("## "):
            branch = line[3:].split("...")[0]
        else:
            changed.append(line)
    return {"branch": branch, "clean": not changed}


@_guard_verify
def _verify_git_status(args, result, ctx):
    failed = _verify_failed(result)
    if failed:
        return failed
    path = _resolve(ctx, args["path"])
    fresh = _git_status_again(path)
    data = result["data"]
    if fresh["branch"] != data.get("branch") or fresh["clean"] != data.get("clean"):
        return False, f"git status changed: branch={fresh['branch']!r} clean={fresh['clean']}"
    return True, f"git status confirmed: branch {fresh['branch']!r}, clean={fresh['clean']}"


@_guard
def _exec_git_log(args, ctx):
    err = _validate(args, _SCHEMAS["git_log"])
    if err:
        return _fail(err)
    max_count = args.get("max_count", 10)
    if max_count <= 0 or max_count > 100:
        return _fail("max_count must be between 1 and 100")
    path, repo_err = _require_git_repo(ctx, args)
    if repo_err:
        return _fail(repo_err)
    result = _run_git(
        path, ["log", f"-n{max_count}", "--date=iso",
               "--format=%H%x1f%an%x1f%ad%x1f%s%x1e"])
    if result.returncode != 0:
        return _fail(f"git log failed: {result.stderr.strip()}")
    commits = []
    for record in result.stdout.split("\x1e"):
        record = record.strip("\n")
        if not record.strip():
            continue
        parts = record.split("\x1f")
        if len(parts) == 4:
            commits.append({"hash": parts[0], "author": parts[1],
                            "date": parts[2], "subject": parts[3]})
    return _ok({"path": str(path), "commits": commits, "count": len(commits)})


@_guard_verify
def _verify_git_log(args, result, ctx):
    failed = _verify_failed(result)
    if failed:
        return failed
    path = _resolve(ctx, args["path"])
    max_count = args.get("max_count", 10)
    fresh = _run_git(
        path, ["log", f"-n{max_count}", "--date=iso",
               "--format=%H%x1f%an%x1f%ad%x1f%s%x1e"])
    commits = []
    for record in fresh.stdout.split("\x1e"):
        record = record.strip("\n")
        if not record.strip():
            continue
        parts = record.split("\x1f")
        if len(parts) == 4:
            commits.append({"hash": parts[0], "author": parts[1],
                            "date": parts[2], "subject": parts[3]})
    if commits == result["data"].get("commits"):
        return True, f"git log matches ({len(commits)} commits)"
    return False, "git log changed since execute (new commits?)"


@_guard
def _exec_git_diff(args, ctx):
    err = _validate(args, _SCHEMAS["git_diff"])
    if err:
        return _fail(err)
    path, repo_err = _require_git_repo(ctx, args)
    if repo_err:
        return _fail(repo_err)
    diff = _run_git(path, ["diff"])
    if diff.returncode != 0:
        return _fail(f"git diff failed: {diff.stderr.strip()}")
    names = _run_git(path, ["diff", "--name-only"])
    stat = _run_git(path, ["diff", "--stat"])
    text = diff.stdout
    truncated = len(text) > MAX_OUTPUT_BYTES
    if truncated:
        text = text[:MAX_OUTPUT_BYTES]
    return _ok({"path": str(path),
                "diff": text,
                "files": [l for l in names.stdout.splitlines() if l],
                "stat": stat.stdout,
                "truncated": truncated})


@_guard_verify
def _verify_git_diff(args, result, ctx):
    failed = _verify_failed(result)
    if failed:
        return failed
    path = _resolve(ctx, args["path"])
    fresh = _run_git(path, ["diff"])
    expected = fresh.stdout[:MAX_OUTPUT_BYTES] if len(fresh.stdout) > MAX_OUTPUT_BYTES else fresh.stdout
    if expected == result["data"].get("diff"):
        return True, "git diff matches working tree"
    return False, "git diff changed since execute"

# ---------------------------------------------------------------------------
# 12-13. Screenshot / windows (level 0) — honest headless behaviour
# ---------------------------------------------------------------------------

@_guard
def _exec_screenshot(args, ctx):
    err = _validate(args, _SCHEMAS["screenshot"])
    if err:
        return _fail(err)
    available, reason = _os_adapter().screenshot_available()
    if not available:
        return _fail(reason, {"unavailable": True, "reason": reason})
    if _is_windows():
        # No capture implementation exists behind the adapter on
        # Windows (the adapter honestly reports unavailable until a
        # Graphics Capture path lands); never run the Linux scrot
        # path below. Unreachable today, kept as a guard for a future
        # adapter that reports available without a capture function.
        return _fail("screenshot capture is not implemented on Windows",
                     {"unavailable": True,
                      "reason": "screenshot capture is not implemented on Windows"})
    tool = next(t for t in ("scrot", "import", "gnome-screenshot")
                if shutil.which(t))
    dest = _state_dir(ctx) / "screenshots" / (
        f"screenshot-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')}.png")
    dest.parent.mkdir(parents=True, exist_ok=True)
    if tool == "scrot":
        argv = ["scrot", str(dest)]
    elif tool == "import":
        argv = ["import", "-window", "root", str(dest)]
    else:
        argv = ["gnome-screenshot", "-f", str(dest)]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=15, shell=False)
    except subprocess.TimeoutExpired:
        return _fail("screenshot timed out", {"unavailable": True, "reason": "screenshot timed out"})
    if proc.returncode != 0 or not dest.is_file() or dest.stat().st_size == 0:
        return _fail(f"screenshot failed: {proc.stderr.strip() or reason}",
                     {"unavailable": True, "reason": proc.stderr.strip() or reason})
    return _ok({"path": str(dest), "size": dest.stat().st_size, "tool": tool})


@_guard_verify
def _verify_screenshot(args, result, ctx):
    failed = _verify_failed(result)
    if failed:
        return failed
    path = Path(result["data"].get("path", ""))
    if not path.is_file() or path.stat().st_size == 0:
        return False, f"screenshot file missing or empty: {path}"
    if path.stat().st_size != result["data"].get("size"):
        return False, "screenshot file size changed"
    return True, f"screenshot file exists and is non-empty ({path.stat().st_size} bytes)"


def _list_windows_live() -> list[dict]:
    """List windows via wmctrl (preferred) or xdotool. Raises on failure."""
    if shutil.which("wmctrl"):
        proc = subprocess.run(["wmctrl", "-l"], capture_output=True, text=True,
                              timeout=15, shell=False)
        if proc.returncode != 0:
            raise RuntimeError(f"wmctrl failed: {proc.stderr.strip()}")
        windows = []
        for line in proc.stdout.splitlines():
            parts = line.split(None, 3)
            if len(parts) >= 4:
                windows.append({"id": parts[0], "desktop": parts[1],
                                "host": parts[2], "title": parts[3]})
            elif len(parts) >= 1:
                windows.append({"id": parts[0], "desktop": "", "host": "", "title": ""})
        return windows
    # xdotool fallback
    proc = subprocess.run(["xdotool", "search", "--onlyvisible", "--name", "."],
                          capture_output=True, text=True, timeout=15, shell=False)
    if proc.returncode != 0:
        raise RuntimeError(f"xdotool failed: {proc.stderr.strip()}")
    windows = []
    for wid in proc.stdout.split():
        name = subprocess.run(["xdotool", "getwindowname", wid],
                              capture_output=True, text=True, timeout=10, shell=False)
        windows.append({"id": wid, "desktop": "", "host": "",
                        "title": name.stdout.strip() if name.returncode == 0 else ""})
    return windows


def _tier1_windows() -> list[dict] | None:
    """Tier-1 window list (ADR-012), or None when no tier-1 backend exists.

    Returns the backend's windows as plain dicts (the ``list_windows``
    tool shape). A backend that reports available but then fails is
    treated as absent — the caller falls back to the tier-2 path.
    """
    try:
        backend = _window_control.get_backend()
    except Exception:
        return None
    if backend is None:
        return None
    try:
        available, _reason = backend.available()
        if not available:
            return None
        return [w.as_dict() for w in backend.list_windows()]
    except Exception:
        return None


@_guard
def _exec_list_windows(args, ctx):
    err = _validate(args, _SCHEMAS["list_windows"])
    if err:
        return _fail(err)
    # Tier 1 first (AT-SPI on Linux, UIA on Windows when it lands):
    # bounds, pid and active state. Tier 2 (wmctrl/xdotool, Get-Process)
    # is the fallback when no tier-1 backend is available.
    windows = _tier1_windows()
    if windows is not None:
        return _ok({"windows": windows, "count": len(windows),
                    "backend": "tier1"})
    available, reason = _os_adapter().list_windows_available()
    if not available:
        return _fail(reason, {"unavailable": True, "reason": reason})
    if _is_windows():
        # Windows lists windows via the adapter's PowerShell query;
        # the Linux wmctrl/xdotool path below does not exist there.
        windows = _os_adapter().list_windows()
    else:
        windows = _list_windows_live()
    return _ok({"windows": windows, "count": len(windows),
                "backend": "tier2"})


@_guard_verify
def _verify_list_windows(args, result, ctx):
    failed = _verify_failed(result)
    if failed:
        return failed
    windows = _tier1_windows()
    if windows is not None:
        live_ids = {str(w.get("id")) for w in windows}
        for window in result["data"].get("windows", []):
            wid = str(window.get("id"))
            if wid not in live_ids:
                return False, f"window {wid} no longer listed"
        return True, f"all {len(result['data'].get('windows', []))} windows still listed"
    available, reason = _os_adapter().list_windows_available()
    if not available:
        return False, f"window tool no longer available: {reason}"
    # Live window ids: Linux entries carry "id", Windows entries
    # carry "pid" — compare whichever the adapter returned.
    live = _os_adapter().list_windows() if _is_windows() else _list_windows_live()
    live_ids = {str(w.get("pid") or w.get("id")) for w in live}
    for window in result["data"].get("windows", []):
        wid = str(window.get("pid") or window.get("id"))
        if wid not in live_ids:
            return False, f"window {wid} no longer listed"
    return True, f"all {len(result['data'].get('windows', []))} windows still listed"


# ---------------------------------------------------------------------------
# 13b. Focus window (level 2) — tier 1 only (ADR-012)
# ---------------------------------------------------------------------------

@_guard
def _exec_window_focus(args, ctx):
    err = _validate(args, _SCHEMAS["window_focus"])
    if err:
        return _fail(err)
    window_id = args["window_id"]
    if not window_id or not isinstance(window_id, str):
        return _fail("window_id must be a non-empty string")
    backend = _window_control.get_backend()
    if backend is None:
        return _fail("no tier-1 window backend on this host; "
                     "window_focus needs AT-SPI (Linux) or UI Automation "
                     "(Windows)", {"unavailable": True})
    available, reason = backend.available()
    if not available:
        return _fail(f"window backend unavailable: {reason}",
                     {"unavailable": True, "reason": reason})
    try:
        focused = backend.focus_window(window_id)
    except _window_control.WindowControlError as exc:
        return _fail(f"window_focus failed: {exc}")
    if not focused:
        return _fail(f"window not found or ambiguous (refused): {window_id!r}")
    return _ok({"window_id": window_id, "focused": True})


@_guard_verify
def _verify_window_focus(args, result, ctx):
    failed = _verify_failed(result)
    if failed:
        return failed
    window_id = args["window_id"]
    backend = _window_control.get_backend()
    if backend is None:
        return False, "window backend no longer available"
    # Focus activation is asynchronous (the window manager updates
    # _NET_ACTIVE_WINDOW / the UIA focused element after the activation
    # request returns), so poll briefly instead of asserting on a
    # single read.
    deadline = time.monotonic() + 2.0
    last_active: str | None = None
    while True:
        try:
            active = backend.get_active_window()
        except _window_control.WindowControlError as exc:
            return False, f"could not re-read active window: {exc}"
        if active is None:
            last_active = None
        elif active.id == window_id:
            return True, f"window {window_id!r} is active"
        else:
            last_active = active.id
        if time.monotonic() >= deadline:
            break
        time.sleep(0.1)
    if last_active is None:
        return False, "no window is active after focus"
    return False, (f"window {window_id!r} is not active after focus "
                   f"(active is {last_active!r})")


# ---------------------------------------------------------------------------
# 14. Launch app (level 1)
# ---------------------------------------------------------------------------

@_guard
def _exec_launch_app(args, ctx):
    err = _validate(args, _SCHEMAS["launch_app"])
    if err:
        return _fail(err)
    app = args["app"]
    if not app:
        return _fail("app must not be empty")
    if Path(app).name in BLOCKED_BINARIES:
        return _fail(f"launching {Path(app).name!r} is blocked")
    extra = args.get("args", [])
    if "/" in app or os.sep in app:
        app_path = Path(app)
        if not app_path.is_file() or not os.access(app_path, os.X_OK):
            return _fail(f"app not found or not executable: {app!r}")
        argv = [str(app_path), *extra]
    else:
        resolved = shutil.which(app)
        if resolved is None:
            return _fail(f"app not found on PATH: {app!r}")
        argv = [resolved, *extra]
    proc = subprocess.Popen(argv, cwd=str(_workdir(ctx)),
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, start_new_session=True,
                            shell=False)
    return _ok({"app": app, "argv": argv, "pid": proc.pid})


@_guard_verify
def _verify_launch_app(args, result, ctx):
    failed = _verify_failed(result)
    if failed:
        return failed
    pid = result["data"].get("pid")
    if not pid or not Path(f"/proc/{pid}").is_dir():
        return False, f"launched process {pid} is not running"
    info = _read_process(pid)
    app = args["app"]
    if Path(app).name in (info["name"],) or app in info["cmdline"] \
            or Path(app).name in info["cmdline"]:
        return True, f"launched process running: pid {pid} ({info['name']})"
    return False, f"pid {pid} is running but does not match app {app!r}: {info['cmdline']!r}"


# ---------------------------------------------------------------------------
# 15-20. File modification (level 2)
# ---------------------------------------------------------------------------

@_guard
def _exec_write_file(args, ctx):
    err = _validate(args, _SCHEMAS["write_file"])
    if err:
        return _fail(err)
    path = _resolve(ctx, args["path"])
    if not args.get("create_parents", False) and not path.parent.is_dir():
        return _fail(f"parent directory does not exist: {path.parent}")
    existed = path.exists()
    snapshot = _snapshot(ctx, path)
    if args.get("create_parents", False):
        path.parent.mkdir(parents=True, exist_ok=True)
    content = args["content"]
    path.write_text(content, encoding="utf-8")
    return _ok({"path": str(path), "size": len(content.encode("utf-8")),
                "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                "snapshot": str(snapshot) if snapshot else None,
                "created": not existed})


@_guard_verify
def _verify_write_file(args, result, ctx):
    failed = _verify_failed(result)
    if failed:
        return failed
    path = _resolve(ctx, args["path"])
    if not path.is_file():
        return False, f"file no longer exists: {path}"
    expected = hashlib.sha256(args["content"].encode("utf-8")).hexdigest()
    actual = _hash_file(path)
    if actual != expected:
        return False, f"content hash mismatch: real={actual} expected={expected}"
    return True, f"file content matches written content (sha256 {actual[:16]}…)"


@_guard
def _exec_create_file(args, ctx):
    err = _validate(args, _SCHEMAS["create_file"])
    if err:
        return _fail(err)
    path = _resolve(ctx, args["path"])
    if path.exists():
        return _fail(f"file already exists: {args['path']!r}")
    if not path.parent.is_dir():
        return _fail(f"parent directory does not exist: {path.parent}")
    content = args.get("content", "")
    path.write_text(content, encoding="utf-8")
    return _ok({"path": str(path), "size": len(content.encode("utf-8")),
                "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest()})


@_guard_verify
def _verify_create_file(args, result, ctx):
    failed = _verify_failed(result)
    if failed:
        return failed
    path = _resolve(ctx, args["path"])
    if not path.is_file():
        return False, f"file no longer exists: {path}"
    expected = hashlib.sha256(args.get("content", "").encode("utf-8")).hexdigest()
    actual = _hash_file(path)
    if actual != expected:
        return False, f"content hash mismatch: real={actual} expected={expected}"
    return True, f"created file exists with expected content (sha256 {actual[:16]}…)"


@_guard
def _exec_append_file(args, ctx):
    err = _validate(args, _SCHEMAS["append_file"])
    if err:
        return _fail(err)
    path = _resolve(ctx, args["path"])
    if not path.parent.is_dir():
        return _fail(f"parent directory does not exist: {path.parent}")
    content = args["content"]
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(content)
    return _ok({"path": str(path), "size": path.stat().st_size,
                "sha256": _hash_file(path)})


@_guard_verify
def _verify_append_file(args, result, ctx):
    failed = _verify_failed(result)
    if failed:
        return failed
    path = _resolve(ctx, args["path"])
    if not path.is_file():
        return False, f"file no longer exists: {path}"
    if not path.read_text(encoding="utf-8", errors="replace").endswith(args["content"]):
        return False, "file does not end with the appended content"
    if _hash_file(path) != result["data"].get("sha256"):
        return False, "file hash changed after append"
    return True, "appended content present at end of file"


@_guard
def _exec_mkdir(args, ctx):
    err = _validate(args, _SCHEMAS["mkdir"])
    if err:
        return _fail(err)
    path = _resolve(ctx, args["path"])
    if path.exists():
        return _fail(f"path already exists: {args['path']!r}")
    try:
        path.mkdir(parents=bool(args.get("parents", False)))
    except FileNotFoundError:
        return _fail(f"parent directory does not exist: {path.parent} (use parents=true)")
    return _ok({"path": str(path)})


@_guard_verify
def _verify_mkdir(args, result, ctx):
    failed = _verify_failed(result)
    if failed:
        return failed
    path = _resolve(ctx, args["path"])
    if path.is_dir():
        return True, f"directory exists: {path}"
    return False, f"directory missing: {path}"


@_guard
def _exec_move_file(args, ctx):
    err = _validate(args, _SCHEMAS["move_file"])
    if err:
        return _fail(err)
    source = _resolve(ctx, args["source"])
    destination = _resolve(ctx, args["destination"])
    if not source.exists():
        return _fail(f"source does not exist: {args['source']!r}")
    if destination.exists():
        return _fail(f"destination already exists: {args['destination']!r}")
    is_dir = source.is_dir()
    sha = _hash_file(source) if source.is_file() else None
    shutil.move(str(source), str(destination))
    return _ok({"source": str(source), "destination": str(destination),
                "sha256": sha, "is_dir": is_dir})


@_guard_verify
def _verify_move_file(args, result, ctx):
    failed = _verify_failed(result)
    if failed:
        return failed
    source = _resolve(ctx, args["source"])
    destination = _resolve(ctx, args["destination"])
    if source.exists():
        return False, f"source still exists after move: {source}"
    if not destination.exists():
        return False, f"destination missing after move: {destination}"
    if not result["data"].get("is_dir"):
        actual = _hash_file(destination)
        if actual != result["data"].get("sha256"):
            return False, f"destination hash mismatch: {actual}"
    return True, f"moved: destination exists, source gone ({destination})"


@_guard
def _exec_copy_file(args, ctx):
    err = _validate(args, _SCHEMAS["copy_file"])
    if err:
        return _fail(err)
    source = _resolve(ctx, args["source"])
    destination = _resolve(ctx, args["destination"])
    if not source.is_file():
        return _fail(f"source is not a file: {args['source']!r}")
    if destination.exists():
        return _fail(f"destination already exists: {args['destination']!r}")
    sha = _hash_file(source)
    shutil.copy2(source, destination)
    return _ok({"source": str(source), "destination": str(destination), "sha256": sha})


@_guard_verify
def _verify_copy_file(args, result, ctx):
    failed = _verify_failed(result)
    if failed:
        return failed
    source = _resolve(ctx, args["source"])
    destination = _resolve(ctx, args["destination"])
    if not source.is_file():
        return False, f"source missing after copy: {source}"
    if not destination.is_file():
        return False, f"destination missing after copy: {destination}"
    if _hash_file(source) != result["data"].get("sha256"):
        return False, "source hash changed after copy"
    if _hash_file(destination) != result["data"].get("sha256"):
        return False, "destination hash does not match source"
    return True, "copy verified: source and destination hashes match"


# ---------------------------------------------------------------------------
# 21. Delete to trash (level 3) — never a hard delete
# ---------------------------------------------------------------------------

@_guard
def _exec_delete_to_trash(args, ctx):
    err = _validate(args, _SCHEMAS["delete_to_trash"])
    if err:
        return _fail(err)
    path = _resolve(ctx, args["path"])
    if not path.exists():
        return _fail(f"no such file or directory: {args['path']!r}")
    sha = _hash_file(path) if path.is_file() else None
    dest = _os_adapter().trash_path(_state_dir(ctx), path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(path), str(dest))
    return _ok({"path": str(path), "trash_path": str(dest), "sha256": sha})


@_guard_verify
def _verify_delete_to_trash(args, result, ctx):
    failed = _verify_failed(result)
    if failed:
        return failed
    path = _resolve(ctx, args["path"])
    trash = Path(result["data"].get("trash_path", ""))
    if path.exists():
        return False, f"original path still exists: {path}"
    if not trash.exists():
        return False, f"trash copy missing: {trash}"
    if result["data"].get("sha256") is not None and trash.is_file():
        if _hash_file(trash) != result["data"]["sha256"]:
            return False, "trash copy hash does not match original"
    return True, f"trashed: original gone, copy at {trash}"


# ---------------------------------------------------------------------------
# 22. Run command (level 3)
# ---------------------------------------------------------------------------

@_guard
def _exec_run_command(args, ctx):
    """Run an argv array (never a shell string).

    verify() for this tool can only confirm the process exited 0 with
    captured output — it cannot prove the command's claimed side effect.
    Callers must verify side effects with a follow-up read tool.
    """
    err = _validate(args, _SCHEMAS["run_command"])
    if err:
        return _fail(err)
    argv = args["argv"]
    if not argv or not argv[0]:
        return _fail("argv must be a non-empty list of strings")
    if Path(argv[0]).name in BLOCKED_BINARIES:
        return _fail(f"running {Path(argv[0]).name!r} is blocked")
    if _is_windows():
        # The Linux blocklist above still applies on Windows; the
        # Windows blocklist adds destructive / privilege-escalating
        # commands (format, diskpart, del, ...) and nested shells
        # (powershell, pwsh, cmd) that would defeat the argv-only
        # quoting boundary. The adapter's run_powershell enforces the
        # same list again (plus conditional blocks like `reg delete`)
        # as defence-in-depth.
        blocked = getattr(_os_adapter(), "WINDOWS_BLOCKED_COMMANDS", frozenset())
        if _windows_command_name(argv[0]) in blocked:
            return _fail(f"running {_windows_command_name(argv[0])!r} is blocked")
    if "--no-preserve-root" in argv:
        return _fail("argument '--no-preserve-root' is blocked")
    timeout = args.get("timeout", 30)
    if timeout < 1 or timeout > 60:
        return _fail("timeout must be between 1 and 60 seconds")
    cwd = _resolve(ctx, args["cwd"]) if args.get("cwd") else _workdir(ctx)
    if not cwd.is_dir():
        return _fail(f"cwd is not a directory: {args.get('cwd')!r}")
    try:
        if _is_windows():
            # Windows: argv array through PowerShell (never cmd.exe,
            # never shell=True). run_powershell raises ValueError for
            # blocked commands, which _guard turns into a clean failure.
            proc = _run_powershell(argv, timeout, cwd if args.get("cwd") else None)
        else:
            proc = subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True,
                                  timeout=timeout, shell=False)
    except subprocess.TimeoutExpired as exc:
        stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        if len(stdout) > MAX_OUTPUT_BYTES:
            stdout = stdout[:MAX_OUTPUT_BYTES]
        return _fail(f"command timed out after {timeout}s",
                     {"argv": argv, "cwd": str(cwd), "returncode": None,
                      "stdout": stdout, "stderr": "", "truncated": False,
                      "timed_out": True})
    stdout, stderr = proc.stdout or "", proc.stderr or ""
    truncated = len(stdout) > MAX_OUTPUT_BYTES or len(stderr) > MAX_OUTPUT_BYTES
    stdout, stderr = stdout[:MAX_OUTPUT_BYTES], stderr[:MAX_OUTPUT_BYTES]
    data = {"argv": argv, "cwd": str(cwd), "returncode": proc.returncode,
            "stdout": stdout, "stderr": stderr, "truncated": truncated,
            "timed_out": False}
    if proc.returncode != 0:
        return _fail(f"command exited with code {proc.returncode}", data)
    return _ok(data)


@_guard_verify
def _verify_run_command(args, result, ctx):
    failed = _verify_failed(result)
    if failed:
        return failed
    data = result["data"]
    if data.get("returncode") != 0:
        return False, f"command exited non-zero: {data.get('returncode')}"
    if "stdout" not in data or "stderr" not in data:
        return False, "no captured output to verify against"
    # LIMIT: this only confirms exit 0 + captured output. It cannot prove a
    # claimed side effect (file written, service started, ...). Verify side
    # effects with a follow-up read tool (read_file / file_info / list_dir).
    return True, (f"command exited 0 with captured output "
                  f"({len(data.get('stdout', ''))} chars stdout) — "
                  f"side effects NOT verified by this tool")

# ---------------------------------------------------------------------------
# Schemas (one per tool)
# ---------------------------------------------------------------------------

_SCHEMAS: dict[str, dict] = {
    "list_dir": _schema({"path": _STR, "recursive": _BOOL}, ["path"]),
    "read_file": _schema({"path": _STR, "max_bytes": _INT}, ["path"]),
    "file_info": _schema({"path": _STR}, ["path"]),
    "file_hash": _schema({"path": _STR,
                          "algorithm": {"type": "string", "enum": list(_HASH_ALGORITHMS)}},
                         ["path"]),
    "search_files": _schema({"path": _STR, "pattern": _STR,
                             "max_results": _INT}, ["path", "pattern"]),
    "system_info": _schema({}),
    "list_processes": _schema({"name_filter": _STR}),
    "process_info": _schema({"pid": _INT}, ["pid"]),
    "git_status": _schema({"path": _STR}, ["path"]),
    "git_log": _schema({"path": _STR, "max_count": _INT}, ["path"]),
    "git_diff": _schema({"path": _STR}, ["path"]),
    "screenshot": _schema({}),
    "list_windows": _schema({}),
    "window_focus": _schema({"window_id": _STR}, ["window_id"]),
    "launch_app": _schema({"app": _STR,
                           "args": {"type": "array", "items": {"type": "string"}}},
                          ["app"]),
    "write_file": _schema({"path": _STR, "content": _STR,
                           "create_parents": _BOOL}, ["path", "content"]),
    "create_file": _schema({"path": _STR, "content": _STR}, ["path"]),
    "append_file": _schema({"path": _STR, "content": _STR}, ["path", "content"]),
    "mkdir": _schema({"path": _STR, "parents": _BOOL}, ["path"]),
    "move_file": _schema({"source": _STR, "destination": _STR},
                         ["source", "destination"]),
    "copy_file": _schema({"source": _STR, "destination": _STR},
                         ["source", "destination"]),
    "delete_to_trash": _schema({"path": _STR}, ["path"]),
    "run_command": _schema({"argv": {"type": "array", "items": {"type": "string"}},
                            "cwd": _STR, "timeout": _INT}, ["argv"]),
}

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_SPECS: list[tuple[str, str, int, Callable, Callable]] = [
    ("list_dir", "List entries of a directory (optionally recursive)", 0,
     _exec_list_dir, _verify_list_dir),
    ("read_file", "Read a file as text (truncated at max_bytes)", 0,
     _exec_read_file, _verify_read_file),
    ("file_info", "Stat a path: size, mtime, sha256 (files), is_dir", 0,
     _exec_file_info, _verify_file_info),
    ("file_hash", "Hash a file (sha256/sha1/md5)", 0,
     _exec_file_hash, _verify_file_hash),
    ("search_files", "Find files by glob/filename-substring match", 0,
     _exec_search_files, _verify_search_files),
    ("system_info", "Host facts: platform, Python, CPU, memory, load, disk", 0,
     _exec_system_info, _verify_system_info),
    ("list_processes", "List processes from /proc, optionally name-filtered", 0,
     _exec_list_processes, _verify_list_processes),
    ("process_info", "Details of one process by pid, from /proc", 0,
     _exec_process_info, _verify_process_info),
    ("git_status", "git status (porcelain) of a repository", 0,
     _exec_git_status, _verify_git_status),
    ("git_log", "Recent git commits of a repository", 0,
     _exec_git_log, _verify_git_log),
    ("git_diff", "Uncommitted git diff of a repository", 0,
     _exec_git_diff, _verify_git_diff),
    ("screenshot", "Capture the screen (unavailable headless: honest failure)", 0,
     _exec_screenshot, _verify_screenshot),
    ("list_windows", "List open windows (unavailable headless: honest failure)", 0,
     _exec_list_windows, _verify_list_windows),
    ("window_focus", "Focus a window by its tier-1 id (AT-SPI/UIA; unavailable without a tier-1 backend)", 2,
     _exec_window_focus, _verify_window_focus),
    ("launch_app", "Launch an application (argv array, no shell)", 1,
     _exec_launch_app, _verify_launch_app),
    ("write_file", "Overwrite/create a file; original snapshotted first", 2,
     _exec_write_file, _verify_write_file),
    ("create_file", "Create a new file; fails if it already exists", 2,
     _exec_create_file, _verify_create_file),
    ("append_file", "Append text to a file (creates it if missing)", 2,
     _exec_append_file, _verify_append_file),
    ("mkdir", "Create a directory (optionally with parents)", 2,
     _exec_mkdir, _verify_mkdir),
    ("move_file", "Move/rename a file or directory", 2,
     _exec_move_file, _verify_move_file),
    ("copy_file", "Copy a file (source stays in place)", 2,
     _exec_copy_file, _verify_copy_file),
    ("delete_to_trash", "Move a path to trash (never a hard delete)", 3,
     _exec_delete_to_trash, _verify_delete_to_trash),
    ("run_command", "Run a command as an argv array (no shell); blocked binaries denied", 3,
     _exec_run_command, _verify_run_command),
]

TOOLS: dict[str, ToolSpec] = {}
for _name, _desc, _level, _exec, _verify in _SPECS:
    TOOLS[_name] = ToolSpec(name=_name, description=_desc, level=_level,
                            schema=_SCHEMAS[_name], execute=_exec, verify=_verify,
                            network=_name in NETWORK_CAPABLE_TOOLS)
del _name, _desc, _level, _exec, _verify


def get_tool(name: str) -> ToolSpec:
    """Return the ToolSpec for ``name``; raises KeyError if unknown."""
    return TOOLS[name]


def list_tools() -> list[dict]:
    """All tools as {name, description, level, network, schema} (schema deep-copied)."""
    return [{"name": spec.name, "description": spec.description,
             "level": spec.level, "network": spec.network,
             "schema": copy.deepcopy(spec.schema)}
            for spec in TOOLS.values()]
