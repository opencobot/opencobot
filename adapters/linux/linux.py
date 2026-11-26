"""Linux OS adapter for OpenCobot (Phase 1 Linux MVP).

Stdlib only. All path handling goes through :func:`safe_resolve`, which
resolves symlinks and refuses any path outside the allowed roots — the
primary defence against path-traversal input from a model.
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

__all__ = [
    "safe_resolve",
    "read_text",
    "write_text",
    "trash_path",
    "list_processes",
    "system_info",
    "screenshot_available",
    "list_windows_available",
]

_SCREENSHOT_TOOLS = ("scrot", "import", "gnome-screenshot")
_WINDOW_TOOLS = ("wmctrl", "xdotool")


def safe_resolve(base: Path, user_path: str, allowed_roots=None) -> Path:
    """Resolve ``user_path`` against ``base`` and require it to stay in scope.

    Relative paths are joined to ``base``; absolute paths are used as-is.
    Symlinks are resolved (``Path.resolve()``) before the containment check,
    so ``..`` segments and symlink escapes are both caught. Raises
    :class:`ValueError` if the resolved path is not under ``base`` or one of
    ``allowed_roots``. ``base`` itself is allowed.
    """
    if not isinstance(user_path, str) or not user_path:
        raise ValueError("path must be a non-empty string")
    base = Path(base).expanduser().resolve()
    candidate = Path(user_path).expanduser()
    if not candidate.is_absolute():
        candidate = base / candidate
    resolved = candidate.resolve()
    roots = [base]
    for root in allowed_roots or []:
        roots.append(Path(root).expanduser().resolve())
    for root in roots:
        if resolved.is_relative_to(root):
            return resolved
    raise ValueError(f"path outside allowed scope: {user_path!r}")


def read_text(path: Path, max_bytes: int | None = None) -> str:
    """Read a file as UTF-8 (replacement characters for undecodable bytes)."""
    data = Path(path).read_bytes()
    if max_bytes is not None:
        data = data[:max_bytes]
    return data.decode("utf-8", errors="replace")


def write_text(path: Path, content: str, create_parents: bool = False) -> Path:
    """Write ``content`` as UTF-8. Returns the resolved path written."""
    path = Path(path)
    if create_parents:
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def trash_path(state_dir: Path, original: Path) -> Path:
    """Destination for a trashed file: XDG Trash if present, else state trash.

    Preserves the original path (minus the leading ``/``) under the trash
    root and appends a UTC timestamp to the filename so repeated trashes of
    the same path never collide.
    """
    xdg_trash = Path("~/.local/share/Trash/files").expanduser()
    base = xdg_trash if xdg_trash.is_dir() else Path(state_dir) / "trash"
    original = Path(original)
    rel = Path(*original.parts[1:]) if original.is_absolute() else original
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    return base / rel.parent / f"{rel.name}.{stamp}"


def _process_starttime(pid: int) -> int | None:
    """Start time of a process, in clock ticks since boot (``/proc`` stat field 22).

    Best-effort: returns ``None`` when the row disappears mid-scan or does
    not parse. The value is invariant across ``exec()`` (same pid, new
    program), which makes it the stable half of a process identity — see
    :func:`tools.definitions._verify_list_processes`.
    """
    try:
        stat = (Path("/proc") / str(pid) / "stat").read_text(
            encoding="utf-8", errors="replace"
        )
        # Format: ``pid (comm) state ppid ...``; comm may contain spaces or
        # parens, so split on the LAST ')'. Fields after comm start at
        # field 3, so starttime (field 22) is index 19 of the remainder.
        fields = stat.rsplit(")", 1)[1].split()
        return int(fields[19])
    except (OSError, ValueError, IndexError):
        return None


def list_processes(name_filter: str | None = None) -> list[dict]:
    """List processes from /proc (no ``ps`` dependency).

    Each entry: ``{"pid": int, "name": str, "cmdline": str}`` plus
    ``"starttime": int`` when ``/proc/<pid>/stat`` could be read (clock
    ticks since boot; invariant across ``exec()``). Entries whose /proc
    rows disappear mid-scan are skipped.
    """
    processes: list[dict] = []
    proc = Path("/proc")
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            pid = int(entry.name)
            name = (entry / "comm").read_text(encoding="utf-8", errors="replace").strip()
            raw = (entry / "cmdline").read_bytes()
            cmdline = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        except (OSError, ValueError):
            continue
        if name_filter and name_filter.lower() not in name.lower() \
                and name_filter.lower() not in cmdline.lower():
            continue
        item: dict = {"pid": pid, "name": name, "cmdline": cmdline}
        starttime = _process_starttime(pid)
        if starttime is not None:
            item["starttime"] = starttime
        processes.append(item)
    processes.sort(key=lambda p: p["pid"])
    return processes


def system_info(workdir: Path | None = None) -> dict:
    """Host facts: platform, Python, CPUs, memory, load, disk of workdir."""
    mem_total = mem_available = None
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition(":")
            if key == "MemTotal":
                mem_total = int(value.split()[0]) * 1024
            elif key == "MemAvailable":
                mem_available = int(value.split()[0]) * 1024
    except OSError:
        pass
    disk = None
    if workdir is not None:
        usage = shutil.disk_usage(str(workdir))
        disk = {"path": str(workdir), "total": usage.total,
                "used": usage.used, "free": usage.free}
    return {
        "platform": platform.system(),
        "platform_release": platform.release(),
        "machine": platform.machine(),
        "python_version": sys.version.split()[0],
        "cpu_count": os.cpu_count(),
        "memory_total_bytes": mem_total,
        "memory_available_bytes": mem_available,
        "load_average": list(os.getloadavg()) if hasattr(os, "getloadavg") else None,
        "disk": disk,
    }


def screenshot_available() -> tuple[bool, str]:
    """(True, reason) only if a display server AND a screenshot tool exist."""
    display = os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
    if not display:
        return False, "no display server (DISPLAY/WAYLAND_DISPLAY unset)"
    for tool in _SCREENSHOT_TOOLS:
        if shutil.which(tool):
            return True, f"display present, screenshot tool available: {tool}"
    return False, "no screenshot tool (scrot/import/gnome-screenshot not found)"


def list_windows_available() -> tuple[bool, str]:
    """(True, reason) if a window-listing path exists.

    Tier 1 first (ADR-012): the AT-SPI backend, when its library loads
    and the session bus + registry answer. Tier 2: a display server AND
    wmctrl/xdotool.
    """
    try:
        from core import window_control as _wc
        backend = _wc.get_backend()
        if backend is not None:
            available, reason = backend.available()
            if available:
                return True, f"tier-1 window backend available: {reason}"
    except Exception:
        pass  # fall through to the tier-2 check
    display = os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
    if not display:
        return False, "no display server (DISPLAY/WAYLAND_DISPLAY unset)"
    for tool in _WINDOW_TOOLS:
        if shutil.which(tool):
            return True, f"display present, window tool available: {tool}"
    return False, "no window-listing tool (wmctrl/xdotool not found)"


def sha256_file(path: Path) -> str:
    """SHA-256 hex digest of a file, streamed (no whole-file read)."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_git(repo_path: Path, argv: list[str], timeout: int = 15) -> subprocess.CompletedProcess:
    """Run ``git`` with an argv array only, cwd=repo_path. No shell."""
    if shutil.which("git") is None:
        raise FileNotFoundError("git binary not found")
    return subprocess.run(
        ["git", *argv], cwd=str(repo_path), capture_output=True,
        text=True, timeout=timeout, shell=False,
    )


def is_git_repo(path: Path) -> bool:
    """True iff ``path`` is inside a git working tree."""
    try:
        result = run_git(Path(path), ["rev-parse", "--git-dir"], timeout=10)
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return False
    return result.returncode == 0
