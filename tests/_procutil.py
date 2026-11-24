"""Shared process-termination helpers for tests (BUG-D).

On Windows ``os.kill(pid, signal.SIGTERM)`` is invalid: ``os.kill``
only accepts ``CTRL_C_EVENT`` (0) / ``CTRL_BREAK_EVENT`` (1) there,
and any other signal raises ``OSError: [WinError 87]``. Test
teardowns that stop policyd / daemon / UI subprocesses used to call
``os.kill`` directly (each test file duplicating its own copy), which
broke teardown on real Windows with 8 errors across test_cli.py,
test_network_flag.py and test_r006_permissions.py.

All teardown kills must go through these helpers: on
``sys.platform == "win32"`` they use ``taskkill /F /PID <pid>`` via
``subprocess`` (argument list, no shell); elsewhere they use the
``os.kill`` signal the caller asked for. This module is test-only
(it lives under ``tests/`` and is imported as ``tests._procutil``).
"""

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

__all__ = [
    "pid_alive",
    "kill_pid",
    "force_kill_pid",
    "kill_pid_file",
    "reap_pid_file",
]


def pid_alive(pid: int) -> bool:
    """True if ``pid`` still exists.

    ``os.kill(pid, 0)`` is a liveness probe on every platform:
    CPython treats signal 0 as an existence check on Windows too,
    so no signal is delivered there either.
    """
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, owned by someone else
    except OSError:
        return False
    return True


def _taskkill(pid: int) -> None:
    """``taskkill /F /PID <pid>`` — best effort, never raises."""
    try:
        subprocess.run(
            ["taskkill", "/F", "/PID", str(pid)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError:
        pass


def kill_pid(pid: int) -> None:
    """Ask ``pid`` to stop: SIGTERM on POSIX, ``taskkill /F`` on
    Windows (where SIGTERM is not a valid ``os.kill`` signal)."""
    if sys.platform == "win32":
        _taskkill(pid)
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass


def force_kill_pid(pid: int) -> None:
    """Force-kill ``pid``: SIGKILL on POSIX. ``taskkill /F`` is
    already forceful on Windows, so it is the same call there."""
    if sys.platform == "win32":
        _taskkill(pid)
        return
    try:
        os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _read_pid_file(pid_path: Path) -> int | None:
    try:
        return int(pid_path.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return None


def kill_pid_file(state_dir, name: str) -> None:
    """Terminate the process named by ``<state_dir>/<name>`` (a pid
    file), if it exists. Missing file / unparsable pid / already-dead
    process are all silent no-ops."""
    pid_path = Path(state_dir) / name
    if not pid_path.exists():
        return
    pid = _read_pid_file(pid_path)
    if pid is None:
        return
    kill_pid(pid)


def reap_pid_file(state_dir, name: str, timeout: float = 2.0) -> None:
    """Wait up to ``timeout`` seconds for the process named by
    ``<state_dir>/<name>`` to exit, then force-kill it if it is
    still alive. Silent no-op when the pid file is absent."""
    pid_path = Path(state_dir) / name
    if not pid_path.exists():
        return
    pid = _read_pid_file(pid_path)
    if pid is None:
        return
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not pid_alive(pid):
            return
        time.sleep(0.05)
    force_kill_pid(pid)
