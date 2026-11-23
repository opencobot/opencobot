"""Windows adapter for OpenCobot."""

from .windows import (
    WINDOWS_BLOCKED_COMMANDS,
    list_processes,
    list_windows,
    list_windows_available,
    read_text,
    run_powershell,
    safe_resolve,
    screenshot_available,
    sha256_file,
    system_info,
    trash_path,
    write_text,
)

__all__ = [
    "WINDOWS_BLOCKED_COMMANDS",
    "list_processes",
    "list_windows",
    "list_windows_available",
    "read_text",
    "run_powershell",
    "safe_resolve",
    "screenshot_available",
    "sha256_file",
    "system_info",
    "trash_path",
    "write_text",
]
