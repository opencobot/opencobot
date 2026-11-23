"""Linux adapter for OpenCobot (Phase 1 Linux MVP)."""

from .linux import (
    is_git_repo,
    list_processes,
    list_windows_available,
    read_text,
    run_git,
    safe_resolve,
    screenshot_available,
    sha256_file,
    system_info,
    trash_path,
    write_text,
)

__all__ = [
    "is_git_repo",
    "list_processes",
    "list_windows_available",
    "read_text",
    "run_git",
    "safe_resolve",
    "screenshot_available",
    "sha256_file",
    "system_info",
    "trash_path",
    "write_text",
]
