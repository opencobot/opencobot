# tools/

Tool definitions (JSON Schema) and implementations (Phase 1, Linux MVP).

Every tool declares `execute()` and `verify()`. See [ARCHITECTURE.md §4](../ARCHITECTURE.md).

## The 23 tools

| Level | Tools |
|-------|-------|
| 0 — read/inspect | `list_dir`, `read_file`, `file_info`, `file_hash`, `search_files`, `system_info`, `list_processes`, `process_info`, `git_status`, `git_log`, `git_diff`, `screenshot`, `list_windows` |
| 1 — basic interaction | `launch_app` |
| 2 — controlled modification | `write_file`, `create_file`, `append_file`, `mkdir`, `move_file`, `copy_file`, `window_focus` |
| 3 — sensitive (approval required) | `delete_to_trash`, `run_command` |

Notes:

- `delete_to_trash` never hard-deletes; files go to the trash directory.
- `run_command` takes an argv array only (`shell=False`); `sudo`/`su`/`doas`/`rm` as argv[0] are blocked, output is truncated, timeout is clamped to 1–60s.
- `screenshot` and `list_windows` honestly report "unavailable" on a headless server instead of faking success.
- `window_focus` (ADR-012) is tier-1 only: it needs the AT-SPI backend on Linux (UI Automation on Windows lands later) and refuses when the window id is not found or ambiguous.
- Every file tool re-checks its paths against the capability-token scope (symlink/`..` escapes are denied).
- There is no Level 4 tool in Phase 1; Level 4 is enforced by the policy engine and covered by policy tests.
