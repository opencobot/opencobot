# adapters/linux/

Linux implementations behind the tool interface (Phase 1, Linux MVP).

- `linux.py` — `safe_resolve` (symlink-resolving, scope-checked), file read/write helpers, trash path, process listing from `/proc`, system info, `screenshot_available` / `list_windows_available` (honest headless detection), git helpers.
- Tools call the adapter; they never shell out to `ps`, `ls` or similar.

Supported in Phase 1: any Linux with Python 3.10+; screenshot/window tools need a display server (`DISPLAY` or `WAYLAND_DISPLAY`) plus `scrot`/`import`/`gnome-screenshot` or `wmctrl`/`xdotool`, and report "unavailable" without them.
