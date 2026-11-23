"""Windows adapter stub for the Linux-first MVP (ADR-001).

Every method raises :class:`NotImplementedError`. Windows support is a
later phase; no Windows code path is reachable from the Linux MVP.
"""

from __future__ import annotations

_MSG = "Windows adapter not implemented in Linux MVP (ADR-001)"


class WindowsAdapter:
    """Placeholder Windows adapter. All methods raise NotImplementedError."""

    def __init__(self, *args, **kwargs):
        raise NotImplementedError(_MSG)

    def safe_resolve(self, *args, **kwargs):
        raise NotImplementedError(_MSG)

    def read_text(self, *args, **kwargs):
        raise NotImplementedError(_MSG)

    def write_text(self, *args, **kwargs):
        raise NotImplementedError(_MSG)

    def trash_path(self, *args, **kwargs):
        raise NotImplementedError(_MSG)

    def list_processes(self, *args, **kwargs):
        raise NotImplementedError(_MSG)

    def system_info(self, *args, **kwargs):
        raise NotImplementedError(_MSG)

    def screenshot_available(self, *args, **kwargs):
        raise NotImplementedError(_MSG)

    def list_windows_available(self, *args, **kwargs):
        raise NotImplementedError(_MSG)
