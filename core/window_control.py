"""Tier-1 window control backends (ADR-012).

Stdlib only. The common interface is :class:`WindowBackend`; the Linux
implementation is :class:`AtspiBackend`, which discovers windows through
the AT-SPI accessibility bus (``libatspi.so.0`` via :mod:`ctypes` — no
pyatspi, no D-Bus Python binding, the same stdlib-only precedent as the
``ctypes`` Win32 named-pipe listener in ADR-010) and activates them
through the window manager via the EWMH ``_NET_ACTIVE_WINDOW`` protocol
(``libX11.so.6`` via :mod:`ctypes`).

Why two libraries: discovery and activation are different operations,
and AT-SPI only does the first one well. Verified live 2026-11-26 —
``atspi_component_grab_focus`` on a toplevel frame is answered by the
app (GTK/ATK) with ``org.freedesktop.DBus.Error.NotSupported``, and the
frame's AT-SPI state set reports neither ACTIVE nor VISIBLE even when
the window manager has it focused (``xdotool getactivewindow`` says
otherwise). ``GrabFocus`` is a widget-focus primitive, not window
activation; activating a window is a window-manager operation, and the
standard WM-compliant way on X11 is the ``_NET_ACTIVE_WINDOW`` client
message. So: AT-SPI lists windows and their bounds; X11 (EWMH) reads
the active window and activates one. The X window is resolved from the
AT-SPI window by (pid, title) — never by title substring alone — so
the wrong-window risk R-029 stays closed.

A window is identified by a backend-opaque id: ``atspi:<pid>:<title>``
on Linux. (The C API's ``atspi_accessible_get_accessible_id`` returns
an empty string for ordinary windows — verified live 2026-11-26 — so it
cannot serve as the id.) Focus resolves an id by (pid, title) and
refuses when the match is ambiguous (fail closed, R-029).

Graceful degradation is the rule: if the library is missing, there is
no session bus, the registry is unreachable, or there is no desktop
session, :meth:`AtspiBackend.available` returns ``(False, reason)``
and the other methods raise :class:`WindowControlUnavailable`. When
there is no X display (Wayland without XWayland, or headless), the
active/focus path falls back to the AT-SPI STATE_ACTIVE flag for
``active`` and ``focus_window`` returns False — activation needs a
window manager, and there is no WM protocol to speak to. Nothing here
ever raises on import and nothing ever crashes the caller for want of
a display.

Memory discipline (libatspi hands out owned references): every string
returned by the C API is copied to :class:`bytes` and freed with
``g_free``; every accessible obtained from the tree is released with
``g_object_unref``; every ``GError`` is freed with ``g_error_free``;
component interfaces are borrowed views of the same object and are
NEVER unref'd separately. Rects from ``atspi_component_get_extents``
are freed with ``atspi_rect_free`` when the symbol exists. X11
displays are opened per operation and closed again (``XCloseDisplay``)
so no stale display handle survives the X server going away.

The Windows implementation is :class:`UiaBackend`, which reaches UI
Automation through the adapter's existing fixed-script PowerShell
path (ADR-012 (b)): a fixed ``powershell.exe -Command`` script (never
built from model input) loads the .NET ``UIAutomationClient`` wrapper,
enumerates ``AutomationElement.RootElement`` children, and reports
name / pid / native window handle / bounding rectangle / foreground
state as JSON. Focus uses ``AutomationElement.FromHandle(hwnd)`` +
``SetFocus()`` and then checks the foreground window, so a request
the window manager ignored reports False instead of claiming success.
Window ids are ``uia:<hwnd>`` — the handle is the identity, never a
title substring (R-029). The hwnd that reaches the script is parsed
to :class:`int` first, so the only characters that can ever appear in
the command are digits. UIA is mock-tested on Linux only (a fake
PowerShell runner); it has never run on a real Windows host yet —
its live run is a laptop step, like every other Windows path.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import json
import os
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Protocol

__all__ = [
    "WindowInfo",
    "WindowBackend",
    "WindowControlError",
    "WindowControlUnavailable",
    "AtspiBackend",
    "UiaBackend",
    "get_backend",
    "reset_backend",
    "list_windows",
    "get_active_window",
    "focus_window",
    "window_bounds",
]

# Verified against GNOME libatspi docs (2026-11-26):
#   ATSPI_STATE_ACTIVE = 1, ATSPI_COORD_TYPE_SCREEN = 0.
_ATSPI_STATE_ACTIVE = 1
_ATSPI_COORD_TYPE_SCREEN = 0

# Top-level window roles, compared as role NAME strings (never numeric
# enums — the names are stable across libatspi versions).
_WINDOW_ROLES = frozenset({"frame", "dialog", "window", "alert"})

# D-Bus calls through libatspi are capped so a hung registry cannot stall
# the daemon (atspi_set_timeout(value_ms, startup_ms)).
_ATSPI_TIMEOUT_MS = 2000
_ATSPI_STARTUP_MS = 2000


class WindowControlError(Exception):
    """Base error for window-control failures."""


class WindowControlUnavailable(WindowControlError):
    """No tier-1 backend is available on this host/session."""


@dataclass(frozen=True)
class WindowInfo:
    """One top-level window, as seen through the accessibility tree."""

    id: str  # backend-opaque, e.g. "atspi:1234:My Window"
    title: str
    app_name: str
    pid: int
    bounds: tuple[int, int, int, int] | None  # (x, y, width, height), screen coords
    active: bool

    def as_dict(self) -> dict:
        """JSON-friendly form, as returned by the ``list_windows`` tool."""
        return {
            "id": self.id,
            "title": self.title,
            "app_name": self.app_name,
            "pid": self.pid,
            "bounds": list(self.bounds) if self.bounds is not None else None,
            "active": self.active,
        }


class WindowBackend(Protocol):
    """A tier-1 accessibility-tree backend (ADR-012)."""

    def available(self) -> tuple[bool, str]:
        """(True, reason) when this backend can list windows now."""
        ...

    def list_windows(self) -> list[WindowInfo]:
        """All top-level windows. Raises WindowControlError on failure."""
        ...

    def get_active_window(self) -> WindowInfo | None:
        """The active window, or None when none is active."""
        ...

    def focus_window(self, window_id: str) -> bool:
        """Bring the window with this id to the front. False when not found."""
        ...

    def window_bounds(self, window_id: str) -> tuple[int, int, int, int] | None:
        """Screen bounds of the window, or None when not found / no bounds."""
        ...


class _AtspiRect(ctypes.Structure):
    _fields_ = [
        ("x", ctypes.c_int),
        ("y", ctypes.c_int),
        ("width", ctypes.c_int),
        ("height", ctypes.c_int),
    ]


class _AtspiLib:
    """Thin :mod:`ctypes` binding over ``libatspi.so.0`` + glib/gobject.

    ``lib`` may be injected (a fake) for tests; otherwise the real shared
    libraries are loaded. Every function that takes a ``GError**`` gets a
    real pointer, which is checked and freed after the call.
    """

    def __init__(self, lib=None, gobject=None, glib=None):
        if lib is None:
            lib = ctypes.CDLL("libatspi.so.0", use_errno=True)
            gobject = ctypes.CDLL("libgobject-2.0.so.0", use_errno=True)
            glib = ctypes.CDLL("libglib-2.0.so.0", use_errno=True)
        else:
            # An injected fake stands in for all three libraries: it must
            # expose the atspi_* functions plus g_object_unref/g_free/
            # g_error_free.
            gobject = glib = lib
        self._lib = lib
        self._gobject = gobject
        self._glib = glib
        self._bind()

    # -- binding ------------------------------------------------------
    def _bind(self):
        lib = self._lib
        c_void_p = ctypes.c_void_p
        c_int = ctypes.c_int
        c_bool = ctypes.c_bool
        err_pp = ctypes.POINTER(c_void_p)

        def fn(name, restype, argtypes):
            f = getattr(lib, name)
            f.restype = restype
            f.argtypes = argtypes
            return f

        self.atspi_init = fn("atspi_init", c_int, [])
        self.atspi_exit = fn("atspi_exit", None, [])
        self.atspi_is_initialized = fn("atspi_is_initialized", c_bool, [])
        self.atspi_set_timeout = fn("atspi_set_timeout", None, [c_int, c_int])
        self.atspi_get_desktop_count = fn("atspi_get_desktop_count", c_int, [])
        self.atspi_get_desktop = fn("atspi_get_desktop", c_void_p, [c_int])
        self.atspi_accessible_get_child_count = fn(
            "atspi_accessible_get_child_count", c_int, [c_void_p, err_pp])
        self.atspi_accessible_get_child_at_index = fn(
            "atspi_accessible_get_child_at_index", c_void_p,
            [c_void_p, c_int, err_pp])
        self.atspi_accessible_get_name = fn(
            "atspi_accessible_get_name", c_void_p, [c_void_p, err_pp])
        self.atspi_accessible_get_role_name = fn(
            "atspi_accessible_get_role_name", c_void_p, [c_void_p, err_pp])
        self.atspi_accessible_get_application = fn(
            "atspi_accessible_get_application", c_void_p, [c_void_p, err_pp])
        self.atspi_accessible_get_component_iface = fn(
            "atspi_accessible_get_component_iface", c_void_p, [c_void_p])
        self.atspi_accessible_get_state_set = fn(
            "atspi_accessible_get_state_set", c_void_p, [c_void_p])
        self.atspi_accessible_get_process_id = fn(
            "atspi_accessible_get_process_id", c_int, [c_void_p, err_pp])
        self.atspi_accessible_get_accessible_id = fn(
            "atspi_accessible_get_accessible_id", c_void_p, [c_void_p, err_pp])
        self.atspi_component_get_extents = fn(
            "atspi_component_get_extents",
            ctypes.POINTER(_AtspiRect), [c_void_p, c_int, err_pp])
        self.atspi_state_set_contains = fn(
            "atspi_state_set_contains", c_bool, [c_void_p, c_int])
        # atspi_rect_free exists in libatspi >= 2.0; guard for old builds.
        self.atspi_rect_free = getattr(lib, "atspi_rect_free", None)
        if self.atspi_rect_free is not None:
            self.atspi_rect_free.restype = None
            self.atspi_rect_free.argtypes = [ctypes.POINTER(_AtspiRect)]

        self.g_object_unref = self._gobject.g_object_unref
        self.g_object_unref.restype = None
        self.g_object_unref.argtypes = [c_void_p]
        self.g_free = self._glib.g_free
        self.g_free.restype = None
        self.g_free.argtypes = [c_void_p]
        self.g_error_free = self._glib.g_error_free
        self.g_error_free.restype = None
        self.g_error_free.argtypes = [c_void_p]

    # -- helpers ------------------------------------------------------
    def new_error(self):
        """A fresh ``GError*`` slot (NULL) to pass as ``GError**``."""
        return ctypes.c_void_p(0)

    def check_error(self, err) -> bool:
        """True when ``err`` was set; frees it either way it was set."""
        if err.value is not None:
            self.g_error_free(err)
            return True
        return False

    def take_string(self, ptr) -> str:
        """Copy a C string the caller owns, then free it. NULL -> \"\"."""
        if not ptr:
            return ""
        text = ctypes.string_at(ptr).decode("utf-8", "replace")
        self.g_free(ptr)
        return text


class _XClientMessageEvent(ctypes.Structure):
    """XClientMessageEvent for the _NET_ACTIVE_WINDOW request."""

    _fields_ = [
        ("type", ctypes.c_int),
        ("serial", ctypes.c_ulong),
        ("send_event", ctypes.c_int),
        ("display", ctypes.c_void_p),
        ("window", ctypes.c_ulong),
        ("message_type", ctypes.c_ulong),
        ("format", ctypes.c_int),
        ("data", ctypes.c_long * 5),
    ]


class _X11:
    """Thin :mod:`ctypes` binding over ``libX11.so.6`` for EWMH.

    Only the three operations window control needs: read the active
    window (``_NET_ACTIVE_WINDOW``), resolve an X window id by pid
    (``_NET_CLIENT_LIST`` + ``_NET_WM_PID``), and ask the window
    manager to activate a window (``_NET_ACTIVE_WINDOW`` client
    message). ``lib`` may be injected (a fake) for tests. The display
    is opened per operation and closed again — no handle is kept
    across calls, so a dead X server cannot leave a stale handle.
    """

    def __init__(self, lib=None):
        if lib is None:
            try:
                lib = ctypes.CDLL("libX11.so.6", use_errno=True)
            except OSError:
                name = ctypes.util.find_library("X11")
                lib = ctypes.CDLL(name, use_errno=True) if name else None
                if lib is None:
                    raise OSError("libX11.so.6 not found")
        self._lib = lib
        self._bind()
        self._available: bool | None = None

    def _bind(self):
        lib = self._lib
        c_void_p = ctypes.c_void_p
        c_ulong = ctypes.c_ulong
        c_int = ctypes.c_int
        self.XOpenDisplay = lib.XOpenDisplay
        self.XOpenDisplay.restype = c_void_p
        self.XOpenDisplay.argtypes = [ctypes.c_char_p]
        self.XCloseDisplay = lib.XCloseDisplay
        self.XCloseDisplay.restype = c_int
        self.XCloseDisplay.argtypes = [c_void_p]
        self.XDefaultRootWindow = lib.XDefaultRootWindow
        self.XDefaultRootWindow.restype = c_ulong
        self.XDefaultRootWindow.argtypes = [c_void_p]
        self.XInternAtom = lib.XInternAtom
        self.XInternAtom.restype = c_ulong
        self.XInternAtom.argtypes = [c_void_p, ctypes.c_char_p, c_int]
        self.XGetWindowProperty = lib.XGetWindowProperty
        self.XGetWindowProperty.restype = c_int
        self.XGetWindowProperty.argtypes = [
            c_void_p, c_ulong, c_ulong, ctypes.c_long, ctypes.c_long,
            c_int, c_ulong,
            ctypes.POINTER(c_ulong), ctypes.POINTER(c_int),
            ctypes.POINTER(c_ulong), ctypes.POINTER(c_ulong),
            ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
        self.XFree = lib.XFree
        self.XFree.restype = c_int
        self.XFree.argtypes = [c_void_p]
        self.XSendEvent = lib.XSendEvent
        self.XSendEvent.restype = c_int
        self.XSendEvent.argtypes = [
            c_void_p, c_ulong, c_int, ctypes.c_long, c_void_p]
        self.XFlush = lib.XFlush
        self.XFlush.restype = c_int
        self.XFlush.argtypes = [c_void_p]

    # -- display ------------------------------------------------------
    def _open(self):
        """Open the default display, or None when there is none."""
        display = os.environ.get("DISPLAY")
        if not display:
            return None
        try:
            dpy = self.XOpenDisplay(display.encode())
        except Exception:
            return None
        return dpy or None

    def available(self) -> bool:
        """True when libX11 loads and a display opens."""
        if self._available is None:
            dpy = self._open()
            self._available = dpy is not None
            if dpy is not None:
                self.XCloseDisplay(dpy)
        return self._available

    # -- properties -----------------------------------------------------
    def _get_property(self, dpy, window, atom, req_type):
        """(format, raw bytes) for a window property, or None."""
        actual_type = ctypes.c_ulong(0)
        actual_format = ctypes.c_int(0)
        nitems = ctypes.c_ulong(0)
        after = ctypes.c_ulong(0)
        data = ctypes.POINTER(ctypes.c_ubyte)()
        rc = self.XGetWindowProperty(
            dpy, window, atom, 0, 1024, 0, req_type,
            ctypes.byref(actual_type), ctypes.byref(actual_format),
            ctypes.byref(nitems), ctypes.byref(after), ctypes.byref(data))
        if rc != 0 or not data:
            return None
        try:
            fmt = actual_format.value
            if fmt == 32:
                count = nitems.value
                vals = ctypes.cast(data, ctypes.POINTER(ctypes.c_ulong))
                raw = b"".join(
                    int(vals[i]).to_bytes(8, "little") for i in range(count))
                return fmt, raw
            if fmt == 8:
                raw = ctypes.string_at(data, nitems.value)
                return fmt, raw
            return None
        finally:
            self.XFree(data)

    def _atom(self, dpy, name):
        return self.XInternAtom(dpy, name.encode(), 0)

    def _longs(self, dpy, window, atom_name, type_name):
        """Property values as ints (format 32), or None."""
        got = self._get_property(dpy, window, self._atom(dpy, atom_name),
                                 self._atom(dpy, type_name))
        if got is None:
            return None
        fmt, raw = got
        if fmt != 32:
            return None
        return [int.from_bytes(raw[i:i + 8], "little")
                for i in range(0, len(raw), 8)]

    def _window_title(self, dpy, window):
        """_NET_WM_NAME (UTF-8), else WM_NAME, else None."""
        for atom_name, type_name in (("_NET_WM_NAME", "UTF8_STRING"),
                                     ("WM_NAME", "STRING")):
            got = self._get_property(dpy, window, self._atom(dpy, atom_name),
                                     self._atom(dpy, type_name))
            if got is not None and got[0] == 8:
                return got[1].decode("utf-8", "replace")
        return None

    # -- EWMH operations --------------------------------------------------
    def active_key(self) -> tuple[int, str | None] | None:
        """(pid, title) of the active window, or None when there is none."""
        dpy = self._open()
        if dpy is None:
            return None
        try:
            root = self.XDefaultRootWindow(dpy)
            active = self._longs(dpy, root, "_NET_ACTIVE_WINDOW", "WINDOW")
            if not active:
                return None
            xid = active[0]
            if xid == 0:
                return None
            pid = self._longs(dpy, xid, "_NET_WM_PID", "CARDINAL")
            if not pid:
                return None
            return pid[0], self._window_title(dpy, xid)
        finally:
            self.XCloseDisplay(dpy)

    def window_id_for_pid(self, pid: int, title: str | None = None) -> int | None:
        """X window id for (pid, title); title disambiguates same-pid apps.

        Returns the title-matching window when one exists, else the
        first window owned by the pid, else None.
        """
        dpy = self._open()
        if dpy is None:
            return None
        try:
            root = self.XDefaultRootWindow(dpy)
            clients = self._longs(dpy, root, "_NET_CLIENT_LIST", "WINDOW")
            if not clients:
                return None
            first_for_pid: int | None = None
            for xid in clients:
                pids = self._longs(dpy, xid, "_NET_WM_PID", "CARDINAL")
                if not pids or pids[0] != pid:
                    continue
                if first_for_pid is None:
                    first_for_pid = xid
                if title is not None and self._window_title(dpy, xid) == title:
                    return xid
            return first_for_pid
        finally:
            self.XCloseDisplay(dpy)

    def activate(self, window_id: int) -> bool:
        """Ask the window manager to activate ``window_id`` (EWMH).

        Sends a ``_NET_ACTIVE_WINDOW`` client message to the root
        window (source indication 2 = pager). Returns True when the
        message was sent; the WM applies it asynchronously.
        """
        dpy = self._open()
        if dpy is None:
            return False
        try:
            root = self.XDefaultRootWindow(dpy)
            message_type = self._atom(dpy, "_NET_ACTIVE_WINDOW")
            ev = _XClientMessageEvent()
            ev.type = 33  # ClientMessage
            ev.serial = 0
            ev.send_event = 1
            ev.display = dpy
            ev.window = window_id
            ev.message_type = message_type
            ev.format = 32
            ev.data[0] = 2  # source indication: pager / application
            ev.data[1] = 0  # timestamp (0 lets the WM fill in CurrentTime)
            ev.data[2] = 0  # currently active window (unknown here)
            ev.data[3] = 0
            ev.data[4] = 0
            # SubstructureRedirectMask | SubstructureNotifyMask
            mask = (1 << 20) | (1 << 19)
            sent = self.XSendEvent(dpy, root, 0, mask, ctypes.byref(ev))
            self.XFlush(dpy)
            return bool(sent)
        finally:
            self.XCloseDisplay(dpy)


class AtspiBackend:
    """AT-SPI tier-1 backend for Linux (ADR-012).

    ``lib`` is an injected :class:`_AtspiLib` (or fake) for tests and
    ``x11`` an injected :class:`_X11` (or fake); by default the real
    libraries are loaded lazily. Loading is lazy: the constructor never
    raises for a missing library — :meth:`available` reports it
    instead.
    """

    def __init__(self, lib: _AtspiLib | None = None,
                 x11: _X11 | None = None):
        self._lib = lib
        self._lib_error: str | None = None
        self._initialized = False
        self._init_error: str | None = None
        self._x11 = x11
        self._x11_error: str | None = None

    # -- lifecycle ----------------------------------------------------
    def _load(self) -> _AtspiLib | None:
        if self._lib is not None:
            return self._lib
        if self._lib_error is not None:
            return None
        try:
            self._lib = _AtspiLib()
        except OSError as exc:  # library (or a dependency) is missing
            self._lib_error = f"libatspi.so.0 not loadable: {exc}"
            return None
        return self._lib

    def _load_x11(self) -> _X11 | None:
        if self._x11 is not None:
            return self._x11
        if self._x11_error is not None:
            return None
        try:
            self._x11 = _X11()
        except OSError as exc:
            self._x11_error = f"libX11.so.6 not loadable: {exc}"
            return None
        return self._x11

    def _ensure_init(self) -> bool:
        if self._initialized:
            return True
        if self._init_error is not None:
            return False
        lib = self._load()
        if lib is None:
            self._init_error = self._lib_error or "libatspi unavailable"
            return False
        try:
            lib.atspi_set_timeout(_ATSPI_TIMEOUT_MS, _ATSPI_STARTUP_MS)
            # NOTE: atspi_init()'s return value is the ONLY reliable
            # signal. Verified live 2026-11-26: with no bus it returns 2
            # while atspi_is_initialized() still reports True, and the
            # next call that touches the bus (atspi_get_desktop) ABORTS
            # the process (GLib dbind-ERROR). So init != 0 is a hard
            # failure and no further libatspi call is made afterwards.
            ret = lib.atspi_init()
            if ret != 0:
                self._init_error = (
                    f"atspi_init() failed (code {ret}): no session bus / "
                    "accessibility registry (is at-spi-bus-launcher running?)")
                return False
            if not lib.atspi_is_initialized():
                self._init_error = "atspi_init() returned 0 but AT-SPI is not initialized"
                return False
        except Exception as exc:  # ctypes errors, D-Bus failures: fail closed
            self._init_error = f"AT-SPI init failed: {exc}"
            return False
        self._initialized = True
        return True

    def available(self) -> tuple[bool, str]:
        if self._ensure_init():
            return True, "AT-SPI backend available"
        return False, self._init_error or "AT-SPI unavailable"

    # -- active-window resolution ---------------------------------------
    def _active_key(self) -> tuple[bool, tuple[int, str | None] | None]:
        """(x11_usable, active (pid, title)).

        Primary source is the X11 ``_NET_ACTIVE_WINDOW`` property —
        the window manager's own record, which is reliable where the
        AT-SPI state set is not (verified live 2026-11-26: the frame
        reported neither ACTIVE nor VISIBLE while the WM had it
        focused). When no X display is usable the caller falls back
        to the AT-SPI STATE_ACTIVE flag.
        """
        x11 = self._load_x11()
        if x11 is None or not x11.available():
            return False, None
        return True, x11.active_key()

    # -- tree walking ---------------------------------------------------
    def _child_count(self, lib: _AtspiLib, acc: int) -> int:
        err = lib.new_error()
        count = lib.atspi_accessible_get_child_count(acc, ctypes.byref(err))
        if lib.check_error(err):
            return 0
        return max(count, 0)

    def _child_at(self, lib: _AtspiLib, acc: int, index: int) -> int | None:
        err = lib.new_error()
        child = lib.atspi_accessible_get_child_at_index(
            acc, index, ctypes.byref(err))
        if lib.check_error(err) or not child:
            return None
        return child

    def _is_window(self, lib: _AtspiLib, acc: int) -> bool:
        err = lib.new_error()
        role = lib.atspi_accessible_get_role_name(acc, ctypes.byref(err))
        if lib.check_error(err):
            return False
        return lib.take_string(role) in _WINDOW_ROLES

    def _bounds(self, lib: _AtspiLib, acc: int) -> tuple[int, int, int, int] | None:
        comp = lib.atspi_accessible_get_component_iface(acc)
        if not comp:
            return None
        err = lib.new_error()
        rect = lib.atspi_component_get_extents(
            comp, _ATSPI_COORD_TYPE_SCREEN, ctypes.byref(err))
        if lib.check_error(err) or not rect:
            return None
        try:
            x, y, w, h = rect.contents.x, rect.contents.y, rect.contents.width, rect.contents.height
        finally:
            if lib.atspi_rect_free is not None:
                lib.atspi_rect_free(rect)
        if (x, y, w, h) == (-1, -1, -1, -1):
            return None  # not visible / no meaningful extents
        return (x, y, w, h)

    def _is_active_state(self, lib: _AtspiLib, acc: int) -> bool:
        """AT-SPI STATE_ACTIVE flag — fallback when no X display exists."""
        state_set = lib.atspi_accessible_get_state_set(acc)
        if not state_set:
            return False
        try:
            return bool(lib.atspi_state_set_contains(state_set, _ATSPI_STATE_ACTIVE))
        finally:
            lib.g_object_unref(state_set)

    def _window_info(self, lib: _AtspiLib, acc: int, app_name: str,
                     active_key: tuple[bool, tuple[int, str | None] | None]) -> WindowInfo | None:
        if not self._is_window(lib, acc):
            return None
        err = lib.new_error()
        name = lib.take_string(
            lib.atspi_accessible_get_name(acc, ctypes.byref(err)))
        lib.check_error(err)
        err = lib.new_error()
        pid = lib.atspi_accessible_get_process_id(acc, ctypes.byref(err))
        if lib.check_error(err):
            pid = -1
        x11_usable, active = active_key
        if x11_usable:
            # Match by (pid, title); title disambiguates same-pid apps.
            # active is None when the WM reports no active window.
            is_active = (active is not None and pid == active[0]
                         and (active[1] is None or name == active[1]))
        else:
            is_active = self._is_active_state(lib, acc)
        return WindowInfo(
            id=f"atspi:{pid}:{name}",
            title=name,
            app_name=app_name,
            pid=pid,
            bounds=self._bounds(lib, acc),
            active=is_active,
        )

    def _apps(self, lib: _AtspiLib) -> list[tuple[int, str]]:
        """All application accessibles: (pointer, name).

        The caller owns every pointer and must ``g_object_unref`` each.
        Desktops are released inside this helper.
        """
        apps: list[tuple[int, str]] = []
        for desktop_index in range(lib.atspi_get_desktop_count()):
            desktop = lib.atspi_get_desktop(desktop_index)
            if not desktop:
                continue
            try:
                for i in range(self._child_count(lib, desktop)):
                    app = self._child_at(lib, desktop, i)
                    if app is None:
                        continue
                    err = lib.new_error()
                    name = lib.take_string(
                        lib.atspi_accessible_get_name(app, ctypes.byref(err)))
                    lib.check_error(err)
                    apps.append((app, name))
            finally:
                lib.g_object_unref(desktop)
        return apps

    def _collect(self, lib: _AtspiLib) -> list[WindowInfo]:
        windows: list[WindowInfo] = []
        active_key = self._active_key()
        apps = self._apps(lib)
        try:
            for app, app_name in apps:
                for i in range(self._child_count(lib, app)):
                    child = self._child_at(lib, app, i)
                    if child is None:
                        continue
                    try:
                        info = self._window_info(lib, child, app_name, active_key)
                    finally:
                        lib.g_object_unref(child)
                    if info is not None:
                        windows.append(info)
        finally:
            for app, _name in apps:
                lib.g_object_unref(app)
        return windows

    def _find_accessible(self, lib: _AtspiLib, window_id: str):
        """Walk the tree for ``window_id``; returns (accessible, info).

        The id is ``atspi:<pid>:<title>``; the match is by (pid, title).
        When two windows share pid+title the match is ambiguous and this
        returns (None, None) — fail closed (R-029). The caller owns the
        accessible and must ``g_object_unref`` it.
        """
        if not window_id.startswith("atspi:"):
            return None, None
        try:
            pid_s, title = window_id[len("atspi:"):].split(":", 1)
            pid = int(pid_s)
        except ValueError:
            return None, None
        active_key = self._active_key()
        found: tuple[int, WindowInfo] | None = None
        apps = self._apps(lib)
        try:
            for app, app_name in apps:
                for i in range(self._child_count(lib, app)):
                    child = self._child_at(lib, app, i)
                    if child is None:
                        continue
                    info = self._window_info(lib, child, app_name, active_key)
                    if info is not None and info.pid == pid and info.title == title:
                        if found is not None:
                            # Ambiguous: release both candidates, refuse.
                            lib.g_object_unref(child)
                            lib.g_object_unref(found[0])
                            return None, None
                        found = (child, info)
                        continue
                    lib.g_object_unref(child)
        finally:
            for app, _name in apps:
                lib.g_object_unref(app)
        if found is None:
            return None, None
        return found

    # -- WindowBackend --------------------------------------------------
    def list_windows(self) -> list[WindowInfo]:
        lib = self._load()
        if lib is None or not self._ensure_init():
            raise WindowControlUnavailable(
                self._init_error or self._lib_error or "AT-SPI unavailable")
        return self._collect(lib)

    def get_active_window(self) -> WindowInfo | None:
        for window in self.list_windows():
            if window.active:
                return window
        return None

    def focus_window(self, window_id: str) -> bool:
        """Activate a window via the window manager (EWMH).

        Resolves the id through the AT-SPI tree first (fail closed on
        not-found/ambiguous), then maps (pid, title) to an X window id
        and sends a ``_NET_ACTIVE_WINDOW`` client message. Returns
        False when the window is not found, has no X window, or there
        is no X display to speak to. ``atspi_component_grab_focus``
        is deliberately NOT used: it is a widget-focus primitive and
        the app answers it with NotSupported for toplevel frames
        (verified live 2026-11-26).
        """
        lib = self._load()
        if lib is None or not self._ensure_init():
            raise WindowControlUnavailable(
                self._init_error or self._lib_error or "AT-SPI unavailable")
        acc, info = self._find_accessible(lib, window_id)
        if acc is None or info is None:
            return False
        try:
            x11 = self._load_x11()
            if x11 is None or not x11.available():
                return False
            xid = x11.window_id_for_pid(info.pid, info.title)
            if xid is None:
                return False
            return bool(x11.activate(xid))
        finally:
            lib.g_object_unref(acc)

    def window_bounds(self, window_id: str) -> tuple[int, int, int, int] | None:
        lib = self._load()
        if lib is None or not self._ensure_init():
            raise WindowControlUnavailable(
                self._init_error or self._lib_error or "AT-SPI unavailable")
        acc, info = self._find_accessible(lib, window_id)
        if acc is None:
            return None
        try:
            return info.bounds if info is not None else None
        finally:
            lib.g_object_unref(acc)


# ---------------------------------------------------------------------------
# UI Automation backend (Windows, ADR-012 (b))
# ---------------------------------------------------------------------------

_POWERSHELL_EXE = "powershell.exe"
_UIA_TIMEOUT_S = 30
_UIA_ID_RE = re.compile(r"^uia:([0-9]+)$")

# Fixed PowerShell scripts. They are constants: no model input, window
# title, or tool argument is ever interpolated into them — except the
# focus script's __HWND__ token, which is replaced with str(int(hwnd))
# after the id has been parsed to int, so only digits can appear there.
# Both run as one argv array (subprocess, shell=False), never via cmd.
_UIA_FOREGROUND_TYPE = (
    "Add-Type -TypeDefinition 'using System; "
    "using System.Runtime.InteropServices; "
    "public static class Win32 { "
    "[DllImport(\"user32.dll\")] "
    "public static extern IntPtr GetForegroundWindow(); "
    "[DllImport(\"user32.dll\")] "
    "public static extern bool SetForegroundWindow(IntPtr hWnd); "
    "[DllImport(\"user32.dll\")] "
    "public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow); }'"
)

_UIA_LIST_SCRIPT = (
    "Add-Type -AssemblyName UIAutomationClient; "
    + _UIA_FOREGROUND_TYPE
    + "; $root = [System.Windows.Automation.AutomationElement]::RootElement; "
    "$children = $root.FindAll("
    "[System.Windows.Automation.TreeScope]::Children, "
    "[System.Windows.Automation.Condition]::TrueCondition); "
    "$fg = [Win32]::GetForegroundWindow().ToInt64(); $out = @(); "
    "foreach ($el in $children) { "
    "try { $hwnd = $el.Current.NativeWindowHandle } catch { continue } "
    "if ($hwnd -eq 0) { continue } "
    "try { $name = $el.Current.Name; $procId = $el.Current.ProcessId; "
    "$r = $el.Current.BoundingRectangle } catch { continue } "
    "$app = ''; "
    "try { $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue; "
    "if ($proc) { $app = $proc.ProcessName } } catch {} "
    "$out += [pscustomobject]@{ name = $name; pid = $procId; hwnd = $hwnd; "
    "app = $app; x = [int][Math]::Round($r.X); "
    "y = [int][Math]::Round($r.Y); "
    "width = [int][Math]::Round($r.Width); "
    "height = [int][Math]::Round($r.Height); "
    "active = ($hwnd -eq $fg) } } "
    "$out | ConvertTo-Json -Compress"
)

_UIA_FOCUS_SCRIPT = (
    "Add-Type -AssemblyName UIAutomationClient; "
    + _UIA_FOREGROUND_TYPE
    + "; $h = [IntPtr]__HWND__; "
    "$el = [System.Windows.Automation.AutomationElement]::FromHandle($h); "
    "if ($null -eq $el) { exit 2 } "
    # UIA SetFocus() throws "Target element cannot receive focus" for
    # real top-level windows (live finding 2026-11-27: Notepad) — the
    # Win32 foreground APIs are the mechanism that works.
    "$null = [Win32]::ShowWindow($h, 9); "
    "$null = [Win32]::SetForegroundWindow($h); "
    "Start-Sleep -Milliseconds 200; "
    "if ([Win32]::GetForegroundWindow().ToInt64() -eq __HWND__) "
    "{ 'true' } else { 'false' }"
)


def _uia_run(argv: list[str], timeout: int = _UIA_TIMEOUT_S) -> subprocess.CompletedProcess:
    """Run an argv array. No shell, ever. Patchable seam for tests."""
    return subprocess.run(
        argv, capture_output=True, text=True, timeout=timeout, shell=False,
    )


class UiaBackend:
    """UI Automation tier-1 backend for Windows (ADR-012 (b)).

    ``runner`` is an injectable ``argv -> CompletedProcess`` seam for
    tests (same shape as the Windows adapter's runner). By default the
    real ``powershell.exe`` is invoked. Loading is lazy and the
    constructor never raises: :meth:`available` reports a missing
    PowerShell, a non-Windows host, or a failing probe script instead.
    The probe result is cached per instance — the daemon calls
    ``available()`` on every tool execute/verify, and re-running
    PowerShell each time would double the cost of every window call.
    """

    def __init__(self, runner=None):
        self._runner = runner if runner is not None else _uia_run
        self._probed = False
        self._available = False
        self._available_reason = "UIA backend not probed yet"

    # -- lifecycle ----------------------------------------------------
    def _run_script(self, script: str, timeout: int = _UIA_TIMEOUT_S):
        argv = [_POWERSHELL_EXE, "-NoProfile", "-NonInteractive",
                "-Command", script]
        return self._runner(argv, timeout=timeout)

    def available(self) -> tuple[bool, str]:
        if self._probed:
            return self._available, self._available_reason
        self._probed = True
        if platform.system() != "Windows":
            self._available_reason = "UIA backend is Windows-only"
            return False, self._available_reason
        if self._runner is _uia_run and shutil.which(_POWERSHELL_EXE) is None:
            self._available_reason = "powershell.exe not found"
            return False, self._available_reason
        try:
            windows = self.list_windows()
        except WindowControlError as exc:
            self._available_reason = f"UIA probe failed: {exc}"
            return False, self._available_reason
        self._available = True
        self._available_reason = (
            f"UIA backend available ({len(windows)} windows)")
        return True, self._available_reason

    # -- parsing ------------------------------------------------------
    @staticmethod
    def _parse_list(stdout: str) -> list[WindowInfo]:
        """Parse the list script's JSON. One bad row is skipped, never
        fatal — a window closing mid-enumeration must not lose the rest.
        """
        text = (stdout or "").strip()
        if not text:
            return []
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise WindowControlError(
                f"UIA list output is not valid JSON: {exc}") from exc
        if isinstance(data, dict):
            data = [data]  # ConvertTo-Json emits an object for 1 window
        if not isinstance(data, list):
            raise WindowControlError(
                "UIA list output is not a JSON array")
        windows: list[WindowInfo] = []
        for row in data:
            if not isinstance(row, dict):
                continue
            hwnd = row.get("hwnd")
            pid = row.get("pid")
            if (isinstance(hwnd, bool) or not isinstance(hwnd, int)
                    or hwnd <= 0
                    or isinstance(pid, bool) or not isinstance(pid, int)):
                continue
            bounds = None
            try:
                bounds = (int(row["x"]), int(row["y"]),
                          int(row["width"]), int(row["height"]))
            except (KeyError, TypeError, ValueError):
                bounds = None
            title = row.get("name")
            app = row.get("app")
            windows.append(WindowInfo(
                id=f"uia:{hwnd}",
                title=title if isinstance(title, str) else "",
                app_name=app if isinstance(app, str) else "",
                pid=pid,
                bounds=bounds,
                active=bool(row.get("active", False)),
            ))
        return windows

    @staticmethod
    def _parse_hwnd(window_id: str) -> int | None:
        """The hwnd for ``uia:<digits>``, or None when the id is not a
        well-formed UIA id. Anything else (AT-SPI ids, titles, hostile
        text) is refused without ever reaching PowerShell (R-029)."""
        if not isinstance(window_id, str):
            return None
        match = _UIA_ID_RE.match(window_id)
        if match is None:
            return None
        hwnd = int(match.group(1))
        if hwnd <= 0 or hwnd > 2**63 - 1:
            return None
        return hwnd

    # -- WindowBackend --------------------------------------------------
    def list_windows(self) -> list[WindowInfo]:
        if platform.system() != "Windows" and self._runner is _uia_run:
            raise WindowControlUnavailable("UIA backend is Windows-only")
        try:
            result = self._run_script(_UIA_LIST_SCRIPT)
        except (OSError, subprocess.SubprocessError) as exc:
            raise WindowControlError(
                f"UIA list failed to run PowerShell: {exc}") from exc
        if result.returncode != 0:
            raise WindowControlError(
                "UIA list script failed "
                f"(exit {result.returncode}): "
                f"{(result.stderr or '').strip()}")
        return self._parse_list(result.stdout or "")

    def get_active_window(self) -> WindowInfo | None:
        for window in self.list_windows():
            if window.active:
                return window
        return None

    def focus_window(self, window_id: str) -> bool:
        """Focus by exact hwnd id (ADR-012).

        Mechanism is the Win32 foreground sequence — restore the window
        (``ShowWindow(SW_RESTORE)``) then ``SetForegroundWindow`` — with
        a foreground re-check. UIA ``FromHandle(hwnd).SetFocus()`` was
        the original mechanism, but it throws "Target element cannot
        receive focus" for real top-level windows (live finding
        2026-11-27: Notepad), while the Win32 call brings the same
        window to the foreground.

        Returns False when the id is malformed, the window is gone
        (script exit 2), or the foreground check says the window
        manager ignored the request. A script error raises
        :class:`WindowControlError` — the caller reports it honestly
        instead of claiming success.
        """
        hwnd = self._parse_hwnd(window_id)
        if hwnd is None:
            return False
        # __HWND__ is replaced with str(int) only — digits, by
        # construction. No other part of the id can reach the script.
        script = _UIA_FOCUS_SCRIPT.replace("__HWND__", str(hwnd))
        try:
            result = self._run_script(script)
        except (OSError, subprocess.SubprocessError) as exc:
            raise WindowControlError(
                f"UIA focus failed to run PowerShell: {exc}") from exc
        if result.returncode == 2:
            return False  # FromHandle returned null: window is gone
        if result.returncode != 0:
            raise WindowControlError(
                "UIA focus script failed "
                f"(exit {result.returncode}): "
                f"{(result.stderr or '').strip()}")
        return (result.stdout or "").strip().lower() == "true"

    def window_bounds(self, window_id: str) -> tuple[int, int, int, int] | None:
        hwnd = self._parse_hwnd(window_id)
        if hwnd is None:
            return None
        for window in self.list_windows():
            if window.id == window_id:
                return window.bounds
        return None


_BACKEND: WindowBackend | None = None
_BACKEND_TRIED = False


def get_backend() -> WindowBackend | None:
    """The tier-1 backend for this platform, or None when unavailable.

    Linux: the AT-SPI backend (loads the library lazily; a host without
    AT-SPI gets None). Windows: the UIA backend (ADR-012 (b)); a host
    without PowerShell, or where the UIA probe fails, gets None.
    Cached per process; :func:`reset_backend` clears the cache (tests).
    """
    global _BACKEND, _BACKEND_TRIED
    if _BACKEND_TRIED:
        return _BACKEND
    _BACKEND_TRIED = True
    if platform.system() == "Linux":
        backend = AtspiBackend()
        if backend.available()[0]:
            _BACKEND = backend
    elif platform.system() == "Windows":
        backend: WindowBackend = UiaBackend()
        if backend.available()[0]:
            _BACKEND = backend
    # macOS: no tier-1 backend in this round.
    return _BACKEND


def reset_backend() -> None:
    """Clear the cached backend (tests)."""
    global _BACKEND, _BACKEND_TRIED
    _BACKEND = None
    _BACKEND_TRIED = False


def list_windows() -> list[WindowInfo]:
    """Tier-1 window list. Raises WindowControlUnavailable with no backend."""
    backend = get_backend()
    if backend is None:
        raise WindowControlUnavailable("no tier-1 window backend on this host")
    return backend.list_windows()


def get_active_window() -> WindowInfo | None:
    """The active window via tier 1, or None."""
    backend = get_backend()
    if backend is None:
        raise WindowControlUnavailable("no tier-1 window backend on this host")
    return backend.get_active_window()


def focus_window(window_id: str) -> bool:
    """Focus a window by its tier-1 id. False when not found."""
    backend = get_backend()
    if backend is None:
        raise WindowControlUnavailable("no tier-1 window backend on this host")
    return backend.focus_window(window_id)


def window_bounds(window_id: str) -> tuple[int, int, int, int] | None:
    """Screen bounds of a window by its tier-1 id, or None."""
    backend = get_backend()
    if backend is None:
        raise WindowControlUnavailable("no tier-1 window backend on this host")
    return backend.window_bounds(window_id)
