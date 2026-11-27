"""Tests for core/window_control.py (ADR-012) and the window_focus tool.

- Mock tests drive :class:`AtspiBackend` with an in-memory fake lib
  (no session bus, no display needed).
- ``test_real_libatspi_loads`` checks the real shared library binds
  (skipped where it is absent).
- Tool tests exercise ``list_windows`` (tier-1 path) and ``window_focus``
  through ``tools/definitions.py`` with a monkeypatched backend.
- Live tests (``test_live_*``) start a real headless desktop (Xvfb +
  session bus + at-spi-bus-launcher + openbox + zenity windows) and
  assert the backend sees real windows; skipped when any stack binary
  is missing.
"""

from __future__ import annotations

import ctypes
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.window_control import (
    AtspiBackend,
    UiaBackend,
    WindowControlError,
    WindowControlUnavailable,
    WindowInfo,
    _UIA_FOCUS_SCRIPT,
    _UIA_LIST_SCRIPT,
    get_backend,
    reset_backend,
)
from tools.definitions import TOOLS, get_tool


# ---------------------------------------------------------------------------
# Fake libatspi
# ---------------------------------------------------------------------------

class _FakeRect:
    """Mimics a ctypes POINTER(_AtspiRect): truthy, .contents has fields."""

    def __init__(self, bounds):
        x, y, w, h = bounds
        self.contents = SimpleNamespace(x=x, y=y, width=w, height=h)


class _FakeLib:
    """In-memory AT-SPI tree.

    Nodes: {"name", "role", "children" [...], "pid", "bounds" | None,
    "active" bool, "has_component" bool, "focusable" bool}.
    Pointers are small ints; string results are ("s", text) tokens.
    """

    def __init__(self, apps, initialized=True, init_return=0):
        self.nodes = {}
        self._next = 1
        self._desktops = []
        for app in apps:
            desktop = {"name": "", "role": "desktop", "children": [app]}
            self._desktops.append(self._add(desktop))
        self.initialized = initialized
        self.init_return = init_return
        self.init_calls = 0
        self.timeouts = []
        self.unrefs: list = []
        self.freed: list = []

    def _add(self, node):
        ptr = self._next
        self._next += 1
        node = dict(node)
        node["children"] = [self._add(c) for c in node.get("children", [])]
        node.setdefault("pid", -1)
        node.setdefault("bounds", None)
        node.setdefault("active", False)
        node.setdefault("has_component", True)
        self.nodes[ptr] = node
        return ptr

    # -- string/error plumbing ---------------------------------------
    def take_string(self, ptr):
        if not ptr:
            return ""
        assert ptr[0] == "s"
        return ptr[1]

    def new_error(self):
        # A real ctypes slot, like _AtspiLib.new_error() — the backend
        # passes it to ctypes.byref().
        return ctypes.c_void_p(0)

    def check_error(self, err):
        return err.value is not None

    # -- lifecycle ----------------------------------------------------
    def atspi_set_timeout(self, value, startup):
        self.timeouts.append((value, startup))

    def atspi_init(self):
        self.init_calls += 1
        return self.init_return

    def atspi_is_initialized(self):
        return self.initialized

    def atspi_exit(self):
        pass

    # -- tree ---------------------------------------------------------
    def atspi_get_desktop_count(self):
        return len(self._desktops)

    def atspi_get_desktop(self, i):
        return self._desktops[i]

    def atspi_accessible_get_child_count(self, acc, err):
        return len(self.nodes[acc]["children"])

    def atspi_accessible_get_child_at_index(self, acc, i, err):
        return self.nodes[acc]["children"][i]

    def atspi_accessible_get_name(self, acc, err):
        return ("s", self.nodes[acc]["name"])

    def atspi_accessible_get_role_name(self, acc, err):
        return ("s", self.nodes[acc]["role"])

    def atspi_accessible_get_application(self, acc, err):
        return acc

    def atspi_accessible_get_component_iface(self, acc):
        return acc if self.nodes[acc]["has_component"] else 0

    def atspi_accessible_get_state_set(self, acc):
        return ("state", acc)

    def atspi_accessible_get_process_id(self, acc, err):
        return self.nodes[acc]["pid"]

    def atspi_accessible_get_accessible_id(self, acc, err):
        return ("s", "")

    def atspi_component_get_extents(self, comp, ctype, err):
        bounds = self.nodes[comp]["bounds"]
        if bounds is None:
            return None
        return _FakeRect(bounds)

    def atspi_state_set_contains(self, state_set, state):
        if state_set[0] != "state":
            return False
        return bool(self.nodes[state_set[1]]["active"]) and state == 1

    def atspi_rect_free(self, rect):
        self.freed.append(("rect", rect))

    def g_object_unref(self, ptr):
        self.unrefs.append(ptr)

    def g_free(self, ptr):
        self.freed.append(("str", ptr))

    def g_error_free(self, ptr):
        self.freed.append(("err", ptr))


def _tree():
    return [
        {"name": "zenity", "role": "application", "pid": 111, "children": [
            {"name": "First Window", "role": "dialog", "pid": 111,
             "bounds": (10, 20, 300, 200), "active": True},
            {"name": "Second Window", "role": "frame", "pid": 111,
             "bounds": (50, 60, 400, 300), "active": False},
            {"name": "A Button", "role": "push button", "pid": 111,
             "bounds": (15, 25, 80, 30)},
        ]},
        {"name": "gedit", "role": "application", "pid": 222, "children": [
            {"name": "notes.txt", "role": "frame", "pid": 222,
             "bounds": (0, 0, 800, 600), "active": False},
            {"name": "No Bounds", "role": "frame", "pid": 222,
             "bounds": None, "active": False},
        ]},
    ]


def _backend(apps=None, x11=None, **kwargs):
    if x11 is None:
        # Fake X11/EWMH state matching the fake tree: pid 111 owns
        # xid 0x100, pid 222 owns 0x200; the WM has "First Window" active.
        x11 = _FakeX11(
            clients={111: 0x100, 222: 0x200},
            titles={0x100: "Second Window", 0x200: "notes.txt"},
            active_key=(111, "First Window"))
    return AtspiBackend(
        lib=_FakeLib(_tree() if apps is None else apps, **kwargs), x11=x11)


class _FakeX11:
    """In-memory X11/EWMH state: clients {pid: xid}, titles {xid: title}.

    ``flip`` controls whether activate() moves the active window (a
    real WM does; flip=False simulates a WM that ignores the request).
    """

    def __init__(self, clients=None, titles=None, active_key=None,
                 available=True, flip=True):
        self.clients = dict(clients or {})
        self.titles = dict(titles or {})
        self._active_key = active_key
        self._available = available
        self.flip = flip
        self.sent: list = []

    def available(self):
        return self._available

    def active_key(self):
        return self._active_key

    def window_id_for_pid(self, pid, title=None):
        for p, xid in self.clients.items():
            if p == pid and title is not None and self.titles.get(xid) == title:
                return xid
        return self.clients.get(pid)

    def activate(self, window_id):
        self.sent.append(window_id)
        if window_id not in self.clients.values():
            return False
        if self.flip:
            pid = next(p for p, x in self.clients.items() if x == window_id)
            self._active_key = (pid, self.titles.get(window_id))
        return True


# ---------------------------------------------------------------------------
# Mock backend tests
# ---------------------------------------------------------------------------

def test_available_true_when_init_succeeds():
    backend = _backend()
    assert backend.available() == (True, "AT-SPI backend available")
    assert backend._lib.init_calls == 1
    assert backend._lib.timeouts == [(2000, 2000)]


def test_available_false_when_init_fails():
    backend = _backend(initialized=False)
    available, reason = backend.available()
    assert available is False
    assert "not initialized" in reason


def test_available_false_when_init_returns_nonzero():
    # Live finding (2026-11-26): with no bus atspi_init() returns 2
    # while atspi_is_initialized() still reports True — the return
    # value is the only reliable signal.
    backend = _backend(init_return=2)
    available, reason = backend.available()
    assert available is False
    assert "code 2" in reason
    with pytest.raises(WindowControlUnavailable):
        backend.list_windows()


def test_available_false_when_library_missing(monkeypatch):
    class _RaisingLib:
        def __init__(self, *args, **kwargs):
            raise OSError("libatspi.so.0: cannot open shared object file")

    monkeypatch.setattr("core.window_control._AtspiLib", _RaisingLib)
    backend = AtspiBackend()
    available, reason = backend.available()
    assert available is False
    assert "not loadable" in reason
    with pytest.raises(WindowControlUnavailable):
        backend.list_windows()


def test_list_windows_maps_tree_and_filters_non_windows():
    backend = _backend()
    windows = backend.list_windows()
    assert [w.title for w in windows] == [
        "First Window", "Second Window", "notes.txt", "No Bounds"]
    assert [w.app_name for w in windows] == [
        "zenity", "zenity", "gedit", "gedit"]
    assert [w.pid for w in windows] == [111, 111, 222, 222]
    assert [w.id for w in windows] == [
        "atspi:111:First Window", "atspi:111:Second Window",
        "atspi:222:notes.txt", "atspi:222:No Bounds"]
    assert windows[0].bounds == (10, 20, 300, 200)
    assert windows[0].active is True
    assert windows[1].active is False
    assert windows[3].bounds is None  # no component extents


def test_list_windows_empty_when_no_apps():
    assert _backend(apps=[]).list_windows() == []


def test_get_active_window():
    assert _backend().get_active_window().title == "First Window"
    assert _backend(apps=[{"name": "x", "role": "application", "pid": 1,
                           "children": [
                               {"name": "w", "role": "frame", "pid": 1,
                                "active": False}]}]).get_active_window() is None


def test_focus_window_by_id():
    backend = _backend()
    assert backend.focus_window("atspi:111:Second Window") is True
    # The _NET_ACTIVE_WINDOW message went to pid 111's X window.
    assert backend._x11.sent == [0x100]
    # ... and the (fake) WM moved the active window there.
    assert backend.get_active_window().title == "Second Window"


def test_focus_window_unknown_id_returns_false():
    backend = _backend()
    assert backend.focus_window("atspi:999:Nope") is False
    assert backend.focus_window("uia:1234") is False
    assert backend.focus_window("garbage") is False
    assert backend._x11.sent == []  # nothing sent for unknown ids


def test_focus_window_ambiguous_refuses():
    apps = [{"name": "dup", "role": "application", "pid": 42, "children": [
        {"name": "Same", "role": "frame", "pid": 42, "bounds": (0, 0, 10, 10)},
        {"name": "Same", "role": "frame", "pid": 42, "bounds": (20, 20, 10, 10)},
    ]}]
    backend = _backend(apps=apps)
    assert backend.focus_window("atspi:42:Same") is False
    assert backend._x11.sent == []  # fail closed: nothing focused


def test_focus_window_without_x_window_returns_false():
    # The window exists in the AT-SPI tree but its pid owns no X window
    # (e.g. a native Wayland app): focus cannot reach it via EWMH.
    apps = [{"name": "a", "role": "application", "pid": 7, "children": [
        {"name": "w", "role": "frame", "pid": 7}]}]
    backend = _backend(apps=apps)
    assert backend.focus_window("atspi:7:w") is False


def test_focus_window_no_x_display_returns_false():
    backend = _backend(x11=_FakeX11(available=False))
    assert backend.focus_window("atspi:111:Second Window") is False


def test_active_falls_back_to_state_when_no_x11():
    # Without a usable X display, `active` comes from the AT-SPI
    # STATE_ACTIVE flag (the fake tree marks "First Window" active).
    backend = _backend(x11=_FakeX11(available=False))
    windows = backend.list_windows()
    assert windows[0].active is True
    assert windows[1].active is False
    assert backend.get_active_window().title == "First Window"


def test_get_active_window_none_when_x_active_pid_not_in_tree():
    backend = _backend(x11=_FakeX11(
        clients={111: 0x100, 222: 0x200}, active_key=(999, "Elsewhere")))
    assert backend.get_active_window() is None


def test_window_bounds():
    backend = _backend()
    assert backend.window_bounds("atspi:222:notes.txt") == (0, 0, 800, 600)
    assert backend.window_bounds("atspi:222:No Bounds") is None
    assert backend.window_bounds("atspi:999:Nope") is None


def test_window_info_as_dict():
    info = WindowInfo(id="atspi:1:w", title="w", app_name="a", pid=1,
                      bounds=(1, 2, 3, 4), active=True)
    assert info.as_dict() == {"id": "atspi:1:w", "title": "w", "app_name": "a",
                              "pid": 1, "bounds": [1, 2, 3, 4], "active": True}
    assert WindowInfo(id="x", title="t", app_name="a", pid=1,
                      bounds=None, active=False).as_dict()["bounds"] is None


def test_list_windows_unref_everything_it_touched():
    backend = _backend()
    backend.list_windows()
    # Every node pointer (desktops, apps, windows, buttons) was released.
    assert set(backend._lib.unrefs) >= set(backend._lib.nodes)


def test_real_libatspi_binds():
    try:
        lib = ctypes.CDLL("libatspi.so.0", use_errno=True)
    except OSError:
        pytest.skip("libatspi.so.0 not installed")
    for name in ("atspi_init", "atspi_get_desktop", "atspi_get_desktop_count",
                 "atspi_accessible_get_name", "atspi_accessible_get_role_name",
                 "atspi_accessible_get_child_count",
                 "atspi_accessible_get_child_at_index",
                 "atspi_accessible_get_process_id",
                 "atspi_component_get_extents",
                 "atspi_state_set_contains", "atspi_set_timeout",
                 "atspi_is_initialized"):
        assert hasattr(lib, name), name


def test_real_libx11_binds():
    try:
        lib = ctypes.CDLL("libX11.so.6", use_errno=True)
    except OSError:
        pytest.skip("libX11.so.6 not installed")
    for name in ("XOpenDisplay", "XCloseDisplay", "XDefaultRootWindow",
                 "XInternAtom", "XGetWindowProperty", "XFree", "XSendEvent",
                 "XFlush"):
        assert hasattr(lib, name), name


@pytest.mark.skipif(sys.platform == "win32",
                    reason="headless/no-backend premise is Linux-only "
                           "(libatspi init); on Windows a working "
                           "PowerShell means a live UIA backend (ADR-012)")
def test_get_backend_none_headless_and_reset(monkeypatch, tmp_path):
    # Runs in a SUBPROCESS on purpose: libatspi's init is process-global
    # and never recovers in-process after a failed init (verified live
    # 2026-11-26 — init returns 2 with no bus, and a later init with a
    # bus up still does not return 0). Calling the real init here would
    # poison this pytest process for the live tests below.
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.delenv("DBUS_SESSION_BUS_ADDRESS", raising=False)
    monkeypatch.delenv("AT_SPI_BUS_ADDRESS", raising=False)
    code = (
        "import sys; sys.path.insert(0, %r);"
        "from core.window_control import get_backend, reset_backend;"
        "reset_backend(); print(get_backend() is None)" % str(Path(__file__).resolve().parents[1])
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True, timeout=30,
        env={k: v for k, v in os.environ.items()
             if k not in ("DISPLAY", "WAYLAND_DISPLAY",
                          "DBUS_SESSION_BUS_ADDRESS", "AT_SPI_BUS_ADDRESS")})
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "True"


# ---------------------------------------------------------------------------
# Tool tests (list_windows tier-1 path, window_focus)
# ---------------------------------------------------------------------------

@pytest.fixture()
def ctx(tmp_path):
    workdir = tmp_path / "work"
    workdir.mkdir()
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    return {"state_dir": state_dir, "workdir": workdir, "token": None}


def _run(name, args, ctx):
    return get_tool(name).execute(args, ctx)


def _verify(name, args, result, ctx):
    return get_tool(name).verify(args, result, ctx)


def test_window_focus_is_level_2():
    assert TOOLS["window_focus"].level == 2
    assert TOOLS["window_focus"].schema["required"] == ["window_id"]
    assert TOOLS["window_focus"].schema.get("additionalProperties") is False


def test_list_windows_prefers_tier1(monkeypatch, ctx):
    backend = _backend()
    monkeypatch.setattr("core.window_control.get_backend", lambda: backend)
    result = _run("list_windows", {}, ctx)
    assert result["ok"] is True
    assert result["data"]["backend"] == "tier1"
    assert result["data"]["count"] == 4
    assert result["data"]["windows"][0]["id"] == "atspi:111:First Window"
    assert result["data"]["windows"][0]["bounds"] == [10, 20, 300, 200]
    assert _verify("list_windows", {}, result, ctx)[0] is True


def test_list_windows_falls_back_without_backend(monkeypatch, ctx):
    monkeypatch.setattr("core.window_control.get_backend", lambda: None)
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    # Tier 2 is the OS adapter's window query (wmctrl/xdotool on Linux,
    # PowerShell on Windows) — neutralise it too, or the test's "no
    # backend anywhere" premise only holds where that query is absent
    # (on Windows the PowerShell fallback succeeds and the tool returns
    # ok=True; see the 2026-11-27 Windows run on 002087e).
    monkeypatch.setattr(
        "tools.definitions._os_adapter",
        lambda: SimpleNamespace(
            list_windows_available=lambda: (False, "no window provider available (test)")))
    result = _run("list_windows", {}, ctx)
    assert result["ok"] is False
    assert result["data"]["unavailable"] is True
    assert _verify("list_windows", {}, result, ctx)[0] is False


def test_window_focus_success_and_verify(monkeypatch, ctx):
    backend = _backend()
    monkeypatch.setattr("core.window_control.get_backend", lambda: backend)
    result = _run("window_focus", {"window_id": "atspi:111:Second Window"}, ctx)
    assert result["ok"] is True
    assert result["data"]["focused"] is True
    # The (fake) WM moved the active window, so verify() passes.
    ok, evidence = _verify("window_focus",
                           {"window_id": "atspi:111:Second Window"}, result, ctx)
    assert ok is True
    assert "Second Window" in evidence


def test_window_focus_verify_fails_when_wm_ignores_request(monkeypatch, ctx):
    # focus_window sent the message (ok=True) but the WM did not move
    # the active window: verify() must fail honestly.
    x11 = _FakeX11(clients={111: 0x100, 222: 0x200},
                   titles={0x100: "Second Window", 0x200: "notes.txt"},
                   active_key=(111, "First Window"), flip=False)
    backend = _backend(x11=x11)
    monkeypatch.setattr("core.window_control.get_backend", lambda: backend)
    result = _run("window_focus", {"window_id": "atspi:111:Second Window"}, ctx)
    assert result["ok"] is True
    ok, evidence = _verify("window_focus",
                           {"window_id": "atspi:111:Second Window"}, result, ctx)
    assert ok is False
    assert "not active" in evidence


def test_window_focus_verify_passes_when_target_active(monkeypatch, ctx):
    apps = [{"name": "a", "role": "application", "pid": 5, "children": [
        {"name": "w", "role": "frame", "pid": 5, "active": True}]}]
    x11 = _FakeX11(clients={5: 0x500}, titles={0x500: "w"},
                   active_key=(5, "w"))
    backend = _backend(apps=apps, x11=x11)
    monkeypatch.setattr("core.window_control.get_backend", lambda: backend)
    result = _run("window_focus", {"window_id": "atspi:5:w"}, ctx)
    assert result["ok"] is True
    assert _verify("window_focus", {"window_id": "atspi:5:w"}, result, ctx)[0] is True


def test_window_focus_not_found(monkeypatch, ctx):
    backend = _backend()
    monkeypatch.setattr("core.window_control.get_backend", lambda: backend)
    result = _run("window_focus", {"window_id": "atspi:999:Nope"}, ctx)
    assert result["ok"] is False
    assert "not found or ambiguous" in result["error"]
    assert _verify("window_focus", {"window_id": "atspi:999:Nope"},
                   result, ctx)[0] is False


def test_window_focus_unavailable_without_backend(monkeypatch, ctx):
    monkeypatch.setattr("core.window_control.get_backend", lambda: None)
    result = _run("window_focus", {"window_id": "atspi:1:w"}, ctx)
    assert result["ok"] is False
    assert result["data"]["unavailable"] is True


def test_window_focus_rejects_bad_args(ctx):
    assert _run("window_focus", {}, ctx)["ok"] is False
    assert _run("window_focus", {"window_id": ""}, ctx)["ok"] is False
    assert _run("window_focus", {"window_id": 42}, ctx)["ok"] is False
    assert _run("window_focus",
                {"window_id": "atspi:1:w", "extra": 1}, ctx)["ok"] is False


# ---------------------------------------------------------------------------
# Live tests: real headless desktop (Xvfb + bus + registry + openbox)
# ---------------------------------------------------------------------------

_LIVE_TITLES = ("OpenCobot Live A", "OpenCobot Live B")


def _live_stack_missing():
    missing = [b for b in ("Xvfb", "dbus-daemon", "openbox", "zenity")
               if shutil.which(b) is None]
    if not os.path.exists("/usr/libexec/at-spi-bus-launcher"):
        missing.append("at-spi-bus-launcher")
    return missing


def _free_display() -> str:
    """First display :98–:109 whose X lock file is absent."""
    for n in range(98, 110):
        if not os.path.exists(f"/tmp/.X{n}-lock"):
            return f":{n}"
    raise RuntimeError("no free X display in :98–:109")


def _stop(proc):
    """Stop a stack process and its whole session (D-Bus-activated
    children — the a11y bus daemon, registryd — live in the launcher's
    session, so killing the process alone would orphan them)."""
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, 15)  # SIGTERM the session
    except (ProcessLookupError, PermissionError):
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, 9)  # SIGKILL the session
        except (ProcessLookupError, PermissionError):
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


@pytest.fixture(scope="module")
def live_desktop():
    """A real desktop: Xvfb + session bus + AT-SPI bus + openbox + 2 windows.

    Skipped when any stack binary is missing. Tears the whole stack
    down afterwards; restores DISPLAY/DBUS_SESSION_BUS_ADDRESS.
    """
    missing = _live_stack_missing()
    if missing:
        pytest.skip(f"live AT-SPI stack missing: {missing}")
    display = _free_display()
    old_display = os.environ.get("DISPLAY")
    old_bus = os.environ.get("DBUS_SESSION_BUS_ADDRESS")
    procs: list[subprocess.Popen] = []
    zenity_procs: list[subprocess.Popen] = []
    try:
        xvfb = subprocess.Popen(
            ["Xvfb", display, "-screen", "0", "1024x768x24"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True)
        procs.append(xvfb)
        time.sleep(1)
        if xvfb.poll() is not None:
            pytest.fail(f"Xvfb failed to start on {display}")
        bus = subprocess.Popen(
            ["dbus-daemon", "--session", "--nofork", "--print-address"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            start_new_session=True)
        procs.append(bus)
        address = bus.stdout.readline().strip()
        assert address.startswith("unix:"), f"no bus address: {address!r}"
        os.environ["DISPLAY"] = display
        os.environ["DBUS_SESSION_BUS_ADDRESS"] = address
        launcher = subprocess.Popen(
            ["/usr/libexec/at-spi-bus-launcher", "--launch-immediately"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True)
        procs.append(launcher)
        time.sleep(1)
        wm = subprocess.Popen(
            ["openbox", "--sm-disable"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True)
        procs.append(wm)
        time.sleep(1)
        for title in _LIVE_TITLES:
            z = subprocess.Popen(
                ["zenity", "--info", f"--title={title}",
                 "--text=live test window", "--no-wrap"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True)
            zenity_procs.append(z)
            procs.append(z)
        backend = AtspiBackend()
        deadline = time.time() + 20
        windows: list[WindowInfo] = []
        while time.time() < deadline:
            try:
                windows = backend.list_windows()
            except WindowControlUnavailable:
                windows = []
            titles = {w.title for w in windows}
            if set(_LIVE_TITLES) <= titles:
                break
            time.sleep(0.5)
        assert set(_LIVE_TITLES) <= {w.title for w in windows}, (
            f"live windows did not appear: {[w.title for w in windows]}")
        yield {"backend": backend,
               "pids": [z.pid for z in zenity_procs]}
    finally:
        for proc in reversed(procs):
            _stop(proc)
        if old_display is None:
            os.environ.pop("DISPLAY", None)
        else:
            os.environ["DISPLAY"] = old_display
        if old_bus is None:
            os.environ.pop("DBUS_SESSION_BUS_ADDRESS", None)
        else:
            os.environ["DBUS_SESSION_BUS_ADDRESS"] = old_bus
        reset_backend()


def test_live_lists_real_windows(live_desktop):
    backend = live_desktop["backend"]
    windows = backend.list_windows()
    by_title = {w.title: w for w in windows}
    for title, pid in zip(_LIVE_TITLES, live_desktop["pids"]):
        w = by_title[title]
        assert w.app_name == "zenity"
        assert w.pid == pid
        assert w.id == f"atspi:{pid}:{title}"
        assert w.bounds is not None
        x, y, width, height = w.bounds
        assert x >= 0 and y >= 0 and width > 0 and height > 0
    assert backend.available()[0] is True


def test_live_focus_flips_active_window(live_desktop):
    backend = live_desktop["backend"]
    windows = {w.title: w for w in backend.list_windows()}
    first = windows[_LIVE_TITLES[0]]
    second = windows[_LIVE_TITLES[1]]

    def _wait_active(window_id, timeout=5.0):
        # Focus activation is asynchronous: the window manager updates
        # _NET_ACTIVE_WINDOW after the client message is processed.
        deadline = time.monotonic() + timeout
        while True:
            active = backend.get_active_window()
            if active is not None and active.id == window_id:
                return active
            if time.monotonic() >= deadline:
                return active
            time.sleep(0.1)

    assert backend.focus_window(first.id) is True
    assert _wait_active(first.id).id == first.id
    assert backend.focus_window(second.id) is True
    assert _wait_active(second.id).id == second.id
    assert backend.window_bounds(second.id) == second.bounds


def test_live_list_windows_tool_uses_tier1(live_desktop, ctx):
    backend = live_desktop["backend"]
    import core.window_control as wc
    old = wc.get_backend
    wc.get_backend = lambda: backend  # noqa: E731
    try:
        result = get_tool("list_windows").execute({}, ctx)
    finally:
        wc.get_backend = old
    assert result["ok"] is True
    assert result["data"]["backend"] == "tier1"
    assert set(_LIVE_TITLES) <= {w["title"] for w in result["data"]["windows"]}


# ---------------------------------------------------------------------------
# UIA backend (Windows, ADR-012 (b)) — mock tests only.
#
# PowerShell cannot run on this Linux host, so every test below drives
# UiaBackend with a fake runner (argv -> CompletedProcess). The scripts
# themselves are never executed here; the live run on a real Windows
# host is a laptop step (STATUS.md Windows column stays NOT VERIFIED
# until that run is recorded). What IS verified here: the id scheme,
# the JSON parsing, the fail-closed focus rules, and that no part of a
# caller-supplied id other than digits can reach the script.
# ---------------------------------------------------------------------------

_UIA_ROWS = [
    {"name": "Notepad", "pid": 1234, "hwnd": 98765, "app": "notepad",
     "x": 10, "y": 20, "width": 800, "height": 600, "active": True},
    {"name": "VS Code", "pid": 2345, "hwnd": 98766, "app": "Code",
     "x": 0, "y": 0, "width": 1920, "height": 1040, "active": False},
]


class _FakeRunner:
    """argv -> CompletedProcess, recording every call.

    ``list_stdout`` is returned for the list script; ``focus_stdout``
    / ``focus_code`` for the focus script (told apart by FromHandle).
    """

    def __init__(self, list_stdout="", list_code=0,
                 focus_stdout="true", focus_code=0, stderr=""):
        self.list_stdout = list_stdout
        self.list_code = list_code
        self.focus_stdout = focus_stdout
        self.focus_code = focus_code
        self.stderr = stderr
        self.calls: list[list[str]] = []

    def __call__(self, argv, timeout=30):
        self.calls.append(list(argv))
        if "FromHandle" in argv[-1]:
            return SimpleNamespace(returncode=self.focus_code,
                                   stdout=self.focus_stdout,
                                   stderr=self.stderr)
        return SimpleNamespace(returncode=self.list_code,
                               stdout=self.list_stdout,
                               stderr=self.stderr)


def _uia_backend(**kwargs):
    return UiaBackend(runner=_FakeRunner(
        list_stdout=json.dumps(_UIA_ROWS), **kwargs))


def _as_windows(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Windows")


def _as_linux(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Linux")


def test_uia_available_false_on_linux(monkeypatch):
    _as_linux(monkeypatch)
    runner = _FakeRunner(list_stdout=json.dumps(_UIA_ROWS))
    backend = UiaBackend(runner=runner)
    available, reason = backend.available()
    assert available is False
    assert "Windows-only" in reason
    assert runner.calls == []  # probe never ran


def test_uia_available_false_when_powershell_missing(monkeypatch):
    _as_windows(monkeypatch)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    backend = UiaBackend()  # real runner: the which() check applies
    available, reason = backend.available()
    assert available is False
    assert "powershell.exe not found" in reason


def test_uia_available_true_when_probe_succeeds(monkeypatch):
    _as_windows(monkeypatch)
    runner = _FakeRunner(list_stdout=json.dumps(_UIA_ROWS))
    backend = UiaBackend(runner=runner)
    available, reason = backend.available()
    assert available is True
    assert "2 windows" in reason
    assert len(runner.calls) == 1  # probe ran once...
    assert backend.available()[0] is True
    assert len(runner.calls) == 1  # ...and is cached, not re-run


def test_uia_available_false_when_probe_fails(monkeypatch):
    _as_windows(monkeypatch)
    runner = _FakeRunner(list_stdout="", list_code=1, stderr="boom")
    backend = UiaBackend(runner=runner)
    available, reason = backend.available()
    assert available is False
    assert "probe failed" in reason


def test_uia_list_windows_maps_json():
    backend = _uia_backend()
    windows = backend.list_windows()
    assert [w.id for w in windows] == ["uia:98765", "uia:98766"]
    assert windows[0].title == "Notepad"
    assert windows[0].app_name == "notepad"
    assert windows[0].pid == 1234
    assert windows[0].bounds == (10, 20, 800, 600)
    assert windows[0].active is True
    assert windows[1].active is False
    assert windows[1].as_dict()["id"] == "uia:98766"


def test_uia_list_windows_single_object_json():
    # ConvertTo-Json emits a bare object (not an array) for one window.
    backend = UiaBackend(runner=_FakeRunner(
        list_stdout=json.dumps(_UIA_ROWS[0])))
    assert [w.id for w in backend.list_windows()] == ["uia:98765"]


def test_uia_list_windows_empty_stdout_is_empty():
    backend = UiaBackend(runner=_FakeRunner(list_stdout=""))
    assert backend.list_windows() == []


def test_uia_list_windows_skips_bad_rows():
    rows = _UIA_ROWS + [
        {"name": "no hwnd", "pid": 1},  # missing hwnd
        {"name": "bad pid", "pid": "x", "hwnd": 111},  # pid not int
        {"name": "zero hwnd", "pid": 1, "hwnd": 0},
        "not a dict",
    ]
    backend = UiaBackend(runner=_FakeRunner(list_stdout=json.dumps(rows)))
    assert [w.id for w in backend.list_windows()] == [
        "uia:98765", "uia:98766"]


def test_uia_list_windows_raises_on_bad_json():
    backend = UiaBackend(runner=_FakeRunner(list_stdout="{not json"))
    with pytest.raises(WindowControlError, match="not valid JSON"):
        backend.list_windows()


def test_uia_list_windows_raises_on_script_failure():
    backend = UiaBackend(runner=_FakeRunner(
        list_stdout="", list_code=1, stderr="Automation failed"))
    with pytest.raises(WindowControlError, match="exit 1"):
        backend.list_windows()


def test_uia_get_active_window():
    backend = _uia_backend()
    assert backend.get_active_window().id == "uia:98765"
    quiet = UiaBackend(runner=_FakeRunner(list_stdout=json.dumps(
        [dict(r, active=False) for r in _UIA_ROWS])))
    assert quiet.get_active_window() is None


def test_uia_focus_window_success():
    runner = _FakeRunner(list_stdout=json.dumps(_UIA_ROWS))
    backend = UiaBackend(runner=runner)
    assert backend.focus_window("uia:98765") is True
    focus_argv = runner.calls[-1]
    assert focus_argv[0] == "powershell.exe"
    assert focus_argv[1:4] == ["-NoProfile", "-NonInteractive", "-Command"]
    # The only caller-controlled text in the script is the digits.
    assert "-Hwnd" not in focus_argv[-1]
    assert "98765" in focus_argv[-1]
    assert "__HWND__" not in focus_argv[-1]


def test_uia_focus_window_not_foreground_returns_false():
    backend = _uia_backend(focus_stdout="false")
    assert backend.focus_window("uia:98765") is False


def test_uia_focus_window_missing_element_returns_false():
    backend = _uia_backend(focus_stdout="", focus_code=2)
    assert backend.focus_window("uia:98765") is False


def test_uia_focus_window_raises_on_script_error():
    backend = _uia_backend(focus_stdout="", focus_code=3,
                           stderr="SetFocus threw")
    with pytest.raises(WindowControlError, match="exit 3"):
        backend.focus_window("uia:98765")


@pytest.mark.parametrize("bad_id", [
    "", "98765", "atspi:1234:Notepad", "uia:abc", "uia:-1", "uia:12x",
    "uia:1; Get-Process", "uia:1 | Format-Table", "uia: 98765",
    "uia:98765 ", "UIA:98765",
])
def test_uia_focus_window_rejects_malformed_ids(bad_id):
    runner = _FakeRunner(list_stdout=json.dumps(_UIA_ROWS))
    backend = UiaBackend(runner=runner)
    assert backend.focus_window(bad_id) is False
    # Nothing hostile ever reached PowerShell.
    assert all("FromHandle" not in call[-1] for call in runner.calls)


def test_uia_focus_window_rejects_huge_hwnd():
    backend = _uia_backend()
    assert backend.focus_window(f"uia:{2**63}") is False


def test_uia_window_bounds():
    backend = _uia_backend()
    assert backend.window_bounds("uia:98766") == (0, 0, 1920, 1040)
    assert backend.window_bounds("uia:1") is None
    assert backend.window_bounds("atspi:1:x") is None


def test_uia_scripts_contain_required_api_calls():
    for token in ("UIAutomationClient", "AutomationElement",
                  "RootElement", "FindAll", "TreeScope",
                  "NativeWindowHandle", "BoundingRectangle",
                  "GetForegroundWindow", "ConvertTo-Json"):
        assert token in _UIA_LIST_SCRIPT, token
    for token in ("UIAutomationClient", "FromHandle", "SetFocus",
                  "GetForegroundWindow"):
        assert token in _UIA_FOCUS_SCRIPT, token
    # No model-controlled interpolation: the only placeholder is the
    # digits-only hwnd token, replaced after int parsing.
    assert "__HWND__" in _UIA_FOCUS_SCRIPT
    assert "$(" not in _UIA_FOCUS_SCRIPT.replace(
        "GetForegroundWindow().ToInt64()", "")


def test_uia_get_backend_dispatch_windows(monkeypatch):
    import core.window_control as wc

    _as_windows(monkeypatch)

    class _FakeUia:
        def __init__(self, *args, **kwargs):
            pass

        def available(self):
            return True, "fake UIA"

    monkeypatch.setattr(wc, "UiaBackend", _FakeUia)
    reset_backend()
    try:
        assert isinstance(get_backend(), _FakeUia)
    finally:
        reset_backend()


def test_uia_tool_focus_uses_backend(monkeypatch, ctx):
    import core.window_control as wc

    _as_windows(monkeypatch)
    runner = _FakeRunner(list_stdout=json.dumps(_UIA_ROWS))
    backend = UiaBackend(runner=runner)
    monkeypatch.setattr(wc, "get_backend", lambda: backend)
    result = get_tool("window_focus").execute(
        {"window_id": "uia:98765"}, ctx)
    assert result["ok"] is True
    assert result["data"]["window_id"] == "uia:98765"
