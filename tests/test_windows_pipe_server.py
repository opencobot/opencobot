"""Tests for the Windows named-pipe *server* listener (ADR-010, R-017).

The listener (``core.transport.NamedPipeListener``) creates the pipe
with ``ctypes`` ``CreateNamedPipeW`` and a DACL that grants
read+write only to the current user and to local Administrators and
explicitly denies remote (NETWORK) logons. It can never run on this
Linux VM (no Win32 API), so everything here is mock-verified:

* the DACL *policy* (who is allowed / denied) is a pure function,
  tested directly;
* the Win32 struct layouts are checked against the 64-bit Windows
  sizes (fixed-width types, so the check is meaningful on Linux);
* the accept loop, JSON-lines dispatch and every fail-closed path
  run against a fake Win32 API injected into the listener;
* the ``policyd`` / daemon wiring is checked by stubbing the
  listener class and calling the handler it was given.

What is NOT verified here (honest limit): the real ``ctypes`` calls
against a real pipe — that needs the laptop run in
docs/WINDOWS_TESTING.md §6.
"""

import platform
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.daemon import Daemon  # noqa: E402
from core.transport import (  # noqa: E402
    DAEMON_PIPE_PATH,
    POLICYD_PIPE_PATH,
    NamedPipeListener,
    TransportNotAvailableError,
    _CtypesWindowsPipeApi,
    _ExplicitAccess,
    _HANDLE,
    _Overlapped,
    _SecurityAttributes,
    _TokenUser,
    _Trustee,
    _load_windows_api,
    _pipe_dacl_entries,
    encode_message,
)
from policy.policyd import serve as policyd_serve  # noqa: E402
from tests._procutil import unique_policyd_pipe  # noqa: E402

import ctypes  # noqa: E402


@pytest.fixture()
def windows_platform(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Windows")


# ---------------------------------------------------------------------------
# Fake Win32 API: same methods as _CtypesWindowsPipeApi, scripted bytes
# ---------------------------------------------------------------------------

class FakeWindowsPipeApi:
    """Stand-in for the Win32 pipe API.

    ``connections`` is a list of byte payloads, one per client
    connection; ``read_available`` serves at most ``read_chunk_size``
    bytes per call so line-splitting across chunks is testable.
    ``writes`` collects every reply the listener wrote, in order.
    """

    def __init__(self, connections=(), read_chunk_size=65536):
        self.connections = [bytearray(c) for c in connections]
        self.read_chunk_size = read_chunk_size
        self.writes: list[bytes] = []
        self.calls: list = []
        self.sa = object()  # sentinel SECURITY_ATTRIBUTES
        self.fail_acl: Exception | None = None
        self.fail_create: Exception | None = None
        self.fail_read_on: set[int] = set()
        self._conn_index = -1
        self._current: bytearray | None = None

    def build_security_attributes(self):
        self.calls.append("build_security_attributes")
        if self.fail_acl is not None:
            raise self.fail_acl
        return self.sa

    def create_pipe(self, pipe_path, sa):
        self.calls.append(("create_pipe", pipe_path, sa))
        if self.fail_create is not None:
            raise self.fail_create
        return 1001  # fake HANDLE

    def wait_for_client(self, handle, stop):
        self.calls.append("wait_for_client")
        if self.connections:
            self._current = self.connections.pop(0)
            self._conn_index += 1
            return True
        if stop is not None:
            stop.set()
        return False

    def read_available(self, handle, size):
        if self._conn_index in self.fail_read_on:
            raise TransportNotAvailableError("fake read failure")
        if self._current is None or not self._current:
            return b""
        n = min(len(self._current), size, self.read_chunk_size)
        chunk = bytes(self._current[:n])
        del self._current[:n]
        return chunk

    def write_all(self, handle, data):
        self.calls.append(("write_all", bytes(data)))
        self.writes.append(bytes(data))

    def disconnect(self, handle):
        self.calls.append("disconnect")

    def close(self, handle):
        self.calls.append(("close", handle))


# ---------------------------------------------------------------------------
# Fake windll: enforces DLL ownership (BUG-A/B/C regression guard)
# ---------------------------------------------------------------------------
#
# The listener-level fake above cannot catch a prototype set on the
# wrong DLL: real ``ctypes`` happily lets you set
# ``kernel32.OpenProcessToken.restype`` (it just creates an attribute
# on the wrong function object) while the real ``advapi32`` call then
# runs with no argtypes. That is exactly how BUG-A/B/C shipped. This
# windll-level fake only exposes each Win32 function on the DLL that
# really owns it, so any wrong-DLL access — including a prototype
# assignment in ``_CtypesWindowsPipeApi._setup_prototypes`` — raises
# ``AttributeError`` loudly instead of silently doing nothing.

class _FakeWin32Function:
    """Stand-in for one ctypes foreign function.

    Setting ``restype`` / ``argtypes`` works (that is what the
    prototype setup does); calling it raises, since no test here
    drives a real Win32 call.
    """

    def __init__(self):
        self.restype = None
        self.argtypes = None

    def __call__(self, *args, **kwargs):  # pragma: no cover - guard
        raise NotImplementedError("fake Win32 function must not be called")


# advapi32 owns the token/SID/ACL functions; kernel32 owns the
# process/pipe/file functions (see the rule comment in
# _CtypesWindowsPipeApi._setup_prototypes).
_ADVAPI32_FUNCTIONS = (
    "OpenProcessToken",
    "GetTokenInformation",
    "CreateWellKnownSid",
    "SetEntriesInAclW",
    "InitializeSecurityDescriptor",
    "SetSecurityDescriptorDacl",
    "GetLengthSid",
)
_KERNEL32_FUNCTIONS = (
    "GetCurrentProcess",
    "CreateNamedPipeW",
    "CreateEventW",
    "ConnectNamedPipe",
    "WaitForSingleObject",
    "GetOverlappedResult",
    "CancelIoEx",
    "ReadFile",
    "WriteFile",
    "DisconnectNamedPipe",
    "CloseHandle",
    "LocalFree",
)


class _FakeDll:
    """One fake DLL object: exposes ONLY the functions it owns.

    No ``__getattr__`` fallback: accessing any other function name
    raises ``AttributeError``, exactly as real ``ctypes.windll``
    does for a function the DLL does not export.
    """

    def __init__(self, function_names):
        for name in function_names:
            setattr(self, name, _FakeWin32Function())


class _FakeWindll:
    """Fake ``ctypes.windll`` with DLL ownership enforced."""

    def __init__(self):
        self.kernel32 = _FakeDll(_KERNEL32_FUNCTIONS)
        self.advapi32 = _FakeDll(_ADVAPI32_FUNCTIONS)


def _echo_handler(calls):
    def handler(request):
        calls.append(request)
        return {"ok": True, "echo": request.get("op")}
    return handler


def _listen(api, pipe_path=POLICYD_PIPE_PATH, handler=None, stop=None):
    stop = stop if stop is not None else threading.Event()
    calls: list = []
    if handler is None:
        handler = _echo_handler(calls)
    NamedPipeListener(pipe_path, api=api).listen(handler=handler, stop=stop)
    return calls


class _RegistryFakeApi(FakeWindowsPipeApi):
    """Fake Win32 pipe API with a shared registry of bound pipe names.

    Models the real ``CreateNamedPipeW`` behaviour: creating a second
    pipe with a name that is already bound fails, and closing the
    handle releases the name. ``wait_for_client`` blocks until the
    listener is stopped, so the pipe stays bound while the listener
    thread is alive. The registry is class-level (the OS pipe
    namespace is process-wide), so tests must clear it first/last.
    """

    bound: set = set()

    def create_pipe(self, pipe_path, sa):
        if pipe_path in type(self).bound:
            raise OSError(f"pipe {pipe_path} is already bound")
        type(self).bound.add(pipe_path)
        self._bound_path = pipe_path
        return super().create_pipe(pipe_path, sa)

    def close(self, handle):
        type(self).bound.discard(getattr(self, "_bound_path", None))
        super().close(handle)

    def wait_for_client(self, handle, stop):
        if stop is not None:
            while not stop.is_set():
                time.sleep(0.01)
        return False


# ---------------------------------------------------------------------------
# DACL policy: pure function, no Win32 needed
# ---------------------------------------------------------------------------

_USER_SID = bytes.fromhex("010500000000000515000000")
_ADMIN_SID = bytes.fromhex("01020000000000052000000020020000")
_NETWORK_SID = bytes.fromhex("010100000000000502000000")


def test_dacl_policy_denies_network_first_then_grants_user_and_admin():
    entries = _pipe_dacl_entries(_USER_SID, _ADMIN_SID, _NETWORK_SID)
    assert len(entries) == 3
    # DENY first: an explicit deny must precede the grants.
    deny, grant_user, grant_admin = entries
    assert deny.mode == 3  # DENY_ACCESS
    assert deny.sid == _NETWORK_SID
    assert deny.trustee_type == 5  # TRUSTEE_IS_WELL_KNOWN_GROUP
    assert grant_user.mode == 1  # GRANT_ACCESS
    assert grant_user.sid == _USER_SID
    assert grant_user.trustee_type == 1  # TRUSTEE_IS_USER
    assert grant_admin.mode == 1
    assert grant_admin.sid == _ADMIN_SID
    assert grant_admin.trustee_type == 5
    # All three entries grant/deny the same mask: read + write only.
    for entry in entries:
        assert entry.access == 0x80000000 | 0x40000000  # GENERIC_R|W


def test_dacl_policy_grants_nobody_else():
    """Only the three SIDs above appear — any other local account
    gets no ACE, hence no access."""
    entries = _pipe_dacl_entries(_USER_SID, _ADMIN_SID, _NETWORK_SID)
    assert {e.sid for e in entries} == {
        _USER_SID, _ADMIN_SID, _NETWORK_SID}


# ---------------------------------------------------------------------------
# Win32 struct layouts: fixed-width types, checkable on Linux
# ---------------------------------------------------------------------------

def test_win32_struct_layouts_match_64bit_windows():
    # 64-bit Windows sizes (offsets verified against WinNT.h /
    # AccCtrl.h): TRUSTEE 32, EXPLICIT_ACCESS 48 (trustee at 16),
    # SECURITY_ATTRIBUTES 24, OVERLAPPED 32, TOKEN_USER 16.
    assert ctypes.sizeof(_Trustee) == 32
    assert ctypes.sizeof(_ExplicitAccess) == 48
    assert _ExplicitAccess.Trustee.offset == 16
    assert ctypes.sizeof(_SecurityAttributes) == 24
    assert ctypes.sizeof(_Overlapped) == 32
    assert ctypes.sizeof(_TokenUser) == 16


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="ctypes.windll always exists on real Windows; the no-windll "
    "path is Linux-only",
)
def test_load_windows_api_fails_closed_without_windll():
    # On this Linux host ctypes.windll does not exist: the same
    # NotImplementedError the shape-only listener raised.
    with pytest.raises(NotImplementedError, match="CreateNamedPipeW"):
        _load_windows_api()


# ---------------------------------------------------------------------------
# ctypes prototypes: DLL ownership (BUG-A/B/C regression tests)
# ---------------------------------------------------------------------------

def test_fake_dll_refuses_functions_owned_by_the_other_dll():
    """The fake windll raises AttributeError for a wrong-DLL access —
    the guard that would have caught BUG-A/B/C in the mock tests."""
    windll = _FakeWindll()
    # advapi32-only functions are not on kernel32 ...
    with pytest.raises(AttributeError):
        windll.kernel32.OpenProcessToken
    with pytest.raises(AttributeError):
        windll.kernel32.GetLengthSid
    with pytest.raises(AttributeError):
        windll.kernel32.GetTokenInformation
    # ... and kernel32-only functions are not on advapi32.
    with pytest.raises(AttributeError):
        windll.advapi32.CreateNamedPipeW
    with pytest.raises(AttributeError):
        windll.advapi32.CloseHandle
    with pytest.raises(AttributeError):
        windll.advapi32.GetCurrentProcess
    # A wrong-DLL *prototype assignment* fails loudly too, instead
    # of silently creating an attribute on the wrong function object.
    with pytest.raises(AttributeError):
        windll.kernel32.OpenProcessToken.restype = ctypes.c_int32
    with pytest.raises(AttributeError):
        windll.advapi32.CreateNamedPipeW.argtypes = []


def test_ctypes_prototypes_land_on_the_correct_dll():
    """Regression test for BUG-A/B/C: constructing the real API
    against the ownership-enforcing fake windll succeeds only if
    every prototype is set on the DLL that owns the function."""
    windll = _FakeWindll()
    api = _CtypesWindowsPipeApi(windll)  # raises AttributeError if wrong
    # The two previously wrong prototypes now live on advapi32 ...
    assert api._advapi32.OpenProcessToken.restype is not None
    assert api._advapi32.OpenProcessToken.argtypes is not None
    assert api._advapi32.GetLengthSid.restype is not None
    assert api._advapi32.GetLengthSid.argtypes is not None
    # ... and kernel32 exposes neither of them at all.
    assert not hasattr(windll.kernel32, "OpenProcessToken")
    assert not hasattr(windll.kernel32, "GetLengthSid")
    # The rest of the ownership split, both directions.
    for name in _ADVAPI32_FUNCTIONS:
        assert hasattr(windll.advapi32, name), name
        assert not hasattr(windll.kernel32, name), name
    for name in _KERNEL32_FUNCTIONS:
        assert hasattr(windll.kernel32, name), name
        assert not hasattr(windll.advapi32, name), name
    # Every prototype was actually set (not left at the None default).
    for dll in (windll.kernel32, windll.advapi32):
        for name in vars(dll):
            fn = getattr(dll, name)
            assert fn.restype is not None, name
            assert fn.argtypes is not None, name


def test_handle_type_holds_the_pseudo_handle():
    """Regression test for the HANDLE overflow (BUG-C): ``_HANDLE``
    must be the unsigned ``c_size_t`` (ULONG_PTR), not ``c_void_p``,
    so the ``GetCurrentProcess()`` pseudo-handle 0xffffffffffffffff
    round-trips instead of overflowing."""
    assert _HANDLE is ctypes.c_size_t
    assert _HANDLE(0xFFFFFFFFFFFFFFFF).value == 0xFFFFFFFFFFFFFFFF
    assert _HANDLE(-1).value == 0xFFFFFFFFFFFFFFFF


# ---------------------------------------------------------------------------
# Listener: ACL is built before the pipe, and the pipe gets that ACL
# ---------------------------------------------------------------------------

def test_listener_builds_acl_before_creating_pipe(windows_platform):
    api = FakeWindowsPipeApi(connections=[])
    _listen(api)
    assert api.calls[0] == "build_security_attributes"
    assert api.calls[1] == ("create_pipe", POLICYD_PIPE_PATH, api.sa)
    assert ("close", 1001) in api.calls


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="the platform guard only refuses on non-Windows hosts; on "
    "Windows the listener accepts a fake API and serves",
)
def test_listener_refuses_on_linux_even_with_fake_api():
    api = FakeWindowsPipeApi(connections=[])
    with pytest.raises(TransportNotAvailableError,
                       match="not available on this platform"):
        NamedPipeListener(POLICYD_PIPE_PATH, api=api).listen(
            handler=lambda req: {}, stop=threading.Event())


def test_listener_requires_a_handler(windows_platform):
    api = FakeWindowsPipeApi(connections=[])
    with pytest.raises(ValueError, match="needs a request handler"):
        NamedPipeListener(POLICYD_PIPE_PATH, api=api).listen(
            handler=None, stop=threading.Event())
    assert api.calls == [], "no pipe must be created without a handler"


def test_listener_stop_already_set_creates_nothing(windows_platform):
    api = FakeWindowsPipeApi(connections=[])
    stop = threading.Event()
    stop.set()
    NamedPipeListener(POLICYD_PIPE_PATH, api=api).listen(
        handler=lambda req: {}, stop=stop)
    assert api.calls == [], "a pre-set stop must not create a pipe"


# ---------------------------------------------------------------------------
# Listener: accept loop + JSON-lines dispatch against the fake API
# ---------------------------------------------------------------------------

def test_listener_serves_one_request_and_replies(windows_platform):
    api = FakeWindowsPipeApi(connections=[
        encode_message({"op": "status", "auth": "a" * 64}),
    ])
    calls = _listen(api)
    assert calls == [{"op": "status", "auth": "a" * 64}]
    assert api.writes == [
        encode_message({"ok": True, "echo": "status"})]
    assert api.calls.count("disconnect") == 1
    assert ("close", 1001) in api.calls


def test_listener_splits_lines_across_chunks(windows_platform):
    payload = (
        encode_message({"op": "one"})
        + encode_message({"op": "two"})
    )
    api = FakeWindowsPipeApi(connections=[payload], read_chunk_size=5)
    calls = _listen(api)
    assert [c["op"] for c in calls] == ["one", "two"]
    assert api.writes == [
        encode_message({"ok": True, "echo": "one"}),
        encode_message({"ok": True, "echo": "two"}),
    ]


def test_listener_bad_json_gets_error_reply_and_connection_survives(
        windows_platform):
    api = FakeWindowsPipeApi(connections=[
        b"not json\n" + encode_message({"op": "ok"}),
    ])
    calls = _listen(api)
    assert calls == [{"op": "ok"}]
    assert api.writes[0] == encode_message(
        {"ok": False, "error": "invalid request"})
    assert api.writes[1] == encode_message({"ok": True, "echo": "ok"})


def test_listener_blank_lines_skipped(windows_platform):
    api = FakeWindowsPipeApi(connections=[
        b"\n\n" + encode_message({"op": "ok"}) + b"\n",
    ])
    calls = _listen(api)
    assert calls == [{"op": "ok"}]
    assert len(api.writes) == 1


def test_listener_handler_exception_gets_error_reply(windows_platform):
    def boom(request):
        raise RuntimeError("kaboom")

    api = FakeWindowsPipeApi(connections=[encode_message({"op": "x"})])
    NamedPipeListener(POLICYD_PIPE_PATH, api=api).listen(
        handler=boom, stop=threading.Event())
    assert api.writes == [
        encode_message({"ok": False, "error": "handler error: kaboom"})]


def test_listener_client_disconnect_ends_connection_not_server(
        windows_platform):
    # First client sends a partial line (no newline) then disconnects;
    # the second client is still served.
    api = FakeWindowsPipeApi(connections=[
        b'{"op": "never-dispatched"',
        encode_message({"op": "served"}),
    ])
    calls = _listen(api)
    assert calls == [{"op": "served"}]
    assert api.calls.count("disconnect") == 2
    assert api.writes == [encode_message({"ok": True, "echo": "served"})]


def test_listener_read_failure_ends_connection_not_server(windows_platform):
    api = FakeWindowsPipeApi(connections=[
        encode_message({"op": "dropped"}),
        encode_message({"op": "served"}),
    ])
    api.fail_read_on = {0}
    calls = _listen(api)
    assert calls == [{"op": "served"}]
    assert api.calls.count("disconnect") == 2


# ---------------------------------------------------------------------------
# Listener: fail closed — never serve an unprotected pipe
# ---------------------------------------------------------------------------

def test_listener_fail_closed_when_acl_build_fails(windows_platform):
    api = FakeWindowsPipeApi(connections=[])
    api.fail_acl = TransportNotAvailableError("SetEntriesInAclW failed")
    with pytest.raises(TransportNotAvailableError, match="SetEntriesInAclW"):
        _listen(api)
    assert not any(
        c[0] == "create_pipe" for c in api.calls if isinstance(c, tuple)
    ), "no pipe may be created when the ACL cannot be built"
    assert "wait_for_client" not in api.calls


def test_listener_fail_closed_when_acl_build_raises_unexpectedly(
        windows_platform):
    api = FakeWindowsPipeApi(connections=[])
    api.fail_acl = RuntimeError("GetTokenInformation blew up")
    with pytest.raises(TransportNotAvailableError,
                       match="cannot build the pipe ACL"):
        _listen(api)
    assert not any(
        c[0] == "create_pipe" for c in api.calls if isinstance(c, tuple)
    )


def test_listener_fail_closed_when_create_pipe_fails(windows_platform):
    api = FakeWindowsPipeApi(connections=[])
    api.fail_create = TransportNotAvailableError("CreateNamedPipeW failed")
    with pytest.raises(TransportNotAvailableError, match="CreateNamedPipeW"):
        _listen(api)
    assert "wait_for_client" not in api.calls
    assert api.calls[0] == "build_security_attributes"


# ---------------------------------------------------------------------------
# Wiring: policyd / daemon hand the listener their real handler
# ---------------------------------------------------------------------------

class _StubListener:
    """Records what serve() passes to the listener; never serves."""

    instances: list = []

    def __init__(self, pipe_path, api=None):
        self.pipe_path = pipe_path
        self.handler = None
        self.stop = None
        _StubListener.instances.append(self)

    def listen(self, handler=None, stop=None):
        self.handler = handler
        self.stop = stop


@pytest.fixture()
def stub_listener(monkeypatch):
    _StubListener.instances.clear()
    monkeypatch.setattr("policy.policyd.NamedPipeListener", _StubListener)
    monkeypatch.setattr("core.daemon.NamedPipeListener", _StubListener)
    yield _StubListener
    _StubListener.instances.clear()


def test_policyd_serve_hands_listener_its_handler(
        tmp_path, windows_platform, stub_listener):
    state = tmp_path / "state"
    state.mkdir()
    stop = threading.Event()
    policyd_serve(state, stop)
    assert len(stub_listener.instances) == 1
    listener = stub_listener.instances[0]
    assert listener.pipe_path == POLICYD_PIPE_PATH
    assert listener.stop is stop
    token = (state / "policyd.auth").read_text(encoding="utf-8").strip()
    reply = listener.handler({"op": "status", "auth": token})
    assert reply["ok"] is True
    assert reply["socket"] == POLICYD_PIPE_PATH
    assert listener.handler(
        {"op": "status", "auth": "wrong"})["error"] == "auth failed"


def test_daemon_serve_forever_hands_listener_its_handler(
        tmp_path, windows_platform, stub_listener):
    state = tmp_path / "state"
    state.mkdir()
    daemon = Daemon(state)
    daemon.serve_forever()
    assert len(stub_listener.instances) == 1
    listener = stub_listener.instances[0]
    assert listener.pipe_path == DAEMON_PIPE_PATH
    assert listener.stop is daemon._stop
    token = (state / "daemon.auth").read_text(encoding="utf-8").strip()
    reply = listener.handler({"op": "status", "auth": token})
    assert reply["ok"] is True
    assert reply["policyd_reachable"] is False
    assert listener.handler(
        {"op": "status", "auth": "wrong"})["error"] == "unauthorized"


# ---------------------------------------------------------------------------
# Per-test pipe isolation (Windows full-suite failures, PR #36)
# ---------------------------------------------------------------------------

def test_two_unique_pipes_coexist_and_bound_name_collides(windows_platform):
    """Collision mechanism, mock-proven: two listeners on two unique
    pipe names both start; a second listener on an already-bound name
    fails; after the first stops, its name can be bound again.

    This is the mechanism behind the Windows full-suite failures in
    docs/test-results/2026-11-25-windows-ffa7b3c.md: every fixture
    server bound the same fixed global pipe, so a leaked server
    blocked the next one. The fix (a unique OPENCOBOT_POLICYD_PIPE
    per test) makes each server hold only its own name.
    """
    _RegistryFakeApi.bound.clear()
    try:
        name_a = r"\\.\pipe\opencobot-policyd-test-aaaa"
        name_b = r"\\.\pipe\opencobot-policyd-test-bbbb"
        stop_a, stop_b = threading.Event(), threading.Event()
        errors: list = []

        def _run(api, name, stop):
            try:
                _listen(api, name, None, stop)
            except Exception as exc:  # noqa: BLE001 - recorded for assert
                errors.append(exc)

        thread_a = threading.Thread(
            target=_run, args=(_RegistryFakeApi(), name_a, stop_a),
            daemon=True)
        thread_b = threading.Thread(
            target=_run, args=(_RegistryFakeApi(), name_b, stop_b),
            daemon=True)
        thread_a.start()
        thread_b.start()
        try:
            deadline = time.time() + 5
            while {name_a, name_b} - _RegistryFakeApi.bound:
                assert time.time() < deadline, "listener did not bind in time"
                time.sleep(0.01)
            assert errors == []
            # Second listener on the already-bound name fails.
            with pytest.raises(TransportNotAvailableError):
                _listen(_RegistryFakeApi(), name_a, None, threading.Event())
            # After the first stops, its name can be bound again.
            stop_a.set()
            thread_a.join(timeout=5)
            assert not thread_a.is_alive()
            assert name_a not in _RegistryFakeApi.bound
            stop_a2 = threading.Event()
            thread_a2 = threading.Thread(
                target=_run, args=(_RegistryFakeApi(), name_a, stop_a2),
                daemon=True)
            thread_a2.start()
            deadline = time.time() + 5
            while name_a not in _RegistryFakeApi.bound:
                assert time.time() < deadline, "re-bind did not happen in time"
                time.sleep(0.01)
            stop_a2.set()
            thread_a2.join(timeout=5)
            assert not thread_a2.is_alive()
            assert errors == []
        finally:
            stop_a.set()
            stop_b.set()
            thread_a.join(timeout=5)
            thread_b.join(timeout=5)
    finally:
        _RegistryFakeApi.bound.clear()


def test_policyd_serve_passes_env_pipe_to_listener(
        tmp_path, windows_platform, stub_listener, monkeypatch):
    """serve() listens on the OPENCOBOT_POLICYD_PIPE override, and the
    status reply reports that same pipe — client and server agree."""
    unique = unique_policyd_pipe(monkeypatch)
    state = tmp_path / "state"
    state.mkdir()
    stop = threading.Event()
    policyd_serve(state, stop)
    assert len(stub_listener.instances) == 1
    listener = stub_listener.instances[0]
    assert listener.pipe_path == unique
    assert listener.stop is stop
    token = (state / "policyd.auth").read_text(encoding="utf-8").strip()
    reply = listener.handler({"op": "status", "auth": token})
    assert reply["ok"] is True
    assert reply["socket"] == unique
