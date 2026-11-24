"""Tests for the policyd/daemon transport abstraction (Slice B).

Unix socket (AF_UNIX, unchanged on Linux) vs Windows named pipe
(``\\\\.\\pipe\\opencobot-policyd`` / ``\\\\.\\pipe\\opencobot-daemon``).
The JSON-lines protocol must be byte-identical over both transports;
the named-pipe client raises clearly on Linux and works against a
fake pipe; the server side is a real ``ctypes`` listener with a
current-user-only ACL (ADR-010) — it serves on Windows and refuses
to start only when the Win32 API is unavailable (fail closed).
"""

import ctypes
import io
import json
import socket
import threading
import types
from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import platform  # noqa: E402

from core.daemon import Daemon  # noqa: E402
from core.transport import (  # noqa: E402
    DAEMON_PIPE_PATH,
    POLICYD_PIPE_PATH,
    NamedPipeListener,
    NamedPipeTransport,
    TransportNotAvailableError,
    UnixSocketTransport,
    decode_message,
    encode_message,
)
from policy import (  # noqa: E402
    PolicyAuthError,
    PolicyClient,
    PolicyUnavailable,
)
from policy.engine import PolicyEngine  # noqa: E402
from policy.policyd import handle_request, serve  # noqa: E402


class FakePipe:
    """In-memory stand-in for a Windows named pipe (client side).

    ``write`` captures request bytes; ``readline`` serves a pre-loaded
    reply. Satisfies the binary file-like interface the client uses.
    """

    def __init__(self, reply_bytes: bytes):
        self._read = io.BytesIO(reply_bytes)
        self.written = b""
        self.closed = False

    def write(self, data: bytes) -> int:
        self.written += data
        return len(data)

    def flush(self) -> None:
        pass

    def readline(self) -> bytes:
        return self._read.readline()

    def close(self) -> None:
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def _status_reply():
    return encode_message(
        {"ok": True, "killed": False, "socket": POLICYD_PIPE_PATH,
         "audit_entries": 0})


class FakePipeApi:
    """In-memory stand-in for the Win32 pipe API (server side).

    Implements the interface :class:`NamedPipeListener` uses
    (``build_security_attributes`` / ``create_pipe`` /
    ``wait_for_client`` / ``read_available`` / ``write_all`` /
    ``disconnect`` / ``close``) so the listener's accept loop is
    verified on Linux, where ``ctypes.windll`` does not exist. Serves
    one request (``request_bytes``) then reports disconnect; a
    second ``wait_for_client`` returns False so ``listen()`` exits.
    """

    def __init__(self, request_bytes: bytes):
        self._request = request_bytes
        self._served = False
        self.written = b""
        self.pipe_path = None
        self.security_attributes_built = False
        self.closed = False

    def build_security_attributes(self):
        self.security_attributes_built = True
        return object()  # opaque SECURITY_ATTRIBUTES stand-in

    def create_pipe(self, pipe_path, sa):
        self.pipe_path = pipe_path
        assert sa is not None, "pipe must be created with an ACL"
        return 1  # fake HANDLE

    def wait_for_client(self, handle, stop):
        if self._served:
            return False
        self._served = True
        return True

    def read_available(self, handle, size):
        if self._request is None:
            return b""  # client disconnected
        request, self._request = self._request, None
        return request

    def write_all(self, handle, data):
        self.written += data

    def disconnect(self, handle):
        pass

    def close(self, handle):
        self.closed = True


@pytest.fixture()
def auth_state(tmp_path):
    """State dir with a policyd auth file (no server running)."""
    state = tmp_path / "state"
    state.mkdir()
    (state / "policyd.auth").write_text("a" * 64, encoding="utf-8")
    return state


@pytest.fixture()
def unix_echo_server(tmp_path):
    """A minimal AF_UNIX server: captures one request line, replies status."""
    state = tmp_path / "state"
    state.mkdir()
    (state / "policyd.auth").write_text("a" * 64, encoding="utf-8")
    sock_path = state / "policyd.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(sock_path))
    server.listen(1)
    server.settimeout(5)
    captured = {}

    def _serve_once():
        try:
            conn, _ = server.accept()
        except socket.timeout:
            return
        with conn, conn.makefile("rwb") as f:
            captured["request"] = f.readline()
            f.write(_status_reply())
            f.flush()

    thread = threading.Thread(target=_serve_once, daemon=True)
    thread.start()
    yield state, captured
    server.close()


@pytest.fixture()
def windows_platform(monkeypatch):
    monkeypatch.setattr(platform, "system", lambda: "Windows")


# ---------------------------------------------------------------------------
# Framing: identical bytes over both transports
# ---------------------------------------------------------------------------

def test_encode_decode_roundtrip():
    payload = {"op": "status", "auth": "a" * 64}
    assert decode_message(encode_message(payload)) == payload
    assert encode_message(payload) == (
        json.dumps(payload) + "\n").encode("utf-8")


def test_decode_message_rejects_bad_input():
    with pytest.raises(ValueError):
        decode_message(b"not json\n")
    with pytest.raises(ValueError):
        decode_message(b"[1, 2]\n")


@pytest.mark.skipif(sys.platform == "win32", reason=(
    "Unix-only: the echo server binds socket.AF_UNIX, which does "
    "not exist on Windows; pipe-side framing is covered by "
    "test_named_pipe_client_check_against_fake_pipe"))
def test_protocol_framing_identical_over_both_transports(unix_echo_server):
    state, captured = unix_echo_server
    unix_client = PolicyClient(state)
    assert unix_client.status()["killed"] is False
    unix_bytes = captured["request"]
    assert unix_bytes, "Unix server saw no request"

    pipe = FakePipe(_status_reply())
    pipe_client = PolicyClient(
        state, transport=NamedPipeTransport(pipe_file=pipe))
    assert pipe_client.status()["killed"] is False
    assert pipe.written == unix_bytes
    assert pipe.written == encode_message(
        {"op": "status", "auth": "a" * 64})


def test_named_pipe_client_check_against_fake_pipe(auth_state):
    reply = encode_message(
        {"ok": True, "allowed": True, "reason": "allowed",
         "needs_approval": False})
    pipe = FakePipe(reply)
    client = PolicyClient(
        auth_state, transport=NamedPipeTransport(pipe_file=pipe))
    decision = client.check(None, "read_file", 0, {"path": "a.txt"})
    assert decision.allowed is True
    assert decision.reason == "allowed"
    assert json.loads(pipe.written.decode("utf-8"))["op"] == "check"


# ---------------------------------------------------------------------------
# Unix client unchanged on Linux
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform == "win32", reason=(
    "Unix-only: UnixSocketTransport is the POSIX default; on "
    "Windows PolicyClient selects NamedPipeTransport (see "
    "test_named_pipe_client_selected_on_windows)"))
def test_unix_client_defaults_on_linux(auth_state):
    client = PolicyClient(auth_state)
    assert isinstance(client._transport, UnixSocketTransport)
    assert client.sock_path == auth_state / "policyd.sock"
    assert client.pipe_path == POLICYD_PIPE_PATH


def test_unix_transport_missing_socket_message(tmp_path):
    transport = UnixSocketTransport(tmp_path / "nope.sock")
    with pytest.raises(TransportNotAvailableError, match="socket missing"):
        transport.connect()


def test_unix_client_unavailable_without_server(auth_state):
    client = PolicyClient(auth_state)
    with pytest.raises(PolicyUnavailable):
        client.status()


# ---------------------------------------------------------------------------
# Named-pipe client: clear failure on Linux, Windows shape
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform == "win32", reason=(
    "Linux-only: asserts the Linux refusal message; on Windows "
    "the named-pipe transport is available"))
def test_named_pipe_client_raises_clearly_on_linux(auth_state):
    transport = NamedPipeTransport()
    with pytest.raises(TransportNotAvailableError,
                       match="not available on this platform"):
        transport.connect()
    client = PolicyClient(auth_state, transport=NamedPipeTransport())
    with pytest.raises(PolicyUnavailable,
                       match="not available on this platform"):
        client.status()


def test_named_pipe_client_selected_on_windows(auth_state, windows_platform):
    client = PolicyClient(auth_state)
    assert isinstance(client._transport, NamedPipeTransport)
    assert client.sock_path is None
    assert client.pipe_path == POLICYD_PIPE_PATH
    # Fake Windows on a Linux host: the transport is selected, but the
    # OS-level open() of the pipe path fails (no such pipe) — still a
    # clean PolicyUnavailable, never a Unix-socket error.
    with pytest.raises(PolicyUnavailable,
                       match="cannot connect to named pipe"):
        client.status()


@pytest.mark.skipif(sys.platform == "win32", reason=(
    "Linux-only: asserts the Linux refusal message; on Windows "
    "the named-pipe listener is available"))
def test_named_pipe_listener_raises_on_linux():
    with pytest.raises(TransportNotAvailableError,
                       match="not available on this platform"):
        NamedPipeListener(POLICYD_PIPE_PATH).listen()


def test_named_pipe_listener_refuses_without_win32_api_on_windows(windows_platform, monkeypatch):
    """Fail closed, ADR-010: on Windows the listener refuses to start
    when the Win32 API is unavailable — an ACL-less pipe is never
    served. The refusal is about the missing API, not about Windows
    as such: see test_named_pipe_listener_serves_request_with_fake_api_on_windows.
    BUG-J: the test must delete ``ctypes.windll`` explicitly. On a
    Linux host it is absent anyway, but on real Windows it exists —
    without the deletion the listener really starts and blocks in
    ``ConnectNamedPipe`` waiting for a client, hanging the test.
    """
    monkeypatch.delattr(ctypes, "windll", raising=False)
    with pytest.raises(NotImplementedError, match="CreateNamedPipeW"):
        NamedPipeListener(POLICYD_PIPE_PATH).listen(
            handler=lambda req: {"ok": True})
    with pytest.raises(NotImplementedError, match="ACL"):
        NamedPipeListener(DAEMON_PIPE_PATH).listen(
            handler=lambda req: {"ok": True})


def test_named_pipe_listener_serves_request_with_fake_api_on_windows(windows_platform):
    """ADR-010: the listener EXISTS on Windows now — with a Win32 API
    available it serves requests over the pipe instead of refusing.
    The fake API stands in for ``ctypes.windll`` (absent on Linux);
    the listener must still build the ACL before creating the pipe.
    """
    request = encode_message({"op": "status", "auth": "a" * 64})
    api = FakePipeApi(request)
    stop = threading.Event()
    listener = NamedPipeListener(POLICYD_PIPE_PATH, api=api)
    listener.listen(handler=lambda req: {"ok": True, "echo": req.get("op")},
                    stop=stop)
    assert api.pipe_path == POLICYD_PIPE_PATH
    assert api.security_attributes_built is True
    assert api.written == encode_message({"ok": True, "echo": "status"})
    assert api.closed is True


def test_named_pipe_listener_requires_handler_on_windows(windows_platform):
    """Fail closed: even with a Win32 API, the listener refuses to
    serve without a request handler."""
    api = FakePipeApi(b"")
    with pytest.raises(ValueError, match="handler"):
        NamedPipeListener(POLICYD_PIPE_PATH, api=api).listen()


# ---------------------------------------------------------------------------
# Server side: listener selection by platform (mocked)
# ---------------------------------------------------------------------------

def test_policyd_serve_refuses_without_win32_api_on_windows(tmp_path, windows_platform, monkeypatch):
    """Fail closed: policyd on Windows refuses to start when the
    Win32 API is unavailable — no ACL-less pipe is ever served.
    The refusal is about the missing API, not about Windows as
    such (see the _uses_named_pipe_listener test below).
    BUG-J: ``ctypes.windll`` is deleted explicitly so the missing
    API is really simulated — on real Windows it exists, and
    without the deletion serve() would really start listening and
    hang waiting for a client."""
    monkeypatch.delattr(ctypes, "windll", raising=False)
    state = tmp_path / "state"
    state.mkdir()
    stop = threading.Event()
    with pytest.raises(NotImplementedError, match="CreateNamedPipeW"):
        serve(state, stop)


def test_policyd_serve_uses_named_pipe_listener_on_windows(tmp_path, windows_platform, monkeypatch):
    """ADR-010: policyd on Windows serves through NamedPipeListener
    instead of refusing. The listener is stubbed (no Win32 on this
    host) to capture how serve() wires it; the captured handler is
    then exercised with the real auth token serve() just created.
    """
    state = tmp_path / "state"
    state.mkdir()
    captured = {}

    class CapturingListener:
        def __init__(self, pipe_path, api=None):
            captured["pipe_path"] = pipe_path

        def listen(self, handler=None, stop=None):
            captured["handler"] = handler
            captured["stop"] = stop

    monkeypatch.setattr("policy.policyd.NamedPipeListener",
                        CapturingListener)
    stop = threading.Event()
    serve(state, stop)
    assert captured["pipe_path"] == POLICYD_PIPE_PATH
    assert callable(captured["handler"])
    assert captured["stop"] is stop
    auth = (state / "policyd.auth").read_text(encoding="utf-8").strip()
    reply = captured["handler"]({"op": "status", "auth": auth})
    assert reply["ok"] is True
    assert reply["socket"] == POLICYD_PIPE_PATH


def test_daemon_serve_forever_refuses_without_win32_api_on_windows(tmp_path, windows_platform, monkeypatch):
    """Fail closed: the daemon on Windows refuses to start when the
    Win32 API is unavailable — no ACL-less pipe is ever served.
    The refusal is about the missing API, not about Windows as
    such (see the _uses_named_pipe_listener test below).
    BUG-J: ``ctypes.windll`` is deleted explicitly so the missing
    API is really simulated — on real Windows it exists, and
    without the deletion serve_forever() would really start
    listening and hang waiting for a client."""
    monkeypatch.delattr(ctypes, "windll", raising=False)
    state = tmp_path / "state"
    state.mkdir()
    daemon = Daemon(state)
    with pytest.raises(NotImplementedError, match="CreateNamedPipeW"):
        daemon.serve_forever()


def test_daemon_serve_forever_uses_named_pipe_listener_on_windows(tmp_path, windows_platform, monkeypatch):
    """ADR-010: the daemon on Windows serves through NamedPipeListener
    instead of refusing. The listener is stubbed (no Win32 on this
    host) to capture how serve_forever() wires it; the captured
    handler is then exercised with the daemon's real auth token.
    """
    state = tmp_path / "state"
    state.mkdir()
    captured = {}

    class CapturingListener:
        def __init__(self, pipe_path, api=None):
            captured["pipe_path"] = pipe_path

        def listen(self, handler=None, stop=None):
            captured["handler"] = handler
            captured["stop"] = stop

    monkeypatch.setattr("core.daemon.NamedPipeListener",
                        CapturingListener)
    daemon = Daemon(state)
    daemon.serve_forever()
    assert captured["pipe_path"] == DAEMON_PIPE_PATH
    assert captured["handler"] == daemon.handle_request
    assert captured["stop"] is daemon._stop
    reply = captured["handler"]({"op": "status", "auth": daemon.auth_token})
    assert reply["ok"] is True
    assert reply["policyd_reachable"] is False


def test_daemon_remove_stale_socket_noop_on_windows(tmp_path,
                                                    windows_platform):
    state = tmp_path / "state"
    state.mkdir()
    stale = state / "daemon.sock"
    stale.write_text("stale", encoding="utf-8")
    daemon = Daemon(state)
    daemon._remove_stale_socket()
    assert stale.exists(), "no socket file exists on Windows to remove"


def test_daemon_policyd_reachable_ignores_pipe_address(tmp_path):
    """A client with no socket file but a pipe address is reachable iff
    its status() call answers — the pipe path must never be probed
    with Path.exists() (it is not a file)."""
    state = tmp_path / "state"
    state.mkdir()
    daemon = Daemon(state)

    pipe_client = types.SimpleNamespace(
        sock_path=None, pipe_path=POLICYD_PIPE_PATH,
        status=lambda: {"killed": False})
    daemon._policy_client_obj = pipe_client
    daemon._policy_client_tried = True
    assert daemon._policyd_reachable() is True

    missing_client = types.SimpleNamespace(
        sock_path=state / "policyd.sock",
        status=lambda: {"killed": False})
    daemon._policy_client_obj = missing_client
    assert daemon._policyd_reachable() is False


def test_handle_request_status_reports_pipe_on_windows(tmp_path,
                                                      windows_platform):
    state = tmp_path / "state"
    state.mkdir()
    engine = PolicyEngine(state)
    reply = handle_request(engine, "tok", {"op": "status", "auth": "tok"})
    assert reply["ok"] is True
    assert reply["socket"] == POLICYD_PIPE_PATH


@pytest.mark.skipif(sys.platform == "win32", reason=(
    "Unix-only: asserts a Unix socket path in status output; on "
    "Windows status reports the pipe path (see "
    "test_handle_request_status_reports_pipe_on_windows)"))
def test_handle_request_status_reports_socket_on_linux(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    engine = PolicyEngine(state)
    reply = handle_request(engine, "tok", {"op": "status", "auth": "tok"})
    assert reply["ok"] is True
    assert reply["socket"] == str(state / "policyd.sock")
