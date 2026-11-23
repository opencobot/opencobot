"""Tests for the policyd/daemon transport abstraction (Slice B).

Unix socket (AF_UNIX, unchanged on Linux) vs Windows named pipe
(``\\\\.\\pipe\\opencobot-policyd`` / ``\\\\.\\pipe\\opencobot-daemon``).
The JSON-lines protocol must be byte-identical over both transports;
the named-pipe client raises clearly on Linux and works against a
fake pipe; the server side refuses to listen on Windows until the
``ctypes`` listener with a current-user-only ACL lands.
"""

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


def test_named_pipe_listener_raises_on_linux():
    with pytest.raises(TransportNotAvailableError,
                       match="not available on this platform"):
        NamedPipeListener(POLICYD_PIPE_PATH).listen()


def test_named_pipe_listener_fails_closed_on_windows(windows_platform):
    with pytest.raises(NotImplementedError, match="CreateNamedPipeW"):
        NamedPipeListener(POLICYD_PIPE_PATH).listen()
    with pytest.raises(NotImplementedError, match="ACL"):
        NamedPipeListener(DAEMON_PIPE_PATH).listen()


# ---------------------------------------------------------------------------
# Server side: listener selection by platform (mocked)
# ---------------------------------------------------------------------------

def test_policyd_serve_refuses_on_windows(tmp_path, windows_platform):
    state = tmp_path / "state"
    state.mkdir()
    stop = threading.Event()
    with pytest.raises(NotImplementedError, match="CreateNamedPipeW"):
        serve(state, stop)


def test_daemon_serve_forever_refuses_on_windows(tmp_path, windows_platform):
    state = tmp_path / "state"
    state.mkdir()
    daemon = Daemon(state)
    with pytest.raises(NotImplementedError, match="CreateNamedPipeW"):
        daemon.serve_forever()


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


def test_handle_request_status_reports_socket_on_linux(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    engine = PolicyEngine(state)
    reply = handle_request(engine, "tok", {"op": "status", "auth": "tok"})
    assert reply["ok"] is True
    assert reply["socket"] == str(state / "policyd.sock")
