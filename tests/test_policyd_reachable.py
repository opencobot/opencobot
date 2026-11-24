"""Tests for the policyd reachability indicator: POSIX Unix socket vs Windows named pipe.

``policy.client.policyd_reachable`` is the mirror of
``core.daemon.daemon_reachable`` for policyd: a bare connect on the live
transport (Unix socket on POSIX, named pipe on Windows), no auth, never
raises. The web UI status (``policyd_socket`` key) and the POSIX branch
of ``cli._compat._policyd_ready`` share it — a stale ``policyd.sock``
file with no listener behind it must report False, and on Windows the
indicator must work at all (there is never a socket file there).
POSIX tests use a real AF_UNIX server thread; Windows tests fake the
platform and inject a fake pipe — the real pipe is proven on the
laptop, not here.
"""

import io
import socket
import sys
import threading
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(REPO_ROOT))

import policy.client as client_mod  # noqa: E402
from core.transport import TransportNotAvailableError  # noqa: E402


@pytest.fixture()
def state_dir(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    yield state


# ---------------------------------------------------------------------------
# Fakes (same shape as tests/test_daemon_transport.py)
# ---------------------------------------------------------------------------

class _FakePipe:
    """In-memory stand-in for a named-pipe connection (client side)."""

    def __init__(self, reply_bytes=b""):
        self._read = io.BytesIO(reply_bytes)
        self.written = b""
        self.closed = False

    def write(self, data):
        self.written += data
        return len(data)

    def flush(self):
        pass

    def readline(self):
        return self._read.readline()

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


class _FakePipeTransport:
    """NamedPipeTransport stand-in: returns a fake pipe or raises."""

    def __init__(self, pipe=None, exc=None):
        self._pipe = pipe
        self._exc = exc

    def connect(self):
        if self._exc is not None:
            raise self._exc
        return self._pipe


class _UnixPolicydServer:
    """Minimal AF_UNIX server thread: replies with ``reply`` per connection."""

    def __init__(self, sock_path, reply=b'{"ok": true}\n'):
        self.sock_path = Path(sock_path)
        self.reply = reply
        self.received = []
        self._stop = threading.Event()
        self._srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._srv.bind(str(self.sock_path))
        self._srv.listen(5)
        self._srv.settimeout(0.1)
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join(timeout=2)
        self._srv.close()
        return False

    def _loop(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                conn.settimeout(2)
                try:
                    data = b""
                    while b"\n" not in data:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    if data:
                        self.received.append(data)
                        conn.sendall(self.reply)
                except OSError:
                    pass


def _patch_windows(monkeypatch, transport=None):
    """Pretend this host is Windows for policy.client's transport pick."""
    monkeypatch.setattr(client_mod, "is_windows", lambda: True)
    if transport is not None:
        monkeypatch.setattr(client_mod, "NamedPipeTransport",
                            lambda path: transport)


# ---------------------------------------------------------------------------
# policyd_reachable
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform == "win32",
                    reason="POSIX AF_UNIX live socket server; Windows tested via Named Pipe")
def test_policyd_reachable_posix_live_server(state_dir):
    with _UnixPolicydServer(state_dir / "policyd.sock"):
        assert client_mod.policyd_reachable(state_dir) is True


def test_policyd_reachable_posix_no_server(state_dir):
    # No server and no policyd.auth file: the bare probe needs no auth
    # and must return False, not raise.
    assert client_mod.policyd_reachable(state_dir) is False


def test_policyd_reachable_posix_stale_socket_file(state_dir):
    # A regular file where the socket will go is not a live policyd:
    # the old bare .exists() check would have lied about this.
    (state_dir / "policyd.sock").write_text("stale", encoding="utf-8")
    assert client_mod.policyd_reachable(state_dir) is False


def test_policyd_reachable_windows_pipe_answers(state_dir, monkeypatch):
    _patch_windows(monkeypatch,
                   _FakePipeTransport(pipe=_FakePipe(b"")))
    assert client_mod.policyd_reachable(state_dir) is True


def test_policyd_reachable_windows_pipe_absent(state_dir, monkeypatch):
    _patch_windows(monkeypatch, _FakePipeTransport(
        exc=TransportNotAvailableError("cannot connect to named pipe")))
    assert client_mod.policyd_reachable(state_dir) is False


# ---------------------------------------------------------------------------
# Web UI status — "policyd_socket" key (value is now reachability)
# ---------------------------------------------------------------------------

def test_webui_status_policyd_socket_false(state_dir):
    from ui.web import WebUIBackend

    assert WebUIBackend(state_dir).status()["policyd_socket"] is False


@pytest.mark.skipif(sys.platform == "win32",
                    reason="POSIX AF_UNIX live socket server; Windows tested via Named Pipe")
def test_webui_status_policyd_socket_live_server(state_dir):
    from ui.web import WebUIBackend

    with _UnixPolicydServer(state_dir / "policyd.sock"):
        assert WebUIBackend(state_dir).status()["policyd_socket"] is True


def test_webui_status_policyd_socket_stale_file(state_dir):
    from ui.web import WebUIBackend

    (state_dir / "policyd.sock").write_text("stale", encoding="utf-8")
    assert WebUIBackend(state_dir).status()["policyd_socket"] is False


def test_webui_status_policyd_socket_windows_pipe(state_dir, monkeypatch):
    from ui.web import WebUIBackend

    _patch_windows(monkeypatch,
                   _FakePipeTransport(pipe=_FakePipe(b"")))
    assert WebUIBackend(state_dir).status()["policyd_socket"] is True


# ---------------------------------------------------------------------------
# cli._compat._policyd_ready — POSIX branch (ensure_policyd gate)
# ---------------------------------------------------------------------------

def test_policyd_ready_posix_stale_socket_file(state_dir):
    # A stale policyd.sock used to make ensure_policyd skip spawning a
    # policyd that was not there. The probe must say "not ready".
    from cli._compat import _policyd_ready

    (state_dir / "policyd.sock").write_text("stale", encoding="utf-8")
    assert _policyd_ready(state_dir) is False


@pytest.mark.skipif(sys.platform == "win32",
                    reason="POSIX AF_UNIX live socket server; Windows tested via Named Pipe")
def test_policyd_ready_posix_live_server(state_dir):
    from cli._compat import _policyd_ready

    with _UnixPolicydServer(state_dir / "policyd.sock"):
        assert _policyd_ready(state_dir) is True
