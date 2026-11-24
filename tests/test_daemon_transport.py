"""Tests for the daemon transport: POSIX Unix socket vs Windows named pipe.

``core.daemon.query_daemon`` / ``daemon_reachable`` pick the live
transport (Unix socket on POSIX, named pipe on Windows); the CLI
daemon commands, doctor and the web UI share them. POSIX tests use a
real AF_UNIX server thread; Windows tests fake the platform
(``platform.system -> "Windows"`` in core.daemon, ``sys.platform ->
"win32"`` in the CLI) and inject a fake pipe — the real pipe is
proven on the laptop, not here.
"""

import io
import json
import os
import socket
import subprocess
import sys
import threading
import types
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI = [sys.executable, "-m", "cli.opencobot_cli"]

sys.path.insert(0, str(REPO_ROOT))

import core.daemon as daemon_mod  # noqa: E402
import core.transport as transport_mod  # noqa: E402
from core.transport import (  # noqa: E402
    DAEMON_PIPE_PATH,
    TransportNotAvailableError,
)
from tests._procutil import kill_pid_file, reap_pid_file  # noqa: E402


@pytest.fixture()
def state_dir(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    yield state
    # Teardown: stop anything this test started (daemon).
    for pid_file in ("policyd.pid", "daemon.pid"):
        kill_pid_file(state, pid_file)
    for pid_file in ("policyd.pid", "daemon.pid"):
        reap_pid_file(state, pid_file, timeout=2.0)


def run_cli(state_dir, *args, timeout=60):
    return subprocess.run(
        CLI + ["--state-dir", str(state_dir), *args],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=timeout)


def run_cli_json(state_dir, *args, timeout=60):
    proc = run_cli(state_dir, *args, timeout=timeout)
    return proc, json.loads(proc.stdout)


def _ns(state_dir, as_json=True):
    return types.SimpleNamespace(state_dir=str(state_dir), json=as_json)


# ---------------------------------------------------------------------------
# Fakes
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


class _UnixDaemonServer:
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
    """Pretend this host is Windows for core.daemon's transport pick."""
    monkeypatch.setattr(daemon_mod, "is_windows", lambda: True)
    if transport is not None:
        monkeypatch.setattr(daemon_mod, "NamedPipeTransport",
                            lambda path: transport)


# ---------------------------------------------------------------------------
# daemon_reachable
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform == "win32",
                    reason="POSIX AF_UNIX live socket server; Windows tested via Named Pipe")
def test_daemon_reachable_posix_live_server(state_dir):
    with _UnixDaemonServer(state_dir / "daemon.sock"):
        assert daemon_mod.daemon_reachable(state_dir) is True


def test_daemon_reachable_posix_no_server(state_dir):
    assert daemon_mod.daemon_reachable(state_dir) is False


def test_daemon_reachable_posix_stale_socket_file(state_dir):
    # A regular file where the socket will go is not a live daemon:
    # the old bare .exists() check would have lied about this.
    (state_dir / "daemon.sock").write_text("stale", encoding="utf-8")
    assert daemon_mod.daemon_reachable(state_dir) is False


def test_daemon_reachable_windows_pipe_answers(state_dir, monkeypatch):
    _patch_windows(monkeypatch,
                   _FakePipeTransport(pipe=_FakePipe(b"")))
    assert daemon_mod.daemon_reachable(state_dir) is True


def test_daemon_reachable_windows_pipe_absent(state_dir, monkeypatch):
    _patch_windows(monkeypatch, _FakePipeTransport(
        exc=TransportNotAvailableError("cannot connect to named pipe")))
    assert daemon_mod.daemon_reachable(state_dir) is False


# ---------------------------------------------------------------------------
# query_daemon
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform == "win32",
                    reason="POSIX AF_UNIX live socket server; Windows tested via Named Pipe")
def test_query_daemon_posix_returns_reply(state_dir):
    (state_dir / "daemon.auth").write_text("tok-123", encoding="utf-8")
    reply = b'{"ok": true, "tools": 3}\n'
    with _UnixDaemonServer(state_dir / "daemon.sock", reply) as srv:
        assert daemon_mod.query_daemon(state_dir, "status") == {
            "ok": True, "tools": 3}
    request = json.loads(srv.received[0].decode("utf-8"))
    assert request["op"] == "status"
    assert request["auth"] == "tok-123"


def test_query_daemon_posix_no_socket(state_dir):
    assert daemon_mod.query_daemon(state_dir, "status") is None


@pytest.mark.skipif(sys.platform == "win32",
                    reason="POSIX AF_UNIX live socket server; Windows tested via Named Pipe")
def test_query_daemon_posix_invalid_reply(state_dir):
    with _UnixDaemonServer(state_dir / "daemon.sock", b"not json\n"):
        assert daemon_mod.query_daemon(state_dir, "status") is None


def test_query_daemon_windows_uses_pipe(state_dir, monkeypatch):
    (state_dir / "daemon.auth").write_text("tok-abc", encoding="utf-8")
    pipe = _FakePipe(b'{"ok": true, "tools": 5}\n')
    _patch_windows(monkeypatch, _FakePipeTransport(pipe=pipe))
    assert daemon_mod.query_daemon(state_dir, "status") == {
        "ok": True, "tools": 5}
    request = json.loads(pipe.written.decode("utf-8"))
    assert request["op"] == "status"
    assert request["auth"] == "tok-abc"
    assert pipe.closed is True


def test_query_daemon_windows_pipe_absent(state_dir, monkeypatch):
    _patch_windows(monkeypatch, _FakePipeTransport(
        exc=TransportNotAvailableError("cannot connect to named pipe")))
    assert daemon_mod.query_daemon(state_dir, "status") is None


def test_query_daemon_windows_closed_connection(state_dir, monkeypatch):
    _patch_windows(monkeypatch, _FakePipeTransport(pipe=_FakePipe(b"")))
    assert daemon_mod.query_daemon(state_dir, "status") is None

# ---------------------------------------------------------------------------
# CLI daemon commands — Windows branches (mocked; real pipe on the laptop)
# ---------------------------------------------------------------------------

class _FakeProc:
    def __init__(self, pid=4321, returncode=None):
        self.pid = pid
        self._returncode = returncode

    def poll(self):
        return self._returncode


def _patch_cli_windows(monkeypatch):
    """Pretend the CLI runs on Windows (sys.platform drives its branches)."""
    monkeypatch.setattr(sys, "platform", "win32")


def test_cmd_daemon_start_windows_reports_pipe(state_dir, monkeypatch, capsys):
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    monkeypatch.setattr(cli_mod, "_daemon_reachable", lambda state: True)
    monkeypatch.setattr(cli_mod.subprocess, "Popen",
                        lambda *a, **k: _FakeProc(pid=4321))
    rc = cli_mod.cmd_daemon_start(_ns(state_dir))
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["running"] is True
    assert payload["pid"] == 4321
    assert payload["pipe"] == DAEMON_PIPE_PATH
    assert "socket" not in payload


def test_cmd_daemon_start_windows_second_probe_fails_still_succeeds(
        state_dir, monkeypatch, capsys):
    # Laptop round (PR #16): with max_instances=1 the pipe listener
    # needs a beat between disconnect and the next ConnectNamedPipe,
    # so an immediate second probe right after a successful one can
    # fail with ERROR_PIPE_BUSY. Start must trust the first answer
    # instead of re-probing and reporting a false timeout (which also
    # unlinked daemon.pid and orphaned the live daemon).
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    answers = iter([True, False])
    monkeypatch.setattr(cli_mod, "_daemon_reachable",
                        lambda state: next(answers))
    monkeypatch.setattr(cli_mod.subprocess, "Popen",
                        lambda *a, **k: _FakeProc(pid=4321))
    rc = cli_mod.cmd_daemon_start(_ns(state_dir))
    assert rc == 0
    assert (state_dir / "daemon.pid").read_text(encoding="utf-8") == "4321"
    payload = json.loads(capsys.readouterr().out)
    assert payload["running"] is True
    assert payload["pid"] == 4321


def test_cmd_daemon_start_windows_daemon_dies(state_dir, monkeypatch, capsys):
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    monkeypatch.setattr(cli_mod, "_daemon_reachable", lambda state: False)
    monkeypatch.setattr(cli_mod.subprocess, "Popen",
                        lambda *a, **k: _FakeProc(pid=4321, returncode=1))
    rc = cli_mod.cmd_daemon_start(_ns(state_dir))
    assert rc == 1
    assert "exited immediately" in capsys.readouterr().err


def test_cmd_daemon_start_windows_never_ready(state_dir, monkeypatch, capsys):
    # The daemon stays alive but never answers within the 5s deadline:
    # start must fail honestly instead of claiming success.
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    monkeypatch.setattr(cli_mod, "_daemon_reachable", lambda state: False)
    monkeypatch.setattr(cli_mod.subprocess, "Popen",
                        lambda *a, **k: _FakeProc(pid=4321))
    rc = cli_mod.cmd_daemon_start(_ns(state_dir))
    assert rc == 1
    assert "did not become ready" in capsys.readouterr().err


def test_cmd_daemon_status_windows_pipe(state_dir, monkeypatch, capsys):
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    monkeypatch.setattr(cli_mod, "_daemon_reachable", lambda state: True)
    monkeypatch.setattr(cli_mod, "_query_daemon",
                        lambda state, op, timeout=3.0: {"ok": True, "tools": 2})
    rc = cli_mod.cmd_daemon_status(_ns(state_dir))
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["running"] is True
    assert payload["pipe"] == DAEMON_PIPE_PATH
    assert payload["status"] == {"ok": True, "tools": 2}
    assert "socket" not in payload


def test_cmd_daemon_status_windows_not_running(state_dir, monkeypatch, capsys):
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    monkeypatch.setattr(cli_mod, "_daemon_reachable", lambda state: False)
    rc = cli_mod.cmd_daemon_status(_ns(state_dir))
    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["running"] is False
    assert payload["pipe"] is None
    assert payload["status"] is None


def test_cmd_daemon_status_windows_pid_alive_but_silent(state_dir, monkeypatch, capsys):
    # A live PID with no answering pipe still counts as running (the
    # process is there), but there is no status payload and no note
    # claiming the pipe is reachable.
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    # A live PID that is NOT the test runner's own: the state_dir
    # fixture's teardown kills whatever daemon.pid names, so writing
    # os.getpid() here would SIGTERM pytest itself.
    # No "sleep" executable exists on Windows; use the interpreter.
    sleeper = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"])
    (state_dir / "daemon.pid").write_text(str(sleeper.pid),
                                          encoding="utf-8")
    monkeypatch.setattr(cli_mod, "_daemon_reachable", lambda state: False)
    rc = cli_mod.cmd_daemon_status(_ns(state_dir))
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["running"] is True
    assert payload["status"] is None


def test_cmd_daemon_stop_windows_no_pid_reachable(state_dir, monkeypatch, capsys):
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    monkeypatch.setattr(cli_mod, "_daemon_reachable", lambda state: True)
    killed = []
    monkeypatch.setattr(cli_mod, "_terminate_pid", lambda pid: killed.append(pid))
    rc = cli_mod.cmd_daemon_stop(_ns(state_dir))
    assert rc == 1
    captured = capsys.readouterr()  # one read: readouterr() drains
    assert "no PID file" in captured.err
    assert "named pipe" in captured.err
    assert killed == []  # refusing to guess means refusing to kill


def test_cmd_daemon_stop_windows_no_pid_not_running(state_dir, monkeypatch, capsys):
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    monkeypatch.setattr(cli_mod, "_daemon_reachable", lambda state: False)
    rc = cli_mod.cmd_daemon_stop(_ns(state_dir))
    assert rc == 1
    # JSON mode emits the payload, not the human message.
    assert json.loads(capsys.readouterr().out)["running"] is False


# ---------------------------------------------------------------------------
# CLI daemon commands — POSIX round-trip through the real daemon
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform == "win32",
                    reason="spawns the real daemon; Windows path covered "
                           "by the mocked tests above + the laptop run")
def test_cli_daemon_start_status_stop_roundtrip(state_dir):
    proc, payload = run_cli_json(state_dir, "daemon", "start", "--json")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert payload["running"] is True
    assert payload["pid"] > 0
    assert payload["socket"] == str(state_dir / "daemon.sock")

    proc, payload = run_cli_json(state_dir, "daemon", "status", "--json")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert payload["running"] is True
    assert payload["status"]["ok"] is True

    proc, payload = run_cli_json(state_dir, "daemon", "stop", "--json")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert payload["running"] is False

    proc = run_cli(state_dir, "daemon", "status")
    assert proc.returncode != 0
    assert "not running" in proc.stdout.lower()


# ---------------------------------------------------------------------------
# Second-instance refusal (E) + pipe instance cap
# ---------------------------------------------------------------------------

def test_serve_forever_windows_refuses_second_instance(state_dir, monkeypatch):
    from core.daemon import Daemon

    _patch_windows(monkeypatch,
                   _FakePipeTransport(pipe=_FakePipe(b"")))
    listened = []
    monkeypatch.setattr(daemon_mod, "NamedPipeListener",
                        lambda path: _FakeListener(listened))
    daemon = Daemon(state_dir)
    with pytest.raises(RuntimeError, match="already running"):
        daemon.serve_forever()
    assert listened == []  # the listener must never start


def test_serve_forever_windows_starts_when_pipe_absent(state_dir, monkeypatch):
    from core.daemon import Daemon

    _patch_windows(monkeypatch, _FakePipeTransport(
        exc=TransportNotAvailableError("cannot connect to named pipe")))
    listened = []
    monkeypatch.setattr(daemon_mod, "NamedPipeListener",
                        lambda path: _FakeListener(listened))
    Daemon(state_dir).serve_forever()
    assert listened == [DAEMON_PIPE_PATH]


class _FakeListener:
    def __init__(self, listened):
        self._listened = listened

    def listen(self, handler=None, stop=None):
        self._listened.append(DAEMON_PIPE_PATH)


def test_pipe_max_instances_is_one():
    # Atomic backstop for second-instance refusal: a second daemon's
    # CreateNamedPipeW fails (ERROR_PIPE_BUSY) instead of serving a
    # second pipe instance alongside the first.
    assert transport_mod._CtypesWindowsPipeApi._PIPE_MAX_INSTANCES == 1


# ---------------------------------------------------------------------------
# Web UI indicator (D)
# ---------------------------------------------------------------------------

def test_webui_status_daemon_running_false(state_dir):
    from ui.web import WebUIBackend

    assert WebUIBackend(state_dir).status()["daemon_running"] is False


@pytest.mark.skipif(sys.platform == "win32",
                    reason="POSIX AF_UNIX live socket server; Windows tested via Named Pipe")
def test_webui_status_daemon_running_live_socket(state_dir):
    from ui.web import WebUIBackend

    with _UnixDaemonServer(state_dir / "daemon.sock"):
        assert WebUIBackend(state_dir).status()["daemon_running"] is True


def test_webui_status_daemon_running_stale_socket_file(state_dir):
    # A regular file where the socket will go is not a live daemon;
    # the old .exists() check would have reported True here.
    from ui.web import WebUIBackend

    (state_dir / "daemon.sock").write_text("stale", encoding="utf-8")
    assert WebUIBackend(state_dir).status()["daemon_running"] is False


# ---------------------------------------------------------------------------
# Doctor daemon check (F)
# ---------------------------------------------------------------------------

def _doctor_checks(state_dir, monkeypatch, windows):
    import cli.opencobot_cli as cli_mod

    monkeypatch.setattr(cli_mod, "ensure_policyd",
                        lambda state: ("running", None))
    if windows:
        _patch_cli_windows(monkeypatch)
        monkeypatch.setattr(cli_mod, "_daemon_reachable", lambda state: True)
        monkeypatch.setattr(cli_mod, "_query_daemon",
                            lambda state, op, timeout=3.0: {"ok": True})
    import io as _io
    import contextlib as _ctx

    buf = _io.StringIO()
    with _ctx.redirect_stdout(buf):
        rc = cli_mod.cmd_doctor(_ns(state_dir))
    return rc, json.loads(buf.getvalue())["checks"]


def test_doctor_daemon_check_windows_reports_pipe(state_dir, monkeypatch):
    rc, checks = _doctor_checks(state_dir, monkeypatch, windows=True)
    assert rc == 0
    by_name = {c["name"]: c for c in checks}
    assert by_name["daemon"]["status"] == "PASS"
    assert "named pipe" in by_name["daemon"]["detail"]
    assert by_name["daemon.sock perms"]["status"] == "INFO"
    assert "named pipe" in by_name["daemon.sock perms"]["detail"]
    assert by_name["policyd.sock perms"]["status"] == "INFO"
    assert "named pipe" in by_name["policyd.sock perms"]["detail"]


@pytest.mark.skipif(sys.platform == "win32",
                    reason="POSIX AF_UNIX live socket server; Windows tested via Named Pipe")
def test_doctor_daemon_check_posix_live_socket(state_dir, monkeypatch):
    with _UnixDaemonServer(state_dir / "daemon.sock"):
        rc, checks = _doctor_checks(state_dir, monkeypatch, windows=False)
    assert rc == 0
    by_name = {c["name"]: c for c in checks}
    assert by_name["daemon"]["status"] == "PASS"
    assert "socket" in by_name["daemon"]["detail"]


def test_doctor_daemon_check_posix_not_running(state_dir, monkeypatch):
    rc, checks = _doctor_checks(state_dir, monkeypatch, windows=False)
    assert rc == 0
    by_name = {c["name"]: c for c in checks}
    assert by_name["daemon"]["status"] == "INFO"
    assert by_name["daemon"]["detail"] == "not running"
