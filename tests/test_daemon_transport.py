"""Tests for the daemon transport: POSIX Unix socket vs Windows named pipe.

``core.daemon.query_daemon`` / ``daemon_reachable`` pick the live
transport (Unix socket on POSIX, named pipe on Windows); the CLI
daemon commands, doctor and the web UI share them. POSIX tests use a
real AF_UNIX server thread; Windows tests fake the platform
(``platform.system -> "Windows"`` in core.daemon, ``sys.platform ->
"win32"`` in the CLI) and inject a fake pipe — the real pipe is
proven on the laptop, not here.
"""

import ctypes
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


def _probe_must_not_run(state):
    """Fail if the old probe-then-query path is ever taken again.

    ``cmd_daemon_status`` queries the daemon directly: the probe's
    accept left no listening pipe instance for the microseconds until
    the next one was created, so the immediate query failed on a live
    daemon. A probe call here means the race is back.
    """
    raise AssertionError(
        "cmd_daemon_status must query directly without a prior probe")


def _ensure_policyd_must_not_run(state_dir):
    """Fail if ``ensure_policyd`` is called before the daemon is up.

    ``cmd_daemon_start`` ensures policyd only after the daemon is
    confirmed ready; a call here means it ran on a path where the
    daemon never became ready (or never started).
    """
    raise AssertionError(
        "ensure_policyd must not run before the daemon is confirmed up")


def test_cmd_daemon_start_windows_reports_pipe(state_dir, monkeypatch, capsys):
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    monkeypatch.setattr(cli_mod, "_daemon_reachable", lambda state: True)
    monkeypatch.setattr(cli_mod, "ensure_policyd",
                        lambda state: ("running", None))
    monkeypatch.setattr(cli_mod.subprocess, "Popen",
                        lambda *a, **k: _FakeProc(pid=4321))
    rc = cli_mod.cmd_daemon_start(_ns(state_dir))
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["running"] is True
    assert payload["pid"] == 4321
    assert payload["policyd"] == "running"
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
    monkeypatch.setattr(cli_mod, "ensure_policyd",
                        lambda state: ("running", None))
    monkeypatch.setattr(cli_mod.subprocess, "Popen",
                        lambda *a, **k: _FakeProc(pid=4321))
    rc = cli_mod.cmd_daemon_start(_ns(state_dir))
    assert rc == 0
    assert (state_dir / "daemon.pid").read_text(encoding="utf-8") == "4321"
    payload = json.loads(capsys.readouterr().out)
    assert payload["running"] is True
    assert payload["pid"] == 4321
    assert payload["policyd"] == "running"


def test_cmd_daemon_start_windows_daemon_dies(state_dir, monkeypatch, capsys):
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    monkeypatch.setattr(cli_mod, "_daemon_reachable", lambda state: False)
    monkeypatch.setattr(cli_mod, "ensure_policyd", _ensure_policyd_must_not_run)
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
    monkeypatch.setattr(cli_mod, "ensure_policyd", _ensure_policyd_must_not_run)
    monkeypatch.setattr(cli_mod.subprocess, "Popen",
                        lambda *a, **k: _FakeProc(pid=4321))
    rc = cli_mod.cmd_daemon_start(_ns(state_dir))
    assert rc == 1
    assert "did not become ready" in capsys.readouterr().err


def test_cmd_daemon_start_windows_starts_policyd(state_dir, monkeypatch, capsys):
    # Starting the daemon also makes sure policyd is up: the daemon
    # gates every privileged op on policyd being reachable, and a
    # fresh `daemon start` used to leave it down, so the VS Code
    # extension's runTask was always refused with "policyd
    # unavailable". ensure_policyd runs once, after the daemon is
    # confirmed ready, with the state dir.
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    monkeypatch.setattr(cli_mod, "_daemon_reachable", lambda state: True)
    calls = []
    def _ensure(state):
        calls.append(state)
        return ("running", _FakeProc(pid=7777))
    monkeypatch.setattr(cli_mod, "ensure_policyd", _ensure)
    monkeypatch.setattr(cli_mod.subprocess, "Popen",
                        lambda *a, **k: _FakeProc(pid=4321))
    rc = cli_mod.cmd_daemon_start(_ns(state_dir))
    assert rc == 0
    assert calls == [state_dir]
    payload = json.loads(capsys.readouterr().out)
    assert payload["running"] is True
    assert payload["pid"] == 4321
    assert payload["policyd"] == "running"


def test_cmd_daemon_start_windows_policyd_already_running(
        state_dir, monkeypatch, capsys):
    # ("running", None) is ensure_policyd's already-running return
    # (its own no-op is covered by
    # test_windows_already_running_does_not_spawn in
    # test_ensure_policyd.py): start still succeeds and reports
    # policyd running.
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    monkeypatch.setattr(cli_mod, "_daemon_reachable", lambda state: True)
    monkeypatch.setattr(cli_mod, "ensure_policyd",
                        lambda state: ("running", None))
    monkeypatch.setattr(cli_mod.subprocess, "Popen",
                        lambda *a, **k: _FakeProc(pid=4321))
    rc = cli_mod.cmd_daemon_start(_ns(state_dir))
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["running"] is True
    assert payload["policyd"] == "running"


def test_cmd_daemon_start_windows_policyd_failure_warns_but_starts(
        state_dir, monkeypatch, capsys):
    # A policyd that fails to start must NOT fail the daemon start:
    # the daemon itself is up and serves status / list_tools, so the
    # start reports success with policyd "failed" and exit code 0.
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    monkeypatch.setattr(cli_mod, "_daemon_reachable", lambda state: True)
    monkeypatch.setattr(cli_mod, "ensure_policyd",
                        lambda state: ("failed", None))
    monkeypatch.setattr(cli_mod.subprocess, "Popen",
                        lambda *a, **k: _FakeProc(pid=4321))
    rc = cli_mod.cmd_daemon_start(_ns(state_dir))
    assert rc == 0
    assert (state_dir / "daemon.pid").read_text(encoding="utf-8") == "4321"
    payload = json.loads(capsys.readouterr().out)
    assert payload["running"] is True
    assert payload["pid"] == 4321
    assert payload["policyd"] == "failed"


def test_cmd_daemon_start_windows_policyd_failure_warning_line(
        state_dir, monkeypatch, capsys):
    # In human (non-JSON) mode the policyd failure is a visible
    # warning line next to the "daemon started" line.
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    monkeypatch.setattr(cli_mod, "_daemon_reachable", lambda state: True)
    monkeypatch.setattr(cli_mod, "ensure_policyd",
                        lambda state: ("failed", None))
    monkeypatch.setattr(cli_mod.subprocess, "Popen",
                        lambda *a, **k: _FakeProc(pid=4321))
    rc = cli_mod.cmd_daemon_start(_ns(state_dir, as_json=False))
    assert rc == 0
    out = capsys.readouterr().out
    assert "daemon started (pid 4321" in out
    assert "warning: policyd did not start (see " in out
    assert "policyd.log" in out
    assert "tool runs will be refused" in out


def test_cmd_daemon_start_windows_policyd_module_missing_warns_but_starts(
        state_dir, monkeypatch, capsys):
    # ensure_policyd raises PolicyUnavailable when the real policyd
    # module is not installed; that is a policyd failure too, so the
    # start still succeeds with policyd "failed".
    import cli.opencobot_cli as cli_mod
    from cli._compat import PolicyUnavailable

    _patch_cli_windows(monkeypatch)
    monkeypatch.setattr(cli_mod, "_daemon_reachable", lambda state: True)
    def _ensure_missing(state):
        raise PolicyUnavailable(
            "real policyd module (policy.policyd) is not installed; "
            "reinstall OpenCobot")
    monkeypatch.setattr(cli_mod, "ensure_policyd", _ensure_missing)
    monkeypatch.setattr(cli_mod.subprocess, "Popen",
                        lambda *a, **k: _FakeProc(pid=4321))
    rc = cli_mod.cmd_daemon_start(_ns(state_dir))
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["running"] is True
    assert payload["policyd"] == "failed"


def test_cmd_daemon_start_windows_already_running_daemon_does_not_ensure_policyd(
        state_dir, monkeypatch, capsys):
    # Deliberate scope boundary: when the daemon is already running,
    # `daemon start` returns immediately without ensuring policyd —
    # only a fresh start does. (If policyd died while the daemon kept
    # running, `doctor` or a tool run starts it; a follow-up could
    # ensure it here too.)
    import cli.opencobot_cli as cli_mod
    import subprocess

    _patch_cli_windows(monkeypatch)
    monkeypatch.setattr(cli_mod, "ensure_policyd", _ensure_policyd_must_not_run)
    sleeper = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        (state_dir / "daemon.pid").write_text(str(sleeper.pid),
                                              encoding="utf-8")
        rc = cli_mod.cmd_daemon_start(_ns(state_dir))
    finally:
        sleeper.terminate()
        sleeper.wait()
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["running"] is True
    assert payload["pid"] == sleeper.pid
    assert payload["note"] == "daemon already running"


def test_cmd_daemon_status_windows_pipe(state_dir, monkeypatch, capsys):
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    monkeypatch.setattr(cli_mod, "_daemon_reachable", _probe_must_not_run)
    monkeypatch.setattr(cli_mod, "_query_daemon",
                        lambda state, op, timeout=3.0: {"ok": True, "tools": 2})
    rc = cli_mod.cmd_daemon_status(_ns(state_dir))
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["running"] is True
    assert payload["pipe"] == DAEMON_PIPE_PATH
    assert payload["status"] == {"ok": True, "tools": 2}
    assert "socket" not in payload


def test_cmd_daemon_status_windows_queries_once_without_probe(
        state_dir, monkeypatch, capsys):
    # One status call makes exactly one connection — the query itself.
    # The old probe+query sequence did two back-to-back connects, and
    # the probe's accept left the listener with no instance to offer
    # the query (see _probe_must_not_run).
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    monkeypatch.setattr(cli_mod, "_daemon_reachable", _probe_must_not_run)
    calls = []
    def _query(state, op, timeout=3.0):
        calls.append(op)
        return {"ok": True, "tools": 2}
    monkeypatch.setattr(cli_mod, "_query_daemon", _query)
    rc = cli_mod.cmd_daemon_status(_ns(state_dir))
    assert rc == 0
    assert calls == ["status"]


def test_cmd_daemon_status_windows_not_running(state_dir, monkeypatch, capsys):
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    monkeypatch.setattr(cli_mod, "_daemon_reachable", _probe_must_not_run)
    monkeypatch.setattr(cli_mod, "_query_daemon",
                        lambda state, op, timeout=3.0: None)
    rc = cli_mod.cmd_daemon_status(_ns(state_dir))
    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["running"] is False
    assert payload["pipe"] is None
    assert payload["status"] is None


def test_cmd_daemon_status_windows_pid_alive_but_silent(state_dir, monkeypatch, capsys):
    # A live PID with no answering daemon still counts as running (the
    # process is there), but there is no status payload and no note
    # claiming the pipe is reachable — without a probe the command
    # cannot tell a silent pipe from no pipe at all, so it reports
    # just the live PID.
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
    monkeypatch.setattr(cli_mod, "_daemon_reachable", _probe_must_not_run)
    monkeypatch.setattr(cli_mod, "_query_daemon",
                        lambda state, op, timeout=3.0: None)
    rc = cli_mod.cmd_daemon_status(_ns(state_dir))
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["running"] is True
    assert payload["pipe"] is None
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
# _pid_alive / _terminate_pid on Windows (stop skipped the kill)
# ---------------------------------------------------------------------------

def _fake_kernel32(exit_codes=(), open_error=0):
    """Minimal kernel32 stand-in for _pid_alive_windows tests.

    ``exit_codes`` is the sequence GetExitCodeProcess returns (one
    per call; exhausted -> 0, i.e. exited). ``open_error`` is the
    Win32 error GetLastError returns when OpenProcess returns NULL
    (0 means OpenProcess succeeds and returns a fake handle).
    The functions are plain closures (not bound methods) so the
    implementation can set restype/argtypes attributes on them.
    """
    state = {"exit_codes": list(exit_codes), "opened": [], "closed": []}

    def open_process(access, inherit, pid):
        state["opened"].append(pid)
        if open_error:
            return 0
        return 12345  # fake non-null handle

    def get_exit_code(handle, out):
        code = state["exit_codes"].pop(0) if state["exit_codes"] else 0
        ctypes.cast(out,
                    ctypes.POINTER(ctypes.c_ulong)).contents.value = code
        return True

    def close_handle(handle):
        state["closed"].append(handle)
        return True

    def get_last_error():
        return open_error

    return types.SimpleNamespace(
        OpenProcess=open_process,
        GetExitCodeProcess=get_exit_code,
        CloseHandle=close_handle,
        GetLastError=get_last_error,
        _state=state,
    )


def _patch_fake_windll(monkeypatch, kernel32):
    """Install a fake ctypes.windll (absent on Linux) for the CLI."""
    import cli.opencobot_cli as cli_mod

    monkeypatch.setattr(cli_mod.ctypes, "windll",
                        types.SimpleNamespace(kernel32=kernel32),
                        raising=False)


def test_cmd_daemon_stop_windows_kills_live_process_despite_winerror87(
        state_dir, monkeypatch, capsys):
    """The reported bug: os.kill(pid, 0) raises WinError 87 for a
    start_new_session process, so the old _pid_alive said "dead" and
    daemon stop skipped the kill while printing "daemon stopped".
    The ctypes check says alive, so the process tree is terminated."""
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)

    def fake_kill(pid, sig):
        err = OSError(87, "The parameter is incorrect")
        err.winerror = 87
        raise err

    monkeypatch.setattr(os, "kill", fake_kill)
    # First liveness probe (the stop decision): alive. Second (the
    # wait loop after taskkill): gone, so the loop exits at once.
    kernel32 = _fake_kernel32(exit_codes=[259, 0])
    _patch_fake_windll(monkeypatch, kernel32)
    calls = []
    monkeypatch.setattr(cli_mod.subprocess, "run",
                        lambda argv, **kw: calls.append(argv))
    (state_dir / "daemon.pid").write_text("380", encoding="utf-8")
    rc = cli_mod.cmd_daemon_stop(_ns(state_dir))
    assert rc == 0
    assert calls == [["taskkill", "/T", "/F", "/PID", "380"]]
    assert not (state_dir / "daemon.pid").exists()
    assert json.loads(capsys.readouterr().out)["running"] is False


# ---------------------------------------------------------------------------
# daemon stop also stops policyd (PR #66 follow-up to PR #64)
# ---------------------------------------------------------------------------

def _fake_pid_liveness(alive_pids):
    """``_pid_alive`` stand-in backed by a mutable set of live pids."""
    alive = set(alive_pids)

    def _alive(pid):
        return pid in alive

    return alive, _alive


def _fake_terminate(alive, killed, works=True):
    """``_terminate_pid`` stand-in: records the call; removes the pid
    from the live set when ``works`` (a kill that does not take effect
    leaves it there, so the re-check still sees it alive)."""
    def _terminate(pid):
        killed.append(pid)
        if works:
            alive.discard(pid)

    return _terminate


def test_cmd_daemon_stop_windows_stops_policyd(state_dir, monkeypatch, capsys):
    # Stopping the daemon also stops the policyd recorded in
    # policyd.pid (laptop re-check on 26fc845: `daemon stop` left two
    # policyd processes + a stale pid file behind). The daemon goes
    # first (it depends on policyd), then policyd, then the pid file.
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    alive, fake_alive = _fake_pid_liveness({7777})
    killed = []
    monkeypatch.setattr(cli_mod, "_pid_alive", fake_alive)
    monkeypatch.setattr(cli_mod, "_terminate_pid",
                        _fake_terminate(alive, killed))
    (state_dir / "daemon.pid").write_text("380", encoding="utf-8")
    (state_dir / "policyd.pid").write_text("7777", encoding="utf-8")
    rc = cli_mod.cmd_daemon_stop(_ns(state_dir))
    assert rc == 0
    assert killed == [7777]  # only policyd: the daemon pid was already dead
    assert not (state_dir / "daemon.pid").exists()
    assert not (state_dir / "policyd.pid").exists()
    payload = json.loads(capsys.readouterr().out)
    assert payload == {"running": False, "pid": 380, "policyd": "stopped"}


def test_cmd_daemon_stop_windows_no_policyd_pid_file(state_dir, monkeypatch, capsys):
    # No policyd.pid means nothing to stop: the stop succeeds, the
    # payload says so, and _terminate_pid is never called.
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    alive, fake_alive = _fake_pid_liveness(set())
    killed = []
    monkeypatch.setattr(cli_mod, "_pid_alive", fake_alive)
    monkeypatch.setattr(cli_mod, "_terminate_pid",
                        _fake_terminate(alive, killed))
    (state_dir / "daemon.pid").write_text("380", encoding="utf-8")
    rc = cli_mod.cmd_daemon_stop(_ns(state_dir))
    assert rc == 0
    assert killed == []
    payload = json.loads(capsys.readouterr().out)
    assert payload["policyd"] == "not running"


def test_cmd_daemon_stop_windows_stale_policyd_pid(state_dir, monkeypatch, capsys):
    # A policyd pid that is already dead is a stale file, not a
    # failure: the stop succeeds, the file is removed, no kill.
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    alive, fake_alive = _fake_pid_liveness(set())
    killed = []
    monkeypatch.setattr(cli_mod, "_pid_alive", fake_alive)
    monkeypatch.setattr(cli_mod, "_terminate_pid",
                        _fake_terminate(alive, killed))
    (state_dir / "daemon.pid").write_text("380", encoding="utf-8")
    (state_dir / "policyd.pid").write_text("7777", encoding="utf-8")
    rc = cli_mod.cmd_daemon_stop(_ns(state_dir))
    assert rc == 0
    assert killed == []
    assert not (state_dir / "policyd.pid").exists()
    payload = json.loads(capsys.readouterr().out)
    assert payload["policyd"] == "not running"


def test_cmd_daemon_stop_windows_policyd_kill_failure_warns_but_stops(
        state_dir, monkeypatch, capsys):
    # A policyd that refuses to die must NOT fail the daemon stop:
    # exit 0, policyd "failed", and the pid file is kept so a later
    # stop can retry it.
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    alive, fake_alive = _fake_pid_liveness({7777})
    killed = []
    monkeypatch.setattr(cli_mod, "_pid_alive", fake_alive)
    monkeypatch.setattr(cli_mod, "_terminate_pid",
                        _fake_terminate(alive, killed, works=False))
    (state_dir / "daemon.pid").write_text("380", encoding="utf-8")
    (state_dir / "policyd.pid").write_text("7777", encoding="utf-8")
    rc = cli_mod.cmd_daemon_stop(_ns(state_dir))
    assert rc == 0
    assert killed == [7777]
    assert (state_dir / "policyd.pid").exists()
    payload = json.loads(capsys.readouterr().out)
    assert payload["policyd"] == "failed"


def test_cmd_daemon_stop_windows_policyd_kill_failure_warning_line(
        state_dir, monkeypatch, capsys):
    # In human (non-JSON) mode the policyd failure is a visible
    # warning line next to the "daemon stopped" line.
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    alive, fake_alive = _fake_pid_liveness({7777})
    killed = []
    monkeypatch.setattr(cli_mod, "_pid_alive", fake_alive)
    monkeypatch.setattr(cli_mod, "_terminate_pid",
                        _fake_terminate(alive, killed, works=False))
    (state_dir / "daemon.pid").write_text("380", encoding="utf-8")
    (state_dir / "policyd.pid").write_text("7777", encoding="utf-8")
    rc = cli_mod.cmd_daemon_stop(_ns(state_dir, as_json=False))
    assert rc == 0
    out = capsys.readouterr().out
    assert "daemon stopped (pid 380)" in out
    assert "warning: policyd (pid 7777) did not stop" in out


def test_cmd_daemon_stop_windows_corrupt_policyd_pid_removed(
        state_dir, monkeypatch, capsys):
    # An unparseable policyd.pid is stale garbage, not a failure: the
    # stop succeeds and the file is removed.
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    alive, fake_alive = _fake_pid_liveness(set())
    killed = []
    monkeypatch.setattr(cli_mod, "_pid_alive", fake_alive)
    monkeypatch.setattr(cli_mod, "_terminate_pid",
                        _fake_terminate(alive, killed))
    (state_dir / "daemon.pid").write_text("380", encoding="utf-8")
    (state_dir / "policyd.pid").write_text("garbage", encoding="utf-8")
    rc = cli_mod.cmd_daemon_stop(_ns(state_dir))
    assert rc == 0
    assert killed == []
    assert not (state_dir / "policyd.pid").exists()
    payload = json.loads(capsys.readouterr().out)
    assert payload["policyd"] == "not running"


def test_cmd_daemon_stop_windows_not_running_still_stops_policyd(
        state_dir, monkeypatch, capsys):
    # Decision: when the daemon is already down, `daemon stop` still
    # stops policyd — the user asked to stop the services. The exit
    # code stays 1 (the daemon was not running); only the policyd
    # outcome is added.
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    monkeypatch.setattr(cli_mod, "_daemon_reachable", lambda state: False)
    alive, fake_alive = _fake_pid_liveness({7777})
    killed = []
    monkeypatch.setattr(cli_mod, "_pid_alive", fake_alive)
    monkeypatch.setattr(cli_mod, "_terminate_pid",
                        _fake_terminate(alive, killed))
    (state_dir / "policyd.pid").write_text("7777", encoding="utf-8")
    rc = cli_mod.cmd_daemon_stop(_ns(state_dir))
    assert rc == 1
    assert killed == [7777]
    assert not (state_dir / "policyd.pid").exists()
    payload = json.loads(capsys.readouterr().out)
    assert payload == {"running": False, "policyd": "stopped"}


def test_cmd_daemon_stop_windows_reachable_daemon_keeps_policyd(
        state_dir, monkeypatch, capsys):
    # Guard for the decision above: when the daemon is running but
    # has no pid file, the stop refuses to guess — and policyd is
    # left alone too, because stopping it under a live daemon would
    # break the daemon's privileged ops.
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    monkeypatch.setattr(cli_mod, "_daemon_reachable", lambda state: True)
    killed = []
    monkeypatch.setattr(cli_mod, "_terminate_pid",
                        lambda pid: killed.append(pid))
    (state_dir / "policyd.pid").write_text("7777", encoding="utf-8")
    rc = cli_mod.cmd_daemon_stop(_ns(state_dir))
    assert rc == 1
    assert killed == []
    assert (state_dir / "policyd.pid").exists()
    assert "no PID file" in capsys.readouterr().err


def test_cmd_ui_stop_windows_kills_live_process_despite_winerror87(
        state_dir, monkeypatch, capsys):
    """Same bug, same helpers, through ui stop."""
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)

    def fake_kill(pid, sig):
        err = OSError(87, "The parameter is incorrect")
        err.winerror = 87
        raise err

    monkeypatch.setattr(os, "kill", fake_kill)
    kernel32 = _fake_kernel32(exit_codes=[259, 0])
    _patch_fake_windll(monkeypatch, kernel32)
    calls = []
    monkeypatch.setattr(cli_mod.subprocess, "run",
                        lambda argv, **kw: calls.append(argv))
    (state_dir / "ui.pid").write_text("381", encoding="utf-8")
    rc = cli_mod.cmd_ui_stop(_ns(state_dir))
    assert rc == 0
    assert calls == [["taskkill", "/T", "/F", "/PID", "381"]]
    assert not (state_dir / "ui.pid").exists()


def test_terminate_pid_windows_kills_tree(monkeypatch):
    """taskkill gets /T: the recorded pid is the .venv launcher, the
    real daemon is its child."""
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    calls = []
    monkeypatch.setattr(cli_mod.subprocess, "run",
                        lambda argv, **kw: calls.append(argv))
    monkeypatch.setattr(cli_mod, "_pid_alive", lambda pid: False)
    cli_mod._terminate_pid(1234)
    assert calls == [["taskkill", "/T", "/F", "/PID", "1234"]]


def test_pid_alive_windows_dead_pid_is_dead(monkeypatch):
    """OpenProcess failing (here: error 87, no such process) is dead —
    the WinError-87 catch was rejected for exactly this reason."""
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    _patch_fake_windll(monkeypatch, _fake_kernel32(open_error=87))
    assert cli_mod._pid_alive(999999) is False


def test_pid_alive_windows_access_denied_is_alive(monkeypatch):
    """OpenProcess failing with access-denied means the process exists
    (fail closed: alive)."""
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    _patch_fake_windll(monkeypatch, _fake_kernel32(open_error=5))
    assert cli_mod._pid_alive(999999) is True


def test_pid_alive_windows_exited_process_is_dead(monkeypatch):
    """A handle whose exit code is not STILL_ACTIVE is dead."""
    import cli.opencobot_cli as cli_mod

    _patch_cli_windows(monkeypatch)
    _patch_fake_windll(monkeypatch, _fake_kernel32(exit_codes=[0]))
    assert cli_mod._pid_alive(999999) is False


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


def test_pipe_max_instances_is_bounded_above_one():
    # Thread-per-connection needs one pipe instance per concurrent
    # client, so the cap is above 1 (8: one listening instance plus
    # in-flight connections). The old value of 1 was the atomic
    # backstop for second-instance refusal — a second daemon's
    # CreateNamedPipeW failed instead of serving alongside the
    # first. That backstop is gone by design: the single-daemon
    # guarantee now rests on the reachable probe
    # (``Daemon.serve_forever`` refuses when a daemon already
    # answers) and the daemon pid file. The cap stays bounded so a
    # runaway client cannot exhaust pipe instances.
    assert transport_mod._CtypesWindowsPipeApi._PIPE_MAX_INSTANCES == 8


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
