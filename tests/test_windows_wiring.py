"""Tests for the Windows adapter wiring (Slice B).

Platform dispatch in :mod:`tools.definitions` (``_os_adapter`` /
``_is_windows``) and the Windows ``run_command`` / git paths. All
Windows behaviour is mock-tested on Linux: ``platform.system`` is
patched to ``"Windows"`` and the Windows adapter is either the real
module (stdlib-only, imports cleanly on Linux) or a fake module
injected into ``sys.modules``. No Windows host is needed; nothing
here executes ``powershell.exe`` for real.
"""

import shutil
import subprocess
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import platform  # noqa: E402

import tools.definitions as definitions  # noqa: E402
from adapters.linux import linux as linux_adapter  # noqa: E402
from adapters.windows import windows as windows_adapter  # noqa: E402
from tools.definitions import TOOLS  # noqa: E402


@pytest.fixture()
def ctx(tmp_path):
    workdir = tmp_path / "work"
    workdir.mkdir()
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    return {"state_dir": state_dir, "workdir": workdir, "token": None}


@pytest.fixture()
def windows_platform(monkeypatch):
    """Pretend this Linux host is Windows (real windows adapter)."""
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    return windows_adapter


@pytest.fixture()
def fake_windows(monkeypatch):
    """Pretend to be Windows with a fake adapter module.

    The fake mirrors the contracted adapter API; its ``safe_resolve``
    works on real Linux paths under the test workdir so file tools can
    run end-to-end through the dispatch. ``state`` toggles
    availability; ``calls`` records ``run_powershell`` invocations.
    """
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    state = {"windows_available": True, "screenshot_available": False}
    calls = []
    fake = types.ModuleType("adapters.windows.windows")
    fake.WINDOWS_BLOCKED_COMMANDS = windows_adapter.WINDOWS_BLOCKED_COMMANDS
    fake._state = state
    fake.calls = calls

    def safe_resolve(base, user_path, allowed_roots=None):
        base = Path(base).resolve()
        candidate = Path(user_path)
        path = (base / candidate).resolve() if not candidate.is_absolute() \
            else candidate.resolve()
        roots = [base] + [Path(r).resolve() for r in (allowed_roots or [])]
        if any(path.is_relative_to(r) for r in roots):
            return path
        raise ValueError(f"path outside allowed scope: {user_path!r}")

    def system_info(workdir=None):
        disk = None
        if workdir is not None:
            usage = shutil.disk_usage(str(workdir))
            disk = {"path": str(workdir), "total": usage.total,
                    "used": usage.used, "free": usage.free}
        return {
            "platform": "Windows", "platform_release": "10",
            "machine": "AMD64", "python_version": "3.12.3",
            "cpu_count": 8, "memory_total_bytes": 2**33,
            "memory_available_bytes": 2**32, "load_average": None,
            "disk": disk,
        }

    def list_processes(name_filter=None):
        processes = [
            {"pid": 1234, "name": "notepad.exe", "cmdline": "notepad.exe"},
            {"pid": 4321, "name": "explorer.exe", "cmdline": ""},
        ]
        if name_filter:
            needle = name_filter.lower()
            processes = [p for p in processes
                         if needle in p["name"].lower()
                         or needle in p["cmdline"].lower()]
        return processes

    def screenshot_available():
        if state["screenshot_available"]:
            return True, "fake screenshot tool available"
        return False, "screenshot capture is deferred (fake)"

    def list_windows_available():
        if state["windows_available"]:
            return True, "fake PowerShell window query works (1 windows)"
        return False, "powershell.exe not found (fake)"

    def list_windows():
        return [{"pid": 1234, "title": "Untitled - Notepad",
                 "process": "notepad.exe"}]

    def run_powershell(argv, timeout=30, runner=None):
        calls.append({"argv": list(argv), "timeout": timeout,
                      "runner": runner})
        if runner is not None:
            # Mimic the real adapter: build the powershell.exe argv
            # and hand it to the runner (which adds cwd=).
            full_argv = ["powershell.exe", "-NoProfile", "-NonInteractive",
                         "-Command", " ".join(argv)]
            return runner(full_argv, timeout=timeout)
        return subprocess.CompletedProcess(
            args=argv, returncode=0, stdout="ps-ok\n", stderr="")

    def trash_path(state_dir, original):
        return Path(state_dir) / "trash" / f"{Path(original).name}.stamp"

    fake.safe_resolve = safe_resolve
    fake.system_info = system_info
    fake.list_processes = list_processes
    fake.screenshot_available = screenshot_available
    fake.list_windows_available = list_windows_available
    fake.list_windows = list_windows
    fake.run_powershell = run_powershell
    fake.trash_path = trash_path
    import adapters.windows as windows_pkg
    monkeypatch.setitem(sys.modules, "adapters.windows.windows", fake)
    monkeypatch.setattr(windows_pkg, "windows", fake)
    return fake


def _exec(name, args, ctx):
    return TOOLS[name].execute(args, ctx)


def _verify(name, args, result, ctx):
    return TOOLS[name].verify(args, result, ctx)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def test_dispatch_returns_linux_adapter_on_linux():
    assert definitions._os_adapter() is linux_adapter
    assert definitions._is_windows() is False


def test_dispatch_returns_windows_adapter_on_windows(windows_platform):
    assert definitions._is_windows() is True
    assert definitions._os_adapter() is windows_adapter


def test_dispatch_returns_injected_fake_windows_module(fake_windows):
    assert definitions._os_adapter() is fake_windows


# ---------------------------------------------------------------------------
# run_command
# ---------------------------------------------------------------------------

def test_run_command_linux_uses_argv_directly(ctx):
    result = _exec("run_command", {"argv": ["echo", "hi"]}, ctx)
    assert result["ok"] is True
    assert result["data"]["stdout"] == "hi\n"
    assert result["data"]["argv"] == ["echo", "hi"]


def test_run_command_windows_goes_through_run_powershell(fake_windows, ctx):
    result = _exec("run_command", {"argv": ["Get-ChildItem"]}, ctx)
    assert result["ok"] is True
    assert result["data"]["stdout"] == "ps-ok\n"
    # The user's argv reaches the adapter unchanged (not pre-wrapped);
    # the adapter itself builds the powershell.exe argv.
    assert len(fake_windows.calls) == 1
    assert fake_windows.calls[0]["argv"] == ["Get-ChildItem"]
    assert fake_windows.calls[0]["runner"] is None
    assert result["data"]["argv"] == ["Get-ChildItem"]


def test_run_command_windows_builds_powershell_argv(windows_platform,
                                                    monkeypatch, ctx):
    """The real adapter wraps the argv as powershell.exe -Command ..."""
    seen = {}

    def fake_run(argv, timeout=30, **kwargs):
        seen["argv"] = list(argv)
        seen["timeout"] = timeout
        return subprocess.CompletedProcess(
            args=argv, returncode=0, stdout="hi\n", stderr="")

    monkeypatch.setattr(windows_adapter, "_run", fake_run)
    result = _exec("run_command", {"argv": ["echo", "hi"]}, ctx)
    assert result["ok"] is True
    assert seen["argv"][0] == "powershell.exe"
    assert seen["argv"][1:4] == ["-NoProfile", "-NonInteractive", "-Command"]
    assert "echo" in seen["argv"][4] and "hi" in seen["argv"][4]
    assert seen["timeout"] == 30


def test_run_command_windows_passes_cwd_via_runner(fake_windows,
                                                   monkeypatch, ctx):
    seen = {}

    def fake_run(argv, timeout=30, **kwargs):
        seen["argv"] = list(argv)
        seen["cwd"] = kwargs.get("cwd")
        seen["shell"] = kwargs.get("shell")
        return subprocess.CompletedProcess(
            args=argv, returncode=0, stdout="cwd-ok\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = _exec("run_command",
                   {"argv": ["echo", "hi"], "cwd": "."}, ctx)
    assert result["ok"] is True
    assert result["data"]["stdout"] == "cwd-ok\n"
    assert seen["argv"][0] == "powershell.exe"
    assert seen["cwd"] == str(ctx["workdir"])
    assert seen["shell"] is False


@pytest.mark.parametrize("argv", [
    ["sudo", "x"],
    ["rm", "-rf", "/"],
])
def test_run_command_blocked_binaries_on_linux(ctx, argv):
    result = _exec("run_command", {"argv": argv}, ctx)
    assert result["ok"] is False
    assert "blocked" in result["error"]


@pytest.mark.parametrize("argv", [
    ["format", "C:"],
    [r"C:\Windows\System32\FORMAT.EXE", "C:"],
    ["powershell", "-Command", "x"],
    ["cmd", "/c", "dir"],
    ["rm", "x"],
    ["diskpart"],
])
def test_run_command_windows_blocklist(fake_windows, ctx, argv):
    result = _exec("run_command", {"argv": argv}, ctx)
    assert result["ok"] is False
    assert "blocked" in result["error"]


def test_run_command_windows_conditional_block(windows_platform,
                                               monkeypatch, ctx):
    """`reg delete` is refused by the adapter before anything runs."""
    called = []

    def fake_run(argv, timeout=30, **kwargs):
        called.append(argv)
        return subprocess.CompletedProcess(
            args=argv, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(windows_adapter, "_run", fake_run)
    result = _exec("run_command",
                   {"argv": ["reg", "delete", r"HKLM\Foo"]}, ctx)
    assert result["ok"] is False
    assert "blocked" in result["error"]
    assert called == []


def test_windows_command_name_normalisation():
    assert definitions._windows_command_name(
        r"C:\Windows\System32\FORMAT.EXE") == "format"
    assert definitions._windows_command_name("powershell.exe") == "powershell"
    assert definitions._windows_command_name("/usr/bin/sudo") == "sudo"
    assert definitions._windows_command_name("Get-ChildItem") == "get-childitem"


# ---------------------------------------------------------------------------
# Tool interfaces unchanged through the dispatch (fake Windows)
# ---------------------------------------------------------------------------

def test_tool_interfaces_unchanged_through_dispatch(fake_windows, ctx):
    assert TOOLS["list_dir"].level == 0
    assert TOOLS["read_file"].level == 0
    assert TOOLS["system_info"].level == 0
    assert TOOLS["list_processes"].level == 0
    assert "path" in TOOLS["list_dir"].schema["properties"]
    assert "argv" in TOOLS["run_command"].schema["properties"]

    (ctx["workdir"] / "a.txt").write_text("hello", encoding="utf-8")
    result = _exec("list_dir", {"path": "."}, ctx)
    assert result["ok"] is True
    assert any(e["name"] == "a.txt" for e in result["data"]["entries"])

    result = _exec("read_file", {"path": "a.txt"}, ctx)
    assert result["ok"] is True
    assert result["data"]["content"] == "hello"

    result = _exec("system_info", {}, ctx)
    assert result["ok"] is True
    assert result["data"]["platform"] == "Windows"
    assert result["data"]["cpu_count"] == 8
    assert _verify("system_info", {}, result, ctx)[0] is True

    result = _exec("list_processes", {}, ctx)
    assert result["ok"] is True
    assert result["data"]["count"] == 2
    assert _verify("list_processes", {}, result, ctx)[0] is True


def test_git_tools_on_windows_use_git_exe(fake_windows, monkeypatch, ctx):
    seen = []
    orig_which = shutil.which

    def fake_which(name):
        if name in ("git.exe", "git"):
            return r"C:\Program Files\Git\cmd\git.exe"
        return orig_which(name)

    def fake_run(argv, **kwargs):
        seen.append(list(argv))
        if argv[1:3] == ["rev-parse", "--git-dir"]:
            return subprocess.CompletedProcess(
                args=argv, returncode=0, stdout=".git\n", stderr="")
        return subprocess.CompletedProcess(
            args=argv, returncode=0, stdout="## main\n", stderr="")

    monkeypatch.setattr(shutil, "which", fake_which)
    monkeypatch.setattr(subprocess, "run", fake_run)
    result = _exec("git_status", {"path": "."}, ctx)
    assert result["ok"] is True
    assert result["data"]["branch"] == "main"
    assert all(a[0].endswith("git.exe") for a in seen)
    assert ["rev-parse", "--git-dir"] == seen[0][1:3]
    assert seen[1][1] == "status"


def test_git_tools_on_windows_fail_without_git(fake_windows, monkeypatch, ctx):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    result = _exec("git_status", {"path": "."}, ctx)
    assert result["ok"] is False
    assert "git binary not found" in result["error"]


def test_screenshot_and_windows_honestly_unavailable(fake_windows, ctx):
    fake_windows._state["windows_available"] = False
    result = _exec("screenshot", {}, ctx)
    assert result["ok"] is False
    assert result["data"]["unavailable"] is True

    result = _exec("list_windows", {}, ctx)
    assert result["ok"] is False
    assert result["data"]["unavailable"] is True


def test_list_windows_on_windows_uses_adapter(fake_windows, ctx):
    result = _exec("list_windows", {}, ctx)
    assert result["ok"] is True
    assert result["data"]["count"] == 1
    assert result["data"]["windows"][0]["title"] == "Untitled - Notepad"
    assert _verify("list_windows", {}, result, ctx)[0] is True


def test_delete_to_trash_uses_windows_trash_path(fake_windows, ctx):
    target = ctx["workdir"] / "gone.txt"
    target.write_text("x", encoding="utf-8")
    result = _exec("delete_to_trash", {"path": "gone.txt"}, ctx)
    assert result["ok"] is True
    assert not target.exists()
    assert result["data"]["trash_path"].startswith(str(ctx["state_dir"]))
    assert Path(result["data"]["trash_path"]).is_file()
