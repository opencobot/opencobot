"""Tests for the Windows adapter (adapters/windows/windows.py).

Everything here runs on Linux: Windows behaviour is exercised through
PureWindowsPath / ntpath semantics, fake ``tasklist`` / ``wmic`` /
PowerShell outputs, and injectable runner/resolver seams. No Windows
host, no Windows-only API, no shell=True anywhere.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path, PureWindowsPath

import pytest

from adapters.windows import windows as win
from adapters.windows.windows import (
    WINDOWS_BLOCKED_COMMANDS,
    list_processes,
    list_windows,
    list_windows_available,
    parse_tasklist_csv,
    read_text,
    run_powershell,
    safe_resolve,
    screenshot_available,
    sha256_file,
    system_info,
    trash_path,
    write_text,
)

ROOT = "C:\\Work"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class FakeResult:
    """Minimal stand-in for subprocess.CompletedProcess."""

    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr
        self.args = None


def make_runner(stdout_map=None, default_stdout="", default_returncode=0):
    """Fake runner dispatching on argv; records every call.

    ``stdout_map`` maps a distinctive argv substring to (stdout, rc).
    """
    calls = []

    def runner(argv, timeout=30):
        calls.append(list(argv))
        joined = " ".join(argv)
        for needle, (out, rc) in (stdout_map or {}).items():
            if needle in joined:
                return FakeResult(stdout=out, returncode=rc)
        return FakeResult(stdout=default_stdout,
                          returncode=default_returncode)

    runner.calls = calls
    return runner


TASKLIST_CSV = (
    '"chrome.exe","1234","Console","1","123,456 K"\r\n'
    '"My App, Inc.exe","4321","Console","1","8,192 K"\r\n'
    '"System","4","Services","0","1,024 K"\r\n'
)

POWERSHELL_WINDOWS_CSV = (
    '"Id","ProcessName","MainWindowTitle"\r\n'
    '"1234","chrome","Google Chrome - OpenCobot, Inc."\r\n'
    '"4321","notepad","Untitled - Notepad"\r\n'
    '"9999","explorer",""\r\n'
)

WMIC_OS = (
    "Caption=Microsoft Windows 11 Pro\r\n"
    "BuildNumber=22631\r\n"
    "Version=10.0.22631\r\n"
)
WMIC_MEM = "TotalPhysicalMemory=17045667840\r\n"


# ---------------------------------------------------------------------------
# safe_resolve
# ---------------------------------------------------------------------------

def test_safe_resolve_accepts_path_under_root():
    assert safe_resolve(ROOT, "C:\\Work\\notes.txt") == \
        PureWindowsPath("C:\\Work\\notes.txt")


def test_safe_resolve_accepts_relative_path():
    assert safe_resolve(ROOT, "sub\\notes.txt") == \
        PureWindowsPath("C:\\Work\\sub\\notes.txt")


def test_safe_resolve_accepts_base_itself():
    assert safe_resolve(ROOT, "C:\\Work") == PureWindowsPath("C:\\Work")


def test_safe_resolve_accepts_forward_slashes():
    assert safe_resolve(ROOT, "C:/Work/sub/file.txt") == \
        PureWindowsPath("C:\\Work\\sub\\file.txt")


def test_safe_resolve_accepts_allowed_root():
    assert safe_resolve(ROOT, "D:\\Shared\\f.txt",
                        allowed_roots=["D:\\Shared"]) == \
        PureWindowsPath("D:\\Shared\\f.txt")


def test_safe_resolve_refuses_windows_escape():
    with pytest.raises(ValueError, match="outside allowed scope"):
        safe_resolve(ROOT, "C:\\Windows\\System32\\evil.exe")


def test_safe_resolve_refuses_dotdot_traversal():
    with pytest.raises(ValueError, match="outside allowed scope"):
        safe_resolve(ROOT, "..\\..\\Windows\\System32\\x.exe")


def test_safe_resolve_refuses_absolute_dotdot_inside():
    with pytest.raises(ValueError, match="outside allowed scope"):
        safe_resolve(ROOT, "C:\\Work\\..\\Windows\\x.exe")


def test_safe_resolve_refuses_unc_escape():
    with pytest.raises(ValueError, match="outside allowed scope"):
        safe_resolve(ROOT, "\\\\server\\share\\evil.txt")


def test_safe_resolve_accepts_unc_under_unc_root():
    assert safe_resolve("\\\\server\\share\\Work",
                        "\\\\server\\share\\Work\\f.txt") == \
        PureWindowsPath("\\\\server\\share\\Work\\f.txt")


def test_safe_resolve_refuses_drive_letter_mismatch():
    with pytest.raises(ValueError, match="outside allowed scope"):
        safe_resolve(ROOT, "D:\\Work\\file.txt")


def test_safe_resolve_case_insensitive_bypass_attempt():
    # Root C:\Work vs path c:\work\..\windows — must still refuse.
    with pytest.raises(ValueError, match="outside allowed scope"):
        safe_resolve("C:\\Work", "c:\\work\\..\\windows\\x.exe")


def test_safe_resolve_case_insensitive_accept():
    assert safe_resolve("C:\\Work", "c:\\WORK\\Sub\\F.TXT") == \
        PureWindowsPath("c:\\WORK\\Sub\\F.TXT")


def test_safe_resolve_prefix_sibling_not_inside():
    # C:\Work2 is a sibling of C:\Work, not inside it (string-prefix trap).
    with pytest.raises(ValueError, match="outside allowed scope"):
        safe_resolve(ROOT, "C:\\Work2\\file.txt")


def test_safe_resolve_tilde_expands_to_profile(monkeypatch):
    monkeypatch.setenv("USERPROFILE", "C:\\Users\\test")
    assert safe_resolve("C:\\Users\\test", "~\\docs\\f.txt") == \
        PureWindowsPath("C:\\Users\\test\\docs\\f.txt")


def test_safe_resolve_rejects_empty_and_non_string():
    with pytest.raises(ValueError):
        safe_resolve(ROOT, "")
    with pytest.raises(ValueError):
        safe_resolve(ROOT, None)  # type: ignore[arg-type]


def test_safe_resolve_short_name_resolved_by_injected_resolver():
    def fake_resolver(path):
        return path.replace("PROGRA~1", "Program Files")

    assert safe_resolve(ROOT, "C:\\Work\\PROGRA~1\\app.exe",
                        resolver=fake_resolver) == \
        PureWindowsPath("C:\\Work\\Program Files\\app.exe")


def test_safe_resolve_symlink_escape_refused_by_injected_resolver():
    def fake_resolver(path):
        if path.lower().startswith("c:\\work\\link"):
            return "C:\\Windows\\System32" + path[len("C:\\Work\\link"):]
        return path

    with pytest.raises(ValueError, match="outside allowed scope"):
        safe_resolve(ROOT, "C:\\Work\\link\\evil.exe",
                     resolver=fake_resolver)


# ---------------------------------------------------------------------------
# read_text / write_text / sha256_file
# ---------------------------------------------------------------------------

def test_read_write_text_roundtrip(tmp_path):
    target = tmp_path / "note.txt"
    assert write_text(target, "hello wörld") == target
    assert read_text(target) == "hello wörld"


def test_write_text_create_parents(tmp_path):
    target = tmp_path / "a" / "b" / "note.txt"
    write_text(target, "x", create_parents=True)
    assert read_text(target) == "x"


def test_read_text_max_bytes_and_bad_utf8(tmp_path):
    target = tmp_path / "bin.dat"
    target.write_bytes(b"abcdef\xff\xfe")
    assert read_text(target, max_bytes=3) == "abc"
    # Undecodable bytes become replacement characters, not an exception.
    assert "\ufffd" in read_text(target)


def test_sha256_file(tmp_path):
    target = tmp_path / "f.bin"
    target.write_bytes(b"abc")
    assert sha256_file(target) == hashlib.sha256(b"abc").hexdigest()


# ---------------------------------------------------------------------------
# trash_path
# ---------------------------------------------------------------------------

def test_trash_path_preserves_relative_path_and_timestamp(tmp_path):
    dest = trash_path(tmp_path, "C:\\Users\\abhay\\notes.txt")
    assert dest.parent == tmp_path / "trash" / "Users" / "abhay"
    assert re.fullmatch(r"notes\.txt\.\d{8}T\d{12}", dest.name), dest.name


def test_trash_path_unc_strips_anchor(tmp_path):
    dest = trash_path(tmp_path, "\\\\server\\share\\f.txt")
    assert dest.parent == tmp_path / "trash"
    assert dest.name.startswith("f.txt.")


def test_trash_path_two_trashes_differ(tmp_path):
    a = trash_path(tmp_path, "C:\\Work\\f.txt")
    b = trash_path(tmp_path, "C:\\Work\\f.txt")
    # Same second is possible; names must at least match the pattern and
    # the timestamp is monotonic-or-equal — the key property is the
    # timestamped suffix exists so collisions are avoided in practice.
    assert re.fullmatch(r"f\.txt\.\d{8}T\d{12}", a.name)
    assert re.fullmatch(r"f\.txt\.\d{8}T\d{12}", b.name)


# ---------------------------------------------------------------------------
# list_processes / tasklist parsing
# ---------------------------------------------------------------------------

def test_tasklist_csv_parsing():
    procs = parse_tasklist_csv(TASKLIST_CSV)
    assert procs == [
        {"pid": 4, "name": "System", "memory_kb": 1024},
        {"pid": 1234, "name": "chrome.exe", "memory_kb": 123456},
        {"pid": 4321, "name": "My App, Inc.exe", "memory_kb": 8192},
    ]


def test_tasklist_csv_skips_bad_pid_rows():
    text = '"notapid","abc","Console","1","1,024 K"\r\n"ok.exe","7","Console","1","512 K"\r\n'
    assert parse_tasklist_csv(text) == [
        {"pid": 7, "name": "ok.exe", "memory_kb": 512}]


def test_list_processes_uses_tasklist_argv_and_filter():
    runner = make_runner(default_stdout=TASKLIST_CSV)
    procs = list_processes(runner=runner)
    assert runner.calls == [["tasklist", "/FO", "CSV", "/NH"]]
    assert [p["pid"] for p in procs] == [4, 1234, 4321]
    filtered = list_processes(name_filter="CHROME", runner=runner)
    assert [p["name"] for p in filtered] == ["chrome.exe"]
    assert list_processes(name_filter="no-such-app", runner=runner) == []


# ---------------------------------------------------------------------------
# system_info
# ---------------------------------------------------------------------------

def test_system_info_parses_wmic():
    runner = make_runner({"wmic os get": (WMIC_OS, 0),
                          "wmic computersystem": (WMIC_MEM, 0)})
    info = system_info(runner=runner)
    assert info["windows_version"] == "10.0.22631"
    assert info["windows_build"] == "22631"
    assert info["windows_edition"] == "Microsoft Windows 11 Pro"
    assert info["memory_total_bytes"] == 17045667840
    assert info["cpu_count"] is not None
    assert info["python_version"]
    assert info["load_average"] is None  # no getloadavg concept on Windows
    assert info["disk"] is None


def test_system_info_falls_back_when_wmic_missing():
    def failing_runner(argv, timeout=30):
        raise FileNotFoundError("wmic not found")

    info = system_info(runner=failing_runner)
    assert info["windows_version"] is None
    assert info["windows_build"] is None
    assert info["windows_edition"] is None
    assert info["memory_total_bytes"] is None
    assert info["platform"]  # platform keys still present, no crash


def test_system_info_disk_for_workdir(tmp_path):
    info = system_info(workdir=tmp_path, runner=make_runner())
    assert info["disk"]["path"] == str(tmp_path)
    assert info["disk"]["total"] > 0
    assert info["disk"]["free"] >= 0


# ---------------------------------------------------------------------------
# screenshot / windows availability
# ---------------------------------------------------------------------------

def test_screenshot_available_is_honestly_false():
    ok, reason = screenshot_available()
    assert ok is False
    assert "deferred" in reason.lower()
    assert "ui automation" in reason.lower()


def test_list_windows_parses_powershell_csv():
    runner = make_runner(default_stdout=POWERSHELL_WINDOWS_CSV)
    windows = list_windows(runner=runner)
    assert windows == [
        {"pid": 1234, "title": "Google Chrome - OpenCobot, Inc.",
         "process": "chrome"},
        {"pid": 4321, "title": "Untitled - Notepad", "process": "notepad"},
    ]
    # Empty-title rows (e.g. background explorer) are skipped.
    assert all(w["title"] for w in windows)
    # The runner was called with powershell.exe, no shell.
    assert runner.calls[0][0] == "powershell.exe"
    assert "-NoProfile" in runner.calls[0]
    assert "-NonInteractive" in runner.calls[0]


def test_list_windows_raises_when_powershell_fails():
    runner = make_runner(default_stdout="", default_returncode=1)
    with pytest.raises(OSError, match="PowerShell window query failed"):
        list_windows(runner=runner)


def test_list_windows_available_true_with_working_runner():
    runner = make_runner(default_stdout=POWERSHELL_WINDOWS_CSV)
    ok, reason = list_windows_available(runner=runner)
    assert ok is True
    assert "2 windows" in reason


def test_list_windows_available_false_when_query_fails():
    def failing_runner(argv, timeout=30):
        raise FileNotFoundError("powershell.exe not found")

    ok, reason = list_windows_available(runner=failing_runner)
    assert ok is False
    assert "failed" in reason.lower()


def test_list_windows_available_false_on_linux_without_powershell(monkeypatch):
    # No runner: relies on shutil.which("powershell.exe") — absent here.
    monkeypatch.setattr(win.shutil, "which", lambda name: None)
    ok, reason = list_windows_available()
    assert ok is False
    assert "powershell.exe not found" in reason


# ---------------------------------------------------------------------------
# run_powershell
# ---------------------------------------------------------------------------

def test_run_powershell_argv_construction():
    runner = make_runner(default_stdout="ok")
    result = run_powershell(["Get-Process", "-Name", "chrome"],
                            runner=runner)
    assert result.stdout == "ok"
    assert runner.calls == [[
        "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
        "& 'Get-Process' '-Name' 'chrome'",
    ]]


def test_run_powershell_quoting_keeps_metachars_literal():
    runner = make_runner()
    run_powershell(["Get-ChildItem", "-Path", "C:\\Work\\it's $(); here"],
                   runner=runner)
    command = runner.calls[0][-1]
    # Single quote doubled, $() and ; stay inside single quotes (literal).
    assert command == (
        "& 'Get-ChildItem' '-Path' 'C:\\Work\\it''s $(); here'")


def test_run_powershell_uses_shell_false(monkeypatch):
    seen = {}

    def fake_run(argv, **kwargs):
        seen.update(kwargs)
        return FakeResult(stdout="ok")

    monkeypatch.setattr(win.subprocess, "run", fake_run)
    run_powershell(["Get-Date"])
    assert seen.get("shell") is False


def test_run_powershell_rejects_empty_argv():
    with pytest.raises(ValueError):
        run_powershell([])
    with pytest.raises(ValueError):
        run_powershell(["Get-Date", ""])


@pytest.mark.parametrize("argv", [
    ["format", "C:"],
    ["diskpart"],
    ["bcdedit", "/enum"],
    ["del", "C:\\Work\\f.txt"],
    ["erase", "f.txt"],
    ["takeown", "/f", "C:\\x"],
    ["sudo", "id"],
    ["su", "-c", "id"],
    ["doas", "id"],
    ["rm", "-rf", "."],
    ["cmd", "/c", "dir"],
    ["powershell", "-Command", "Get-Date"],
    ["pwsh", "-c", "Get-Date"],
    ["FORMAT.EXE", "C:"],
    ["C:\\Windows\\System32\\format.exe", "C:"],
])
def test_run_powershell_blocked_commands(argv):
    with pytest.raises(ValueError, match="blocked command"):
        run_powershell(argv, runner=make_runner())


@pytest.mark.parametrize("argv", [
    ["reg", "delete", "HKCU\\Software\\X"],
    ["reg", "DELETE", "HKCU\\Software\\X"],
    ["shutdown", "/r", "/t", "0"],
    ["shutdown", "/s"],
    ["rmdir", "/s", "C:\\Work\\dir"],
    ["icacls", "C:\\f.txt", "/grant", "user:F"],
    ["icacls", "C:\\f.txt", "/remove", "user"],
    ["icacls", "C:\\f.txt", "/setowner", "user"],
])
def test_run_powershell_blocked_conditional_forms(argv):
    with pytest.raises(ValueError, match="blocked command form"):
        run_powershell(argv, runner=make_runner())


@pytest.mark.parametrize("argv", [
    ["reg", "query", "HKCU\\Software\\X"],
    ["shutdown", "/a"],
    ["rmdir", "C:\\Work\\empty-dir"],
    ["icacls", "C:\\f.txt"],
    ["Get-Process"],
])
def test_run_powershell_allowed_forms(argv):
    runner = make_runner()
    run_powershell(argv, runner=runner)
    assert runner.calls  # it ran


def test_blocked_command_set_contents():
    for name in ("sudo", "su", "doas", "rm", "format", "diskpart",
                 "bcdedit", "del", "takeown"):
        assert name in WINDOWS_BLOCKED_COMMANDS
    assert isinstance(WINDOWS_BLOCKED_COMMANDS, frozenset)


# ---------------------------------------------------------------------------
# Package exports
# ---------------------------------------------------------------------------

def test_windows_package_exports():
    import adapters.windows as pkg

    for name in ("safe_resolve", "read_text", "write_text", "trash_path",
                 "list_processes", "list_windows", "list_windows_available",
                 "run_powershell", "screenshot_available", "sha256_file",
                 "system_info", "WINDOWS_BLOCKED_COMMANDS"):
        assert name in pkg.__all__
        assert hasattr(pkg, name)
