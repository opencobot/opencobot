"""Tests for the OpenCobot Phase 1 Linux MVP tools slice.

pytest, tmp_path workdirs, no network. Each tool gets a happy path and at
least one failure/denial path; verify() is checked against real state,
including a tamper-after-write case.
"""

import hashlib
import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adapters.linux.linux import safe_resolve, trash_path  # noqa: E402
from adapters.windows.stub import WindowsAdapter  # noqa: E402
from tools.definitions import TOOLS, get_tool, list_tools  # noqa: E402

EXPECTED = {
    "list_dir": 0, "read_file": 0, "file_info": 0, "file_hash": 0,
    "search_files": 0, "system_info": 0, "list_processes": 0,
    "process_info": 0, "git_status": 0, "git_log": 0, "git_diff": 0,
    "screenshot": 0, "list_windows": 0, "launch_app": 1, "write_file": 2,
    "create_file": 2, "append_file": 2, "mkdir": 2, "move_file": 2,
    "copy_file": 2, "delete_to_trash": 3, "run_command": 3,
}


@pytest.fixture()
def ctx(tmp_path):
    workdir = tmp_path / "work"
    workdir.mkdir()
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    return {"state_dir": state_dir, "workdir": workdir, "token": None}


@pytest.fixture()
def launched_pids():
    pids = []
    yield pids
    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def run(name, args, ctx):
    return get_tool(name).execute(args, ctx)


def verify(name, args, result, ctx):
    return get_tool(name).verify(args, result, ctx)


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def test_registry_has_22_tools_with_levels():
    assert set(TOOLS) == set(EXPECTED)
    assert len(TOOLS) == 22
    for name, level in EXPECTED.items():
        assert TOOLS[name].level == level, name
        assert TOOLS[name].schema["type"] == "object"
        assert TOOLS[name].schema.get("additionalProperties") is False


def test_get_tool_unknown_raises():
    with pytest.raises(KeyError):
        get_tool("no_such_tool")


def test_list_tools_shape():
    listed = list_tools()
    assert len(listed) == 22
    for item in listed:
        assert set(item) == {"name", "description", "level", "schema"}
        assert item["schema"]["type"] == "object"


def test_schema_validation_rejects_unknown_arg(ctx):
    result = run("system_info", {"bogus": 1}, ctx)
    assert result["ok"] is False
    assert "unexpected arguments" in result["error"]


def test_schema_validation_rejects_wrong_type(ctx):
    result = run("process_info", {"pid": "123"}, ctx)
    assert result["ok"] is False
    assert "must be integer" in result["error"]


def test_schema_validation_rejects_missing_required(ctx):
    result = run("read_file", {}, ctx)
    assert result["ok"] is False
    assert "missing required" in result["error"]


# ---------------------------------------------------------------------------
# Path scope / traversal
# ---------------------------------------------------------------------------

def test_path_traversal_denied(ctx, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    for tool, args in [
        ("read_file", {"path": "../outside.txt"}),
        ("read_file", {"path": str(outside)}),
        ("write_file", {"path": "../evil.txt", "content": "x"}),
        ("list_dir", {"path": "/etc"}),
    ]:
        result = run(tool, args, ctx)
        assert result["ok"] is False, (tool, args, result)
        assert "outside allowed scope" in result["error"]


def test_symlink_escape_denied(ctx, tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("secret")
    link = ctx["workdir"] / "link.txt"
    link.symlink_to(target)
    result = run("read_file", {"path": "link.txt"}, ctx)
    assert result["ok"] is False
    assert "outside allowed scope" in result["error"]


def test_safe_resolve_allows_token_scope(ctx, tmp_path):
    extra = tmp_path / "extra"
    extra.mkdir()
    (extra / "a.txt").write_text("hi")
    ctx["token"] = {"folders": [str(extra)]}
    result = run("read_file", {"path": str(extra / "a.txt")}, ctx)
    assert result["ok"] is True
    assert result["data"]["content"] == "hi"


def test_trash_path_uses_state_dir_when_no_xdg_trash(ctx):
    dest = trash_path(ctx["state_dir"], Path("/tmp/work/file.txt"))
    assert str(dest).startswith(str(ctx["state_dir"] / "trash"))


# ---------------------------------------------------------------------------
# File reading tools
# ---------------------------------------------------------------------------

def test_list_dir_and_verify(ctx):
    (ctx["workdir"] / "a.txt").write_text("a")
    (ctx["workdir"] / "sub").mkdir()
    (ctx["workdir"] / "sub" / "b.txt").write_text("b")
    result = run("list_dir", {"path": "."}, ctx)
    assert result["ok"] is True
    assert {e["name"] for e in result["data"]["entries"]} == {"a.txt", "sub"}
    assert verify("list_dir", {"path": "."}, result, ctx)[0] is True
    result = run("list_dir", {"path": ".", "recursive": True}, ctx)
    names = {e["name"] for e in result["data"]["entries"]}
    assert "sub/b.txt" in names
    assert verify("list_dir", {"path": ".", "recursive": True}, result, ctx)[0] is True


def test_list_dir_not_a_directory(ctx):
    (ctx["workdir"] / "f.txt").write_text("x")
    result = run("list_dir", {"path": "f.txt"}, ctx)
    assert result["ok"] is False


def test_read_file_truncation_and_verify(ctx):
    (ctx["workdir"] / "f.txt").write_text("hello world")
    result = run("read_file", {"path": "f.txt", "max_bytes": 5}, ctx)
    assert result["ok"] is True
    assert result["data"]["content"] == "hello"
    assert result["data"]["truncated"] is True
    assert verify("read_file", {"path": "f.txt", "max_bytes": 5}, result, ctx)[0] is True
    # Tamper after read -> verify must fail.
    (ctx["workdir"] / "f.txt").write_text("changed!!")
    ok, evidence = verify("read_file", {"path": "f.txt", "max_bytes": 5}, result, ctx)
    assert ok is False, evidence


def test_read_file_missing(ctx):
    assert run("read_file", {"path": "nope.txt"}, ctx)["ok"] is False


def test_file_info_and_hash(ctx):
    (ctx["workdir"] / "f.txt").write_text("abc")
    info = run("file_info", {"path": "f.txt"}, ctx)
    assert info["ok"] is True
    assert info["data"]["size"] == 3
    assert info["data"]["is_dir"] is False
    assert info["data"]["sha256"] == sha("abc")
    assert verify("file_info", {"path": "f.txt"}, info, ctx)[0] is True
    hashed = run("file_hash", {"path": "f.txt"}, ctx)
    assert hashed["data"]["hash"] == sha("abc")
    assert verify("file_hash", {"path": "f.txt"}, hashed, ctx)[0] is True
    md5 = run("file_hash", {"path": "f.txt", "algorithm": "md5"}, ctx)
    assert md5["data"]["hash"] == hashlib.md5(b"abc").hexdigest()
    bad = run("file_hash", {"path": "f.txt", "algorithm": "sha999"}, ctx)
    assert bad["ok"] is False


def test_search_files_glob_and_substring(ctx):
    (ctx["workdir"] / "report.txt").write_text("x")
    (ctx["workdir"] / "notes.md").write_text("x")
    (ctx["workdir"] / "data.csv").write_text("x")
    result = run("search_files", {"path": ".", "pattern": "*.txt"}, ctx)
    assert result["ok"] is True
    assert [Path(p).name for p in result["data"]["results"]] == ["report.txt"]
    assert verify("search_files", {"path": ".", "pattern": "*.txt"}, result, ctx)[0] is True
    result = run("search_files", {"path": ".", "pattern": "note"}, ctx)
    assert [Path(p).name for p in result["data"]["results"]] == ["notes.md"]
    # No regex injection: a regex-looking pattern is literal/fnmatch only.
    result = run("search_files", {"path": ".", "pattern": ".*"}, ctx)
    assert result["data"]["results"] == []


def test_search_files_not_a_directory(ctx):
    assert run("search_files", {"path": "missing", "pattern": "x"}, ctx)["ok"] is False


# ---------------------------------------------------------------------------
# System / processes
# ---------------------------------------------------------------------------

def test_system_info(ctx):
    result = run("system_info", {}, ctx)
    assert result["ok"] is True
    data = result["data"]
    assert data["platform"] == "Linux"
    assert data["cpu_count"] == os.cpu_count()
    assert data["memory_total_bytes"] and data["memory_total_bytes"] > 0
    assert data["disk"]["total"] > 0
    assert verify("system_info", {}, result, ctx)[0] is True


def test_list_processes_and_verify(ctx):
    result = run("list_processes", {}, ctx)
    assert result["ok"] is True
    assert result["data"]["count"] > 0
    assert any(p["pid"] == os.getpid() for p in result["data"]["processes"])
    assert verify("list_processes", {}, result, ctx)[0] is True
    filtered = run("list_processes", {"name_filter": "python"}, ctx)
    assert filtered["ok"] is True
    assert all("python" in (p["name"] + p["cmdline"]).lower()
               for p in filtered["data"]["processes"])
    assert verify("list_processes", {"name_filter": "python"}, filtered, ctx)[0] is True


def test_process_info_self(ctx):
    result = run("process_info", {"pid": os.getpid()}, ctx)
    assert result["ok"] is True
    assert result["data"]["pid"] == os.getpid()
    assert result["data"]["name"]
    assert verify("process_info", {"pid": os.getpid()}, result, ctx)[0] is True


def test_process_info_missing_pid(ctx):
    result = run("process_info", {"pid": 999999}, ctx)
    assert result["ok"] is False


def test_process_info_bad_pid(ctx):
    assert run("process_info", {"pid": -1}, ctx)["ok"] is False


# ---------------------------------------------------------------------------
# Git (real tmp repo)
# ---------------------------------------------------------------------------

@pytest.fixture()
def git_repo(ctx):
    repo = ctx["workdir"] / "repo"
    repo.mkdir()
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    subprocess.run(["git", "init", "-q", str(repo)], check=True, env=env)
    (repo / "a.txt").write_text("one\n")
    subprocess.run(["git", "add", "."], cwd=repo, check=True, env=env)
    subprocess.run(["git", "commit", "-qm", "first"], cwd=repo, check=True, env=env)
    return repo


def test_git_status_clean_then_dirty(ctx, git_repo):
    clean = run("git_status", {"path": "repo"}, ctx)
    assert clean["ok"] is True
    assert clean["data"]["clean"] is True
    assert clean["data"]["branch"]
    assert verify("git_status", {"path": "repo"}, clean, ctx)[0] is True
    (git_repo / "a.txt").write_text("two\n")
    dirty = run("git_status", {"path": "repo"}, ctx)
    assert dirty["data"]["clean"] is False
    assert dirty["data"]["unstaged"] == ["a.txt"]
    assert verify("git_status", {"path": "repo"}, dirty, ctx)[0] is True


def test_git_log_and_diff(ctx, git_repo):
    log = run("git_log", {"path": "repo"}, ctx)
    assert log["ok"] is True
    assert log["data"]["count"] == 1
    assert log["data"]["commits"][0]["subject"] == "first"
    assert verify("git_log", {"path": "repo"}, log, ctx)[0] is True
    diff_clean = run("git_diff", {"path": "repo"}, ctx)
    assert diff_clean["ok"] is True
    assert diff_clean["data"]["diff"] == ""
    (git_repo / "a.txt").write_text("two\n")
    diff = run("git_diff", {"path": "repo"}, ctx)
    assert diff["data"]["files"] == ["a.txt"]
    assert "-one" in diff["data"]["diff"] and "+two" in diff["data"]["diff"]
    assert verify("git_diff", {"path": "repo"}, diff, ctx)[0] is True


def test_git_tools_not_a_repo(ctx):
    for name in ("git_status", "git_log", "git_diff"):
        result = run(name, {"path": "."}, ctx)
        assert result["ok"] is False
        assert "not a git repository" in result["error"]


# ---------------------------------------------------------------------------
# Screenshot / windows (headless: honest unavailable, never fake)
# ---------------------------------------------------------------------------

def test_screenshot_unavailable_headless(ctx):
    assert "DISPLAY" not in os.environ and "WAYLAND_DISPLAY" not in os.environ
    result = run("screenshot", {}, ctx)
    assert result["ok"] is False
    assert result["data"]["unavailable"] is True
    assert "no display server" in result["data"]["reason"]
    assert verify("screenshot", {}, result, ctx)[0] is False


def test_list_windows_unavailable_headless(ctx):
    result = run("list_windows", {}, ctx)
    assert result["ok"] is False
    assert result["data"]["unavailable"] is True
    assert verify("list_windows", {}, result, ctx)[0] is False


# ---------------------------------------------------------------------------
# launch_app
# ---------------------------------------------------------------------------

def test_launch_app_sleep_and_verify(ctx, launched_pids):
    result = run("launch_app", {"app": "sleep", "args": ["30"]}, ctx)
    assert result["ok"] is True
    pid = result["data"]["pid"]
    launched_pids.append(pid)
    assert verify("launch_app", {"app": "sleep", "args": ["30"]}, result, ctx)[0] is True


def test_launch_app_blocked_and_missing(ctx):
    assert run("launch_app", {"app": "sudo", "args": ["id"]}, ctx)["ok"] is False
    assert run("launch_app", {"app": "su"}, ctx)["ok"] is False
    assert run("launch_app", {"app": "definitely-not-a-real-app-xyz"}, ctx)["ok"] is False


# ---------------------------------------------------------------------------
# File modification
# ---------------------------------------------------------------------------

def test_write_file_snapshot_and_tamper_verify(ctx):
    target = ctx["workdir"] / "f.txt"
    target.write_text("original")
    result = run("write_file", {"path": "f.txt", "content": "new content"}, ctx)
    assert result["ok"] is True
    assert result["data"]["sha256"] == sha("new content")
    snapshot = Path(result["data"]["snapshot"])
    assert snapshot.is_file() and snapshot.read_text() == "original"
    assert verify("write_file", {"path": "f.txt", "content": "new content"},
                  result, ctx)[0] is True
    target.write_text("tampered")
    ok, evidence = verify("write_file", {"path": "f.txt", "content": "new content"},
                          result, ctx)
    assert ok is False, evidence


def test_write_file_create_parents(ctx):
    result = run("write_file", {"path": "a/b/c.txt", "content": "hi"}, ctx)
    assert result["ok"] is False  # no create_parents
    result = run("write_file", {"path": "a/b/c.txt", "content": "hi",
                                "create_parents": True}, ctx)
    assert result["ok"] is True
    assert (ctx["workdir"] / "a" / "b" / "c.txt").read_text() == "hi"


def test_create_file_and_duplicate(ctx):
    result = run("create_file", {"path": "new.txt", "content": "hello"}, ctx)
    assert result["ok"] is True
    assert verify("create_file", {"path": "new.txt", "content": "hello"},
                  result, ctx)[0] is True
    assert run("create_file", {"path": "new.txt", "content": "again"}, ctx)["ok"] is False


def test_append_file(ctx):
    (ctx["workdir"] / "f.txt").write_text("one")
    result = run("append_file", {"path": "f.txt", "content": " two"}, ctx)
    assert result["ok"] is True
    assert (ctx["workdir"] / "f.txt").read_text() == "one two"
    assert verify("append_file", {"path": "f.txt", "content": " two"},
                  result, ctx)[0] is True
    (ctx["workdir"] / "f.txt").write_text("replaced")
    assert verify("append_file", {"path": "f.txt", "content": " two"},
                  result, ctx)[0] is False


def test_mkdir(ctx):
    result = run("mkdir", {"path": "d1"}, ctx)
    assert result["ok"] is True
    assert (ctx["workdir"] / "d1").is_dir()
    assert verify("mkdir", {"path": "d1"}, result, ctx)[0] is True
    assert run("mkdir", {"path": "d1"}, ctx)["ok"] is False  # already exists
    assert run("mkdir", {"path": "x/y"}, ctx)["ok"] is False  # no parents
    assert run("mkdir", {"path": "x/y", "parents": True}, ctx)["ok"] is True


def test_move_and_copy_file(ctx):
    (ctx["workdir"] / "src.txt").write_text("data")
    moved = run("move_file", {"source": "src.txt", "destination": "dst.txt"}, ctx)
    assert moved["ok"] is True
    assert not (ctx["workdir"] / "src.txt").exists()
    assert (ctx["workdir"] / "dst.txt").read_text() == "data"
    assert verify("move_file", {"source": "src.txt", "destination": "dst.txt"},
                  moved, ctx)[0] is True
    copied = run("copy_file", {"source": "dst.txt", "destination": "copy.txt"}, ctx)
    assert copied["ok"] is True
    assert (ctx["workdir"] / "dst.txt").exists()  # source stays
    assert (ctx["workdir"] / "copy.txt").read_text() == "data"
    assert verify("copy_file", {"source": "dst.txt", "destination": "copy.txt"},
                  copied, ctx)[0] is True
    assert run("move_file", {"source": "missing.txt", "destination": "x"}, ctx)["ok"] is False
    assert run("copy_file", {"source": "dst.txt", "destination": "copy.txt"},
               ctx)["ok"] is False  # destination exists


def test_move_verify_fails_if_source_restored(ctx):
    (ctx["workdir"] / "s.txt").write_text("v")
    moved = run("move_file", {"source": "s.txt", "destination": "d.txt"}, ctx)
    assert moved["ok"] is True
    (ctx["workdir"] / "s.txt").write_text("back")
    assert verify("move_file", {"source": "s.txt", "destination": "d.txt"},
                  moved, ctx)[0] is False


# ---------------------------------------------------------------------------
# delete_to_trash
# ---------------------------------------------------------------------------

def test_delete_to_trash_moves_not_deletes(ctx):
    target = ctx["workdir"] / "doomed.txt"
    target.write_text("keep me")
    result = run("delete_to_trash", {"path": "doomed.txt"}, ctx)
    assert result["ok"] is True
    assert not target.exists()
    trash_copy = Path(result["data"]["trash_path"])
    assert trash_copy.is_file()
    assert trash_copy.read_text() == "keep me"
    assert result["data"]["sha256"] == sha("keep me")
    assert verify("delete_to_trash", {"path": "doomed.txt"}, result, ctx)[0] is True


def test_delete_to_trash_missing(ctx):
    assert run("delete_to_trash", {"path": "ghost.txt"}, ctx)["ok"] is False


# ---------------------------------------------------------------------------
# run_command
# ---------------------------------------------------------------------------

def test_run_command_happy(ctx):
    result = run("run_command", {"argv": ["python3", "-c", "print(1)"]}, ctx)
    assert result["ok"] is True
    assert result["data"]["returncode"] == 0
    assert result["data"]["stdout"].strip() == "1"
    assert verify("run_command", {"argv": ["python3", "-c", "print(1)"]},
                  result, ctx)[0] is True


def test_run_command_shell_metachar_is_literal(ctx, tmp_path):
    # "a; rm -rf /" must be ONE argv element to echo, never executed as shell.
    marker = ctx["workdir"] / "marker.txt"
    marker.write_text("alive")
    result = run("run_command", {"argv": ["echo", "a; rm -rf /"]}, ctx)
    assert result["ok"] is True
    assert result["data"]["stdout"].strip() == "a; rm -rf /"
    assert marker.read_text() == "alive"


def test_run_command_blocked(ctx):
    for argv in (["sudo", "id"], ["su", "-c", "id"], ["rm", "-rf", "."],
                 ["echo", "--no-preserve-root"]):
        result = run("run_command", {"argv": argv}, ctx)
        assert result["ok"] is False, argv
        assert "blocked" in result["error"], argv


def test_run_command_failures(ctx):
    assert run("run_command", {"argv": []}, ctx)["ok"] is False
    assert run("run_command", {"argv": ["false"]}, ctx)["ok"] is False
    assert run("run_command", {"argv": ["echo", "hi"], "timeout": 61}, ctx)["ok"] is False
    assert run("run_command", {"argv": ["echo", "hi"], "timeout": 0}, ctx)["ok"] is False
    assert run("run_command", {"argv": ["echo", "hi"], "cwd": "/etc"}, ctx)["ok"] is False
    result = run("run_command", {"argv": ["definitely-not-a-real-cmd-xyz"]}, ctx)
    assert result["ok"] is False


def test_run_command_timeout(ctx):
    result = run("run_command", {"argv": ["sleep", "5"], "timeout": 1}, ctx)
    assert result["ok"] is False
    assert result["data"]["timed_out"] is True
    assert "timed out" in result["error"]


def test_run_command_output_truncated(ctx):
    result = run("run_command",
                 {"argv": ["python3", "-c", "print('x' * 200000)"]}, ctx)
    assert result["ok"] is True
    assert len(result["data"]["stdout"]) <= 64 * 1024
    assert result["data"]["truncated"] is True


# ---------------------------------------------------------------------------
# Windows stub
# ---------------------------------------------------------------------------

def test_windows_adapter_stub():
    with pytest.raises(NotImplementedError, match="ADR-001"):
        WindowsAdapter()
    adapter = WindowsAdapter.__new__(WindowsAdapter)
    with pytest.raises(NotImplementedError, match="ADR-001"):
        adapter.list_processes()
