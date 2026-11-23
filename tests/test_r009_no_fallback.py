"""Tests for R-009: cli/_fallback.py is gone; the CLI fails loudly.

The duplicate in-process policy engine / tool registry was deleted.
When a real ``policy`` / ``tools`` / ``core`` module is missing, the
CLI must print a clear error and exit non-zero — never silently run
a weaker in-process copy. The missing-module case is simulated in a
subprocess with a meta-path blocker (no files are moved).
"""

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cli._compat import (  # noqa: E402
    PolicyUnavailable,
    RuntimeUnavailable,
    get_audit_log,
    get_policy_client,
    get_policy_engine,
    get_runtime,
    get_tools,
)

REPO_ROOT = Path(__file__).resolve().parents[1]

_BLOCKER = '''
import sys
class Blocker:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in ("policy", "tools", "core"):
            raise ImportError("blocked for test: " + fullname)
        return None
sys.meta_path.insert(0, Blocker())
sys.argv = ["opencobot", *__ARGV__]
from cli.opencobot_cli import main
raise SystemExit(main())
'''


def test_fallback_file_is_gone():
    assert not (REPO_ROOT / "cli" / "_fallback.py").exists()


def test_no_python_file_imports_the_fallback():
    # Only real references to the deleted module count: an import of
    # cli._fallback or one of its classes/functions. Docstring
    # mentions of the deleted filename (explaining R-009) and the
    # gateway's provider "fallback chain" are different concepts
    # and are allowed.
    import re

    pattern = re.compile(
        r"(from\s+cli\._fallback|import\s+cli\._fallback|"
        r"FallbackPolicy|FallbackRuntime|FallbackAuditLog|"
        r"fallback_get_tool|fallback_list_tools)")
    offenders = []
    for path in REPO_ROOT.rglob("*.py"):
        if "tests" in path.parts and path.name == "test_r009_no_fallback.py":
            continue
        if "__pycache__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if pattern.search(text):
            offenders.append(str(path.relative_to(REPO_ROOT)))
    assert offenders == []


def test_loaders_fail_loudly_when_modules_missing(tmp_path):
    # In-process simulation: block re-import of the real modules and
    # evict them from sys.modules, then restore everything.
    import importlib

    blocked = ("policy", "tools", "core")

    class Blocker:
        def find_spec(self, fullname, path=None, target=None):
            if fullname.split(".")[0] in blocked:
                raise ImportError(f"blocked for test: {fullname}")
            return None

    saved = {name: sys.modules.pop(name)
             for name in list(sys.modules)
             if name.split(".")[0] in blocked}
    blocker = Blocker()
    sys.meta_path.insert(0, blocker)
    try:
        with pytest.raises(PolicyUnavailable):
            get_policy_client(tmp_path)
        with pytest.raises(PolicyUnavailable):
            get_policy_engine(tmp_path)
        with pytest.raises(RuntimeUnavailable):
            get_runtime(tmp_path)
        with pytest.raises(RuntimeUnavailable):
            get_tools()
        with pytest.raises(PolicyUnavailable):
            get_audit_log(tmp_path)
    finally:
        sys.meta_path.remove(blocker)
        sys.modules.update(saved)
        importlib.invalidate_caches()


def _run_blocked_cli(argv):
    code = _BLOCKER.replace("__ARGV__", repr(list(argv)))
    return subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True,
        cwd=str(REPO_ROOT), timeout=60)


def test_cli_tools_list_fails_clearly_without_core_modules():
    proc = _run_blocked_cli(["tools", "list"])
    assert proc.returncode == 2
    assert "runtime unavailable" in proc.stderr
    assert "not installed" in proc.stderr
    assert "Traceback" not in proc.stderr
    assert "fallback" not in proc.stderr.lower()


def test_cli_tool_run_fails_clearly_without_core_modules():
    proc = _run_blocked_cli(
        ["tool", "run", "read_file",
         "--args-json", '{"path": "README.md"}'])
    assert proc.returncode == 2
    assert "not installed" in proc.stderr
    assert "Traceback" not in proc.stderr
    assert "fallback" not in proc.stderr.lower()
