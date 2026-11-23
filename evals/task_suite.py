"""OpenCobot Phase 1 task suite (SPEC §13).

Verifies REAL system state on Linux: every task runs through the real
Runtime + PolicyEngine + tool registry in a temporary directory and checks
the filesystem afterwards. Run directly::

    python evals/task_suite.py [--workdir DIR]

or import :func:`run_suite` from tests. Exits 0 only if every task passes.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.runtime import Runtime  # noqa: E402
from policy.engine import PolicyEngine  # noqa: E402
from tools.definitions import TOOLS  # noqa: E402


def _setup(workdir: Path):
    state_dir = workdir / ".opencobot-state"
    state_dir.mkdir(parents=True, exist_ok=True)
    engine = PolicyEngine(state_dir)
    runtime = Runtime(state_dir, engine, TOOLS)
    token = engine.issue_token(
        scope_folders=[str(workdir)], tools=["*"], duration_seconds=600
    )
    return engine, runtime, token


def _run(runtime, token, name, args, tainted=False):
    return runtime.run_tool(token, name, args, tainted=tainted)


def run_suite(workdir: Path | None = None) -> list[dict]:
    """Run the task suite in a fresh temp dir (or the given one)."""
    own_dir = workdir is None
    workdir = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="opencobot-eval-"))
    results: list[dict] = []

    def check(name: str, ok: bool, evidence: str = "") -> None:
        results.append({"task": name, "passed": bool(ok), "evidence": evidence})

    try:
        engine, runtime, token = _setup(workdir)

        # 1. Create a file (L2) and verify its content on disk.
        r = _run(runtime, token, "create_file",
                 {"path": "notes.txt", "content": "hello opencobot\n"})
        check("create_file", r["ok"] and r["verified"]
              and (workdir / "notes.txt").read_text() == "hello opencobot\n",
              str(r.get("evidence", "")))

        # 2. Rename it with move_file (L2) and verify real state.
        r = _run(runtime, token, "move_file",
                 {"source": "notes.txt", "destination": "renamed.txt"})
        check("rename_file", r["ok"] and r["verified"]
              and (workdir / "renamed.txt").exists()
              and not (workdir / "notes.txt").exists())

        # 3. Organise a folder: create dir + move files into it.
        (workdir / "a.txt").write_text("a")
        (workdir / "b.txt").write_text("b")
        _run(runtime, token, "mkdir", {"path": "sorted"})
        r1 = _run(runtime, token, "move_file",
                  {"source": "a.txt", "destination": "sorted/a.txt"})
        r2 = _run(runtime, token, "move_file",
                  {"source": "b.txt", "destination": "sorted/b.txt"})
        check("organize_folder", r1["ok"] and r2["ok"]
              and (workdir / "sorted" / "a.txt").exists()
              and (workdir / "sorted" / "b.txt").exists())

        # 4. git status on a real repo (L0, read-only).
        subprocess.run(["git", "init", "-q", str(workdir / "repo")],
                       check=True, timeout=30)
        subprocess.run(["git", "-C", str(workdir / "repo"), "config",
                        "user.email", "eval@opencobot.local"], check=True, timeout=30)
        subprocess.run(["git", "-C", str(workdir / "repo"), "config",
                        "user.name", "eval"], check=True, timeout=30)
        (workdir / "repo" / "f.txt").write_text("x")
        r = _run(runtime, token, "git_status", {"path": "repo"})
        check("git_status", r["ok"] and r["verified"]
              and "f.txt" in str(r["result"].get("data", {})),
              str(r["result"].get("data", {}))[:200])

        # 5. Blocked delete: delete_to_trash (L3) without approval must fail.
        (workdir / "important.txt").write_text("do not delete")
        r = _run(runtime, token, "delete_to_trash", {"path": "important.txt"})
        check("blocked_delete_without_approval",
              (not r["ok"]) and r["decision"].get("needs_approval") is True
              and (workdir / "important.txt").exists(),
              str(r["decision"].get("reason", "")))

        # 6. Approved workflow: approve, then the same delete succeeds and
        #    the file is in the trash (not hard-deleted).
        engine.approve(token.token_id, "delete_to_trash", 3,
                 {"path": "important.txt"}, duration_seconds=600)
        r = _run(runtime, token, "delete_to_trash", {"path": "important.txt"})
        trash = list((workdir / ".opencobot-state" / "trash").rglob("*important*"))
        check("approved_delete_to_trash",
              r["ok"] and r["verified"]
              and not (workdir / "important.txt").exists()
              and len(trash) > 0)

        # 7. Blocked shell: run_command (L3) without approval must fail.
        r = _run(runtime, token, "run_command",
                 {"argv": ["python3", "-c", "print(42)"]})
        check("blocked_run_command_without_approval",
              (not r["ok"]) and r["decision"].get("needs_approval") is True)

        # 8. Approved shell runs and its output is captured and verified.
        engine.approve(token.token_id, "run_command", 3,
                 {"argv": ["python3", "-c", "print(42)"]}, duration_seconds=600)
        r = _run(runtime, token, "run_command",
                 {"argv": ["python3", "-c", "print(42)"]})
        check("approved_run_command",
              r["ok"] and "42" in str(r["result"].get("data", {})))
    finally:
        if own_dir:
            shutil.rmtree(workdir, ignore_errors=True)
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OpenCobot Phase 1 task suite")
    parser.add_argument("--workdir", default=None)
    args = parser.parse_args(argv)
    results = run_suite(Path(args.workdir) if args.workdir else None)
    failed = 0
    for item in results:
        status = "PASS" if item["passed"] else "FAIL"
        print(f"[{status}] {item['task']} {item['evidence']}")
        failed += 0 if item["passed"] else 1
    print(f"{len(results) - failed}/{len(results)} tasks passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
