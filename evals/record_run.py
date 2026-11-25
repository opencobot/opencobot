"""Run the test suite and record the measured result.

Writes ``docs/test-results/<YYYY-MM-DD>-<os>-<shortsha>.md`` containing
only measured output: OS and version, Python version, git commit and
whether the tree was dirty, the exact command, pass/fail/skip counts,
the list of failed and skipped tests with reasons, duration, and who
ran it (``--by human`` or ``--by agent``).

Usage (from the repo root)::

    python -m evals.record_run --by human
    python -m evals.record_run --by agent -- -q -rf -rs tests/test_tools.py

The report is generated from the run. Do not hand-edit a results file;
re-run the tool to regenerate it. The tool exits with pytest's exit
code (0 = suite green).
"""

from __future__ import annotations

import argparse
import datetime
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RESULTS_DIR = REPO_ROOT / "docs" / "test-results"
DEFAULT_PYTEST_ARGS = ["-q", "-rs"]

_SUMMARY_RE = re.compile(
    r"^(?:=+ )?(?P<body>(?:\d+ (?:passed|failed|skipped|error|xfailed|xpassed|warnings?)(?:, )?)+)"
    r"(?: in (?P<seconds>[\d.]+)s)?",
    re.MULTILINE,
)
_COUNT_RE = re.compile(r"(\d+) (passed|failed|skipped|error|xfailed|xpassed)")


def os_token() -> str:
    """Short OS token for the results filename."""
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def git_info(repo_root: Path = REPO_ROOT) -> tuple[str, str]:
    """(short commit sha, dirty flag) for ``repo_root``.

    Returns ``("unknown", "unknown")`` when git is unavailable or the
    directory is not a repo — never raises, so the record stays honest
    about what it could not determine.
    """
    try:
        sha = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=repo_root, capture_output=True, text=True, timeout=30,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo_root, capture_output=True, text=True, timeout=30,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown", "unknown"
    if not sha:
        return "unknown", "unknown"
    return sha, ("dirty" if status else "clean")


def parse_pytest_output(text: str) -> dict:
    """Parse ``pytest -q`` output into measured counts and test lists.

    Returns a dict with ``passed``, ``failed``, ``skipped``, ``errors``,
    ``duration_seconds`` (float or None), ``summary_line`` (the final
    counts line, or ""), ``failed_tests``, ``skipped_tests`` and
    ``error_tests`` (verbatim ``FAILED``/``SKIPPED``/``ERROR`` lines
    from the short test summary info block), and ``raw_tail`` (the last
    20 lines, used when no summary line could be found).
    """
    lines = text.splitlines()
    summary_line = ""
    counts = {"passed": 0, "failed": 0, "skipped": 0, "errors": 0}
    duration: float | None = None
    for line in reversed(lines):
        if "passed" in line or "failed" in line or "error" in line:
            match = _SUMMARY_RE.search(line)
            if match:
                summary_line = line.strip()
                for number, kind in _COUNT_RE.findall(match.group("body")):
                    key = {"passed": "passed", "failed": "failed",
                           "skipped": "skipped", "error": "errors"}[kind]
                    counts[key] += int(number)
                if match.group("seconds"):
                    duration = float(match.group("seconds"))
                break
    summary_block: list[str] = []
    in_block = False
    for line in lines:
        if line.startswith("=") and "short test summary info" in line:
            in_block = True
            continue
        if in_block:
            if line.startswith(("FAILED", "SKIPPED", "ERROR", "XPASS", "XFAIL")):
                summary_block.append(line.strip())
            elif line.startswith("=") or line.strip() == "":
                if summary_block:
                    break
    return {
        "passed": counts["passed"],
        "failed": counts["failed"],
        "skipped": counts["skipped"],
        "errors": counts["errors"],
        "duration_seconds": duration,
        "summary_line": summary_line,
        "failed_tests": [l for l in summary_block if l.startswith("FAILED")],
        "skipped_tests": [l for l in summary_block if l.startswith("SKIPPED")],
        "error_tests": [l for l in summary_block if l.startswith("ERROR")],
        "raw_tail": lines[-20:],
    }


def build_report(
    *,
    parsed: dict,
    command: list[str],
    by: str,
    repo_root: Path = REPO_ROOT,
) -> str:
    """Render the markdown results file from a parsed pytest run."""
    sha, dirty = git_info(repo_root)
    date = datetime.date.today().isoformat()
    duration = parsed["duration_seconds"]
    duration_text = f"{duration:.2f}s" if duration is not None else "unknown"
    lines = [
        f"# Test results — {date} ({os_token()})",
        "",
        "Generated by `python -m evals.record_run` — measured output only.",
        "Do not hand-edit this file; re-run the tool to regenerate it.",
        "",
        "## Environment",
        "",
        f"- OS: {platform.platform()} ({sys.platform})",
        f"- Python: {sys.version.split()[0]} (`{sys.executable}`)",
        f"- Git commit: `{sha}` (tree: {dirty})",
        f"- Recorded by: {by}",
        "",
        "## Command",
        "",
        "```",
        " ".join(command),
        "```",
        "",
        "## Result",
        "",
        f"- Passed: {parsed['passed']}",
        f"- Failed: {parsed['failed']}",
        f"- Skipped: {parsed['skipped']}",
        f"- Errors: {parsed['errors']}",
        f"- Duration: {duration_text}",
        f"- Summary line: `{parsed['summary_line'] or 'not found in output'}`",
        "",
        "## Failed tests",
        "",
    ]
    if parsed["failed_tests"] or parsed["error_tests"]:
        for item in parsed["failed_tests"] + parsed["error_tests"]:
            lines.append(f"- `{item}`")
    else:
        lines.append("None.")
    lines += ["", "## Skipped tests (with reasons)", ""]
    if parsed["skipped_tests"]:
        for item in parsed["skipped_tests"]:
            lines.append(f"- `{item}`")
    else:
        lines.append("None.")
    if not parsed["summary_line"]:
        lines += ["", "## Raw output (tail — no summary line found)", "", "```"]
        lines += parsed["raw_tail"]
        lines.append("```")
    lines.append("")
    return "\n".join(lines)


def resolve_pytest_args(pytest_args: list[str] | None) -> list[str]:
    """Extra pytest args, defaulting to ``-q -rs``.

    Both ``None`` and an empty list mean "no extra args given", so both
    fall back to the defaults — an empty list must not silently drop
    ``-rs``, or skipped tests would be counted but never listed.
    """
    return list(pytest_args) if pytest_args else list(DEFAULT_PYTEST_ARGS)


def run_record(
    *,
    by: str,
    pytest_args: list[str] | None = None,
    output_dir: Path = DEFAULT_RESULTS_DIR,
    repo_root: Path = REPO_ROOT,
) -> tuple[Path, int]:
    """Run pytest, parse the output, write the results file.

    Returns ``(results_file_path, pytest_exit_code)``.
    """
    args = resolve_pytest_args(pytest_args)
    command = [sys.executable, "-m", "pytest", *args]
    started = time.monotonic()
    proc = subprocess.run(
        command, cwd=repo_root, capture_output=True, text=True, timeout=3600,
    )
    elapsed = time.monotonic() - started
    output = (proc.stdout or "") + (proc.stderr or "")
    parsed = parse_pytest_output(output)
    if parsed["duration_seconds"] is None:
        parsed["duration_seconds"] = elapsed
    sha, _dirty = git_info(repo_root)
    date = datetime.date.today().isoformat()
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{date}-{os_token()}-{sha}.md"
    path.write_text(build_report(parsed=parsed, command=command, by=by,
                                 repo_root=repo_root), encoding="utf-8")
    print(f"results file: {path}")
    print(f"summary: {parsed['summary_line'] or 'no summary line parsed'}"
          f" (exit code {proc.returncode})")
    return path, proc.returncode


def main(argv: list[str] | None = None) -> int:
    """CLI entry point: ``python -m evals.record_run --by human``."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--by", choices=["human", "agent"], default="agent",
                        help="who ran the suite (recorded in the file)")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_RESULTS_DIR,
                        help="where to write the results file")
    parser.add_argument("pytest_args", nargs="*", default=None,
                        help="extra args passed to pytest "
                             "(default: -q -rs)")
    args = parser.parse_args(argv)
    _path, returncode = run_record(
        by=args.by, pytest_args=args.pytest_args,
        output_dir=args.output_dir, repo_root=REPO_ROOT,
    )
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
