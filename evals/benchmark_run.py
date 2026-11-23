"""Run the capability benchmark (SPEC section 8.3) against a mock provider.

No live LLM, Ollama, or cloud key is used: the demo providers below are
deterministic callables, so the run is reproducible anywhere.

  python evals/benchmark_run.py            # good mock  -> profile "full"
  python evals/benchmark_run.py --bad      # bad mock   -> profile "safe tasks only"
  python evals/benchmark_run.py --json     # machine-readable report

Exit code is 0 when the total score is >= 0.5 (profile "supervised" or
"full"), 1 otherwise -- so a bad provider fails the run, like the other
suites in this directory.
"""

from __future__ import annotations

import argparse
import itertools
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.benchmark import run_benchmark  # noqa: E402


def good_mock_provider(prompt: str) -> str:
    """Deterministic mock that follows instructions and answers correctly.

    Keyword-matched on the benchmark prompts in core/benchmark.py; a real
    provider is expected to do the same work from the prompt text alone.
    """
    p = prompt.lower()
    if "exactly the word blue" in p:
        return "BLUE"
    if "name of the user's dog" in p:
        return "Milo"
    if "capital of france" in p:
        return "Paris"
    if "17 + 25" in p:
        return "42"
    if "file_create" in p:
        return ('{"tool": "file_create", "arguments": '
                '{"path": "/tmp/notes.txt", "content": "hello"}}')
    if '"name"' in p and "json object" in p:
        return '{"name": "Asha", "age": 30, "city": "Pune"}'
    if "numbered list of steps" in p:
        return (
            "1. Create a subfolder for each file type.\n"
            "2. Move each file into the folder for its type.\n"
            "3. Sort the remaining files and rename any duplicates."
        )
    return "I don't know."


def bad_mock_provider(prompt: str) -> str:
    """Deliberately bad provider: different garbage on every call.

    Fails every test, including consistency (the two repeat calls disagree).
    """
    n = next(bad_mock_provider._counter)
    return f"!!! garbage output {n} ???"


bad_mock_provider._counter = itertools.count(1)  # type: ignore[attr-defined]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bad", action="store_true",
                        help="run against the bad mock provider instead")
    parser.add_argument("--json", action="store_true",
                        help="print the JSON report instead of the text report")
    parser.add_argument("--name", default=None,
                        help="provider name shown in the report")
    args = parser.parse_args(argv)

    if args.bad:
        call = bad_mock_provider
        name = args.name or "bad-mock"
    else:
        call = good_mock_provider
        name = args.name or "good-mock"

    report = run_benchmark(call, name=name)
    print(report.to_json() if args.json else report.to_text())
    return 0 if report.total_score >= 0.5 else 1


if __name__ == "__main__":
    raise SystemExit(main())
