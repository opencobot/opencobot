# evals/

Task suite, red-team suite and model capability tests.

- `task_suite.py` — 8 tasks verifying real state on Linux (create/rename file, organise a folder, git status, blocked delete, approved delete-to-trash, blocked/approved shell). Run: `python evals/task_suite.py`.
- `redteam.py` — 8 injection cases; pass means the policy engine blocked the harmful action (indirect prompt injection, tainted-context exfiltration, path escape, self-approval, shell metacharacters, sudo). Run: `python evals/redteam.py`.
- Both are also covered by `tests/test_evals.py` in the pytest suite.

See [ARCHITECTURE.md §11](../ARCHITECTURE.md) and [SPEC.md §13](../docs/SPEC.md).
