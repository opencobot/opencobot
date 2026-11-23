# adapters/windows/

Windows adapter — **stub only in Phase 1** (ADR-001, Linux-first MVP).

`stub.py` provides a `WindowsAdapter` whose methods raise `NotImplementedError`. It exists so the tool interface stays the same when the Windows implementation lands; no Windows UI Automation code is attempted on Linux.
