# Build and Test Status

The source of truth for "what is built and what is tested". One row
per component. Status vocabulary, used exactly:

- **NOT STARTED** — no code exists.
- **BUILT (UNTESTED)** — code is merged, but no test run is recorded
  in `docs/test-results/`.
- **TESTED (LINUX)** — the component's tests were run on the Linux
  server and the run is recorded in `docs/test-results/`.
- **TESTED (WINDOWS)** — the component's tests were run on the
  Windows laptop and the run is recorded in `docs/test-results/`.
- **VERIFIED ON BOTH** — recorded runs on both, with no known gaps.
- **BLOCKED** — cannot be tested for a stated reason.

## Evidence rule

A "tested" claim must link to a results file in
`docs/test-results/`, produced by `evals/record_run.py`
(`python -m evals.record_run --by human` on the laptop,
`--by agent` on the server). A chat message saying "it passed" is
not evidence. Windows cells stay **NOT VERIFIED (awaiting human
run)** until a results file produced on the Windows laptop is
committed by the human. Windows success is never inferred from CI
or from code review.

## A note on the laptop reports in chat (read this before trusting the table)

Extensive laptop verification **was** reported in chat: all 9
`docs/WINDOWS_TESTING.md` checklist steps green on real Windows
(PRs #11–#19 live-verified, daemon start/status/stop, policyd
indicator, CLI-provider quoting, hostile-arg literal) and a
llama3.1:8b benchmark of 1.00 (7/7) on 2026-11-25. Under this
document's evidence rule those reports **do not count** — they are
not committed results files. That is deliberate: chat history is
not an auditable record, and the next person to read this table
cannot re-run a chat message. The Windows column therefore says
NOT VERIFIED everywhere until the human re-runs with
`evals/record_run.py --by human` and commits the file. This is not
a claim that the laptop work failed; it is a claim that the repo
does not yet hold the evidence.

## Component table

| Component | Built (merged PR and ADR) | Tested on Linux server (date, commit, result) | Tested on Windows laptop (date, commit, result) | CI | Known gaps and open risks (R-numbers) |
|---|---|---|---|---|---|
| Daemon | PR #2 | 2026-11-25, `918e521`, 658 passed / 1 skipped — [results](test-results/2026-11-25-linux-918e521.md). Tests: `test_runtime.py`, `test_daemon_transport.py`, `test_readonly.py`, `test_cli.py`. **TESTED (LINUX)** | 2026-11-26, `ab19d5e`, 656 passed / 24 failed / 26 skipped / 0 errors (full suite on PR #42 fix; Linux-only failures expected) + §10 live start/status/stop passed — [results](test-results/2026-11-26-windows-ab19d5e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | Daemon start/stop/status over the named pipe unverified on a real host (R-017) |
| Policyd | PR #2; ADR-001, ADR-002 | 2026-11-25, `1de2d8e`, 664 passed / 1 skipped — [results](test-results/2026-11-25-linux-1de2d8e.md). Tests: `test_policy.py`, `test_policyd_reachable.py`, `test_ensure_policyd.py`. **TESTED (LINUX)** | 2026-11-26, `ab19d5e`, 656 passed / 24 failed / 26 skipped / 0 errors (full suite on PR #42 fix; Linux-only failures expected) + §9 `tool run` & same-user pipe connect passed — [results](test-results/2026-11-26-windows-ab19d5e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | Different-user DACL negative check never run; same-user boundary residual (R-006, R-017) |
| Tools (22) | PR #2 | 2026-11-25, `2d7403f`, 634 passed / 1 skipped — [results](test-results/2026-11-25-linux-2d7403f.md). Tests: `test_tools.py`, `test_verify_list_processes.py`. **TESTED (LINUX)** | NOT VERIFIED (awaiting human run) | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | `process_info` / `launch_app` verify() are Linux-only (`/proc`) and fail on Windows; `screenshot` honestly unavailable on Windows (R-018) |
| Capability tokens | PR #2; ADR-006 (network flag, PR #5) | 2026-11-25, `2d7403f`, 634 passed / 1 skipped — [results](test-results/2026-11-25-linux-2d7403f.md). Tests: `test_policy.py`, `test_network_flag.py`. **TESTED (LINUX)** | NOT VERIFIED (awaiting human run) | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | No `apps` field, no app scoping (permission-spec F2); no signature on the token itself (R-014) |
| Taint tracking | PR #2 (basic mechanism); "hardened" is Phase 3, not done | 2026-11-25, `2d7403f`, 634 passed / 1 skipped — [results](test-results/2026-11-25-linux-2d7403f.md). Tests: `test_policy.py`, `test_approvals_scoped.py` (incidental coverage only). **TESTED (LINUX)** | NOT VERIFIED (awaiting human run) | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | No automatic taint marking (R-020); no dedicated taint test file |
| Audit log | PR #2 | 2026-11-25, `2d7403f`, 634 passed / 1 skipped — [results](test-results/2026-11-25-linux-2d7403f.md). Tests: `test_audit.py`, `test_audit_windows.py`. **TESTED (LINUX)** | NOT VERIFIED (awaiting human run) | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | No external anchor or signature — a same-user rewrite recomputes the chain (R-023, R-008) |
| Kill switch | PR #2 | 2026-11-25, `054a90b`, 644 passed / 1 skipped — [results](test-results/2026-11-25-linux-054a90b.md). Tests: `test_policy.py`, `test_runtime.py`. **TESTED (LINUX)** | 2026-11-26, `ab19d5e`, 656 passed / 24 failed / 26 skipped / 0 errors (full suite on PR #42 fix; Linux-only failures expected) + §10 kill/unkill passed — [results](test-results/2026-11-26-windows-ab19d5e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | No hotkey, tray, phone button or visible indicator; CLI `kill` and web UI kill need policyd running; see `docs/WINDOWS_TESTING.md` §10 |
| MCP server | PR #2 | 2026-11-25, `2d7403f`, 634 passed / 1 skipped — [results](test-results/2026-11-25-linux-2d7403f.md). Tests: `test_mcp.py`. **TESTED (LINUX)** | NOT VERIFIED (awaiting human run) | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | Tool definitions are not pinned/hashed; no MCP tool-poisoning defence (threat-model §4.6) |
| CLI | PR #2 | 2026-11-25, `2d7403f`, 634 passed / 1 skipped — [results](test-results/2026-11-25-linux-2d7403f.md). Tests: `test_cli.py`, `test_live_fixes.py`. **TESTED (LINUX)** | NOT VERIFIED (awaiting human run) | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | `policy approve` mints a fresh token; the approval only matches runs reusing its printed `token_id` |
| Model gateway | PR #4; ADR-004, ADR-007 | 2026-11-25, `0cc72af`, 638 passed / 1 skipped — [results](test-results/2026-11-25-linux-0cc72af.md). Tests: `test_gateway.py`, `test_gateway2.py`, `test_live_fixes.py`. **TESTED (LINUX)** | NOT VERIFIED (awaiting human run) | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | R-021 fixed: `Gateway.chat()` now enforces the cloud pre-approval gate like `complete()`/`escalate()`; sensitivity is decided by the gateway, not policyd (permission-spec F5) |
| CLI-model providers | PR #4; ADR-004, ADR-009 | 2026-11-25, `2d7403f`, 634 passed / 1 skipped — [results](test-results/2026-11-25-linux-2d7403f.md). Tests: `test_cli_providers.py`, `test_r010_r013.py`. **TESTED (LINUX)** | NOT VERIFIED (awaiting human run) | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | Built-in argv templates are plausible defaults, not verified against real CLI versions (R-010–R-012) |
| Hybrid routing | PR #4; ADR-004 | 2026-11-25, `0cc72af`, 638 passed / 1 skipped — [results](test-results/2026-11-25-linux-0cc72af.md). Tests: `test_gateway2.py`. **TESTED (LINUX)** | NOT VERIFIED (awaiting human run) | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | Cloud escalation needs a user-configured cloud provider (none by default) |
| Capability benchmark | PR #4 | 2026-11-25, `2d7403f`, 634 passed / 1 skipped — [results](test-results/2026-11-25-linux-2d7403f.md). Tests: `test_benchmark.py`, `test_evals.py`. **TESTED (LINUX)** | NOT VERIFIED (awaiting human run) | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | Text-only benchmark; vision not covered. Live-model result on the laptop (llama3.1:8b 1.00, 2026-11-25) is chat-reported only — no results file |
| Read-only mode | PR #4 | 2026-11-25, `2d7403f`, 634 passed / 1 skipped — [results](test-results/2026-11-25-linux-2d7403f.md). Tests: `test_readonly.py`. **TESTED (LINUX)** | NOT VERIFIED (awaiting human run) | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | None open |
| Web UI | PR #4; ADR-003, ADR-009 | 2026-11-25, `054a90b`, 644 passed / 1 skipped — [results](test-results/2026-11-25-linux-054a90b.md). Tests: `test_webui.py`. **TESTED (LINUX)** | 2026-11-26, `ab19d5e`, 656 passed / 24 failed / 26 skipped / 0 errors (full suite on PR #42 fix; Linux-only failures expected) + §10 login/logout/stop passed — [results](test-results/2026-11-26-windows-ab19d5e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | No Origin validation or rate limiting (R-025); session cookie has no `Secure` flag (deliberate — breaks login over plain loopback HTTP); see `docs/WINDOWS_TESTING.md` §10 |
| Linux adapter | PR #2; ADR-001 | 2026-11-25, `2d7403f`, 634 passed / 1 skipped — [results](test-results/2026-11-25-linux-2d7403f.md). Tests: `test_tools.py` (indirect coverage only). **TESTED (LINUX)** | NOT VERIFIED (awaiting human run) | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | No dedicated `test_linux_adapter.py`; Wayland not covered (xdg-desktop-portal) |
| Windows adapter | PR #7; ADR-008 | 2026-11-25, `2d7403f`, 634 passed / 1 skipped — [results](test-results/2026-11-25-linux-2d7403f.md). Tests: `test_windows_adapter.py`, `test_windows_wiring.py` (mock-based, run on Linux). **TESTED (LINUX)** | NOT VERIFIED (awaiting human run) | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | Live verification NOT VERIFIED (R-015, R-016, R-019); `process_info` / `launch_app` are Linux-shaped and fail cleanly on Windows |
| Named-pipe transport | PR #7 (client), PR #8 (server ACLs); ADR-008, ADR-010 | 2026-11-25, `1de2d8e`, 664 passed / 1 skipped — [results](test-results/2026-11-25-linux-1de2d8e.md). Tests: `test_windows_transport.py`, `test_windows_pipe_server.py`, `test_daemon_transport.py`, `test_policyd_reachable.py` (mock-based, run on Linux). **TESTED (LINUX)** | 2026-11-26, `ab19d5e`, 656 passed / 24 failed / 26 skipped / 0 errors (full suite on PR #42 fix; Linux-only failures expected) + §9/§10 live pipe checks passed — [results](test-results/2026-11-26-windows-ab19d5e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | DACL implemented-but-unverified on a real host (R-017); different-user negative check never run; ADR-010's honest limit stands; per-test pipe isolation added in PR #36 (mock-verified on Linux) — live Windows full-suite re-run still pending |
| Red-team suite | PR #2 (`evals/redteam.py`); updated PR #5 | 2026-11-25, `2d7403f`, 634 passed / 1 skipped — [results](test-results/2026-11-25-linux-2d7403f.md). Tests: `test_evals.py` wraps the suite; `evals/redteam.py` run directly the same day: 8/8 blocked. **TESTED (LINUX)** | NOT VERIFIED (awaiting human run) | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | 8 cases only — no skills, remote/IPC auth, supply-chain, secrets-in-logs, approval-forgery, audit-tampering or kill-switch case (threat-model §5, gap 12) |
| CI | PR #3 | **BUILT (UNTESTED)** — CI runs are observed on GitHub, not recorded by `record_run.py`. Latest main run #38 (`48be2ef`) completed in 52s; its conclusion could not be confirmed from the Actions list text. | NOT VERIFIED (awaiting human run) — no Windows job exists | One job (`test`) on ubuntu-latest, Python 3.12, `pytest -q`; no Windows job; no lint, typecheck, license or secret scan | No Windows job (proposed in the process-rules PR — see AGENTS.md rule added there); CI does not implement the SPEC §17.7 gates |
| Orchestrator (Phase 3) | ADR-011; this PR | 2026-11-26, `3d1917f`, 705 passed / 1 skipped — [results](test-results/2026-11-26-linux-3d1917f.md). Tests: `test_orchestrator.py` (mock gateway + fake runtime; one real-Runtime integration test). **TESTED (LINUX)** | 2026-11-26, `ab19d5e`, 656 passed / 24 failed / 26 skipped / 0 errors; `test_orchestrator.py`: 31/31 passed — [results](test-results/2026-11-26-windows-ab19d5e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | Decomposition JSON schema unproven against real architect models (strict parser + deterministic fallback); no live Windows run (mock/Linux only); R-026–R-028 mitigations land here, risks stay Open until review |
| Window control (Phase 3) | ADR-012; this PR | 2026-11-26, `ec21541`, 768 passed / 1 skipped — [results](test-results/2026-11-26-linux-ec21541.md). Tests: `test_window_control.py` 63 passed (fake AT-SPI + fake X11 + fake PowerShell runner for UIA; 3 live AT-SPI tests pass when the Xvfb stack is present, skip cleanly when it is missing). **TESTED (LINUX)** | NOT VERIFIED (awaiting human run) — UIA backend built, mock-tested on Linux only (fake PowerShell runner); live Windows run pending | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | AT-SPI discovers windows/bounds; activation is EWMH `_NET_ACTIVE_WINDOW` via libX11 (`grab_focus` is NotSupported on toplevel frames — verified live); active is read from the WM, STATE_ACTIVE is only the no-X fallback; no X display → focus returns False; libatspi init never recovers in-process after a failure (daemon restart needed); UIA scripts never run on real Windows yet — `SetFocus` on toplevel windows, the foreground re-check, and `ConvertTo-Json` edge cases are unverified; UIA `available()` probe is cached per process |

## Not started

Every roadmap item with no code yet (SPEC §15, ARCHITECTURE.md).
Each entry names the source and the evidence of absence.

- **Phone remote (task mode)** — SPEC §15 Phase 3, ARCHITECTURE.md §7.
  `remote/` contains only a README; no relay, pairing, QR,
  Noise/mTLS or phone code (R-004).
- **Skills system (manifests + signing)** — SPEC §15 Phase 3,
  ARCHITECTURE.md §8. `skills/` contains only a README; no manifest
  loader, signer, verifier or sandbox runner (R-002).
- **Scheduler** — SPEC §15 Phase 3, §12. No scheduler module, class
  or job store in the repo.
- **Workflow recorder / workflow-to-script compiler** — SPEC §15
  Phase 3, §11. No recording, replay or compiler code.
- **macOS adapter** — SPEC §15 Phase 4. `adapters/macos/` is empty.
- **Browser adapter** — ARCHITECTURE.md §4. `adapters/browser/` is
  empty; no Playwright/DOM code.
- **Voice** — SPEC §15 Phase 4, §12. No Whisper.cpp/Piper/wake-word/
  push-to-talk code.
- **Tauri desktop UI** — SPEC §15 Phase 2, deferred by ADR-003. No
  Tauri/Rust/Node code anywhere in the repo.
- **Live view** — SPEC §15 Phase 4, §9. No WebRTC/streaming code.
- **Public skill registry** — SPEC §15 Phase 5. No registry code,
  tiers or publishing (R-002).
- **SDK** — SPEC §15 Phase 5. No `sdk/` directory or SDK package.
- **Multi-user** — SPEC §8.5. No accounts, per-user pools/keys,
  roles or metering code.
- **Screen privacy (block/blur sensitive windows)** — ARCHITECTURE.md
  §5. No code (R-018).
- **Sandboxed workers** — ARCHITECTURE.md §2/§5. Tools execute
  in-process in the runtime/daemon; no worker processes, no sandbox.
- **OS keychain secrets** — SPEC §5.2, ARCHITECTURE.md §5. No
  keychain code; gateway keys come from env vars at call time
  (R-024).
- **Global hotkey / tray / phone kill surfaces, visible indicator**
  — ARCHITECTURE.md §5. CLI + web UI + policyd/daemon ops only.
- **Vision benchmark** — `docs/GATEWAY.md`. The capability
  benchmark is text-only.
- **CI lint / typecheck / license / secret scans** — SPEC §17.7,
  AGENTS.md §6. CI runs `pytest -q` only.
- **Windows CI job** — proposed in the process-rules PR, not yet
  merged.

## How to update this file

1. Run the suite with `python -m evals.record_run --by human` (or
   `--by agent` on the server) and commit the results file.
2. Change the row's Linux or Windows cell to link that file, with
   the date, commit and result.
3. Never write TESTED (WINDOWS), VERIFIED ON BOTH or a "verified"
   claim without the linked results file. If the run failed, record
   the failure and mark the row BLOCKED with the reason.
4. Every PR that runs tests must update this file (see AGENTS.md).
