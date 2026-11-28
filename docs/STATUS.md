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
cannot re-run a chat message. The Windows column said NOT VERIFIED everywhere until the human
re-ran with `evals/record_run.py --by human` and committed the
files (2026-11-27 and 2026-11-28); rows now link those files. This is not
a claim that the laptop work failed; it is a claim that the repo
does not yet hold the evidence.

## Component table

| Component | Built (merged PR and ADR) | Tested on Linux server (date, commit, result) | Tested on Windows laptop (date, commit, result) | CI | Known gaps and open risks (R-numbers) |
|---|---|---|---|---|---|
| Daemon | PR #2 | 2026-11-25, `918e521`, 658 passed / 1 skipped — [results](test-results/2026-11-25-linux-918e521.md). Tests: `test_runtime.py`, `test_daemon_transport.py`, `test_readonly.py`, `test_cli.py`. **TESTED (LINUX)** | 2026-11-28, `5c83c2e`, full suite: 712 passed / 40 failed / 32 skipped / 0 errors; `test_runtime.py::test_daemon_status_list_tools_and_policyd_unavailable` failed. Prior §10 live start/status/stop & Node pipe status checks passed — [results](test-results/2026-11-28-windows-5c83c2e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | Daemon start/stop/status over the named pipe unverified on a real host (R-017) |
| Policyd | PR #2; ADR-001, ADR-002 | 2026-11-25, `1de2d8e`, 664 passed / 1 skipped — [results](test-results/2026-11-25-linux-1de2d8e.md). Tests: `test_policy.py`, `test_policyd_reachable.py`, `test_ensure_policyd.py`. **TESTED (LINUX)** | 2026-11-28, `5c83c2e`, full suite: 712 passed / 40 failed / 32 skipped / 0 errors; failures included `test_policy.py`, `test_policyd_reachable.py`, and `test_r006_permissions.py`. Note: 16 of the 40 failures are new vs 002087e and cluster in tests that assume policyd/daemon absent (test_cli.py, test_policyd_reachable.py, test_doctor_windows.py) — the live daemon (pid 2648) and possible orphans from an interrupted first run were up during the suite, so the count is likely contaminated; a clean re-run with the daemon stopped is pending. Prior §9 `tool run` & same-user pipe connect checks passed — [results](test-results/2026-11-28-windows-5c83c2e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | Different-user DACL negative check never run; same-user boundary residual (R-006, R-017) |
| Tools (22) | PR #2 | 2026-11-25, `2d7403f`, 634 passed / 1 skipped — [results](test-results/2026-11-25-linux-2d7403f.md). Tests: `test_tools.py`, `test_verify_list_processes.py`. **TESTED (LINUX)** | 2026-11-28, `5c83c2e`, full suite: 712 passed / 40 failed / 32 skipped / 0 errors; `test_tools.py`: 2 failed (`test_symlink_escape_denied` — WinError 1314, needs SeCreateSymbolicLinkPrivilege; `test_list_dir_and_verify` — known leftover) — [results](test-results/2026-11-28-windows-5c83c2e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | `process_info` / `launch_app` verify() are Linux-only (`/proc`) and fail on Windows; `screenshot` honestly unavailable on Windows (R-018) |
| Capability tokens | PR #2; ADR-006 (network flag, PR #5) | 2026-11-25, `2d7403f`, 634 passed / 1 skipped — [results](test-results/2026-11-25-linux-2d7403f.md). Tests: `test_policy.py`, `test_network_flag.py`. **TESTED (LINUX)** | 2026-11-28, `5c83c2e`, full suite: 712 passed / 40 failed / 32 skipped / 0 errors; `test_policy.py`: 5 failed (2× 0600, 2× symlink, `test_client_unavailable_when_no_daemon`); `test_network_flag.py`: 2 failed (`test_cli_token_issue_network_flag`, `test_cli_network_tool_allowed_with_flag`) — [results](test-results/2026-11-28-windows-5c83c2e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | No `apps` field, no app scoping (permission-spec F2); no signature on the token itself (R-014) |
| Taint tracking | PR #2 (basic mechanism); "hardened" is Phase 3, not done | 2026-11-25, `2d7403f`, 634 passed / 1 skipped — [results](test-results/2026-11-25-linux-2d7403f.md). Tests: `test_policy.py`, `test_approvals_scoped.py` (incidental coverage only). **TESTED (LINUX)** | 2026-11-28, `5c83c2e`, full suite: 712 passed / 40 failed / 32 skipped / 0 errors; `test_policy.py`: 5 failed (2× 0600, 2× symlink, `test_client_unavailable_when_no_daemon`); `test_approvals_scoped.py`: no failures — [results](test-results/2026-11-28-windows-5c83c2e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | No automatic taint marking (R-020); no dedicated taint test file |
| Audit log | PR #2 | 2026-11-25, `2d7403f`, 634 passed / 1 skipped — [results](test-results/2026-11-25-linux-2d7403f.md). Tests: `test_audit.py`, `test_audit_windows.py`. **TESTED (LINUX)** | 2026-11-28, `5c83c2e`, full suite: 712 passed / 40 failed / 32 skipped / 0 errors; `test_audit.py::test_concurrent_appends_from_two_processes_keep_chain` and `test_audit_windows.py::test_real_module_restored_after_blocked_imports` failed (known leftovers) — [results](test-results/2026-11-28-windows-5c83c2e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | No external anchor or signature — a same-user rewrite recomputes the chain (R-023, R-008) |
| Kill switch | PR #2 | 2026-11-25, `054a90b`, 644 passed / 1 skipped — [results](test-results/2026-11-25-linux-054a90b.md). Tests: `test_policy.py`, `test_runtime.py`. **TESTED (LINUX)** | 2026-11-28, `5c83c2e`, full suite: 712 passed / 40 failed / 32 skipped / 0 errors; `test_cli.py::test_kill_blocks_tool_run_and_unkill_restores` failed. Prior §10 kill/unkill live check passed — [results](test-results/2026-11-28-windows-5c83c2e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | No hotkey, tray, phone button or visible indicator; CLI `kill` and web UI kill need policyd running; see `docs/WINDOWS_TESTING.md` §10 |
| MCP server | PR #2 | 2026-11-25, `2d7403f`, 634 passed / 1 skipped — [results](test-results/2026-11-25-linux-2d7403f.md). Tests: `test_mcp.py`. **TESTED (LINUX)** | 2026-11-28, `5c83c2e`, full suite: 712 passed / 40 failed / 32 skipped / 0 errors; `test_mcp.py`: no failures — [results](test-results/2026-11-28-windows-5c83c2e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | Tool definitions are not pinned/hashed; no MCP tool-poisoning defence (threat-model §4.6) |
| CLI | PR #2 | 2026-11-25, `2d7403f`, 634 passed / 1 skipped — [results](test-results/2026-11-25-linux-2d7403f.md). Tests: `test_cli.py`, `test_live_fixes.py`. **TESTED (LINUX)** | 2026-11-28, `5c83c2e`, full suite: 712 passed / 40 failed / 32 skipped / 0 errors; `test_cli.py`: 9 failed — 8 in the new no-daemon-assumption cluster (see the Policyd row note) plus `test_terminate_pid_posix_sigkill_when_stubborn` (POSIX SIGKILL case) — [results](test-results/2026-11-28-windows-5c83c2e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | `policy approve` mints a fresh token; the approval only matches runs reusing its printed `token_id` |
| Model gateway | PR #4; ADR-004, ADR-007 | 2026-11-25, `0cc72af`, 638 passed / 1 skipped — [results](test-results/2026-11-25-linux-0cc72af.md). Tests: `test_gateway.py`, `test_gateway2.py`, `test_live_fixes.py`. **TESTED (LINUX)** | 2026-11-28, `5c83c2e`, full suite: 712 passed / 40 failed / 32 skipped / 0 errors; `test_gateway.py`, `test_gateway2.py`: no failures — [results](test-results/2026-11-28-windows-5c83c2e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | R-021 fixed: `Gateway.chat()` now enforces the cloud pre-approval gate like `complete()`/`escalate()`; sensitivity is decided by the gateway, not policyd (permission-spec F5) |
| CLI-model providers | PR #4; ADR-004, ADR-009 | 2026-11-25, `2d7403f`, 634 passed / 1 skipped — [results](test-results/2026-11-25-linux-2d7403f.md). Tests: `test_cli_providers.py`, `test_r010_r013.py`. **TESTED (LINUX)** | 2026-11-28, `5c83c2e`, full suite: 712 passed / 40 failed / 32 skipped / 0 errors; `test_cli_providers.py`, `test_r010_r013.py`: no failures — [results](test-results/2026-11-28-windows-5c83c2e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | Built-in argv templates are plausible defaults, not verified against real CLI versions (R-010–R-012) |
| Hybrid routing | PR #4; ADR-004 | 2026-11-25, `0cc72af`, 638 passed / 1 skipped — [results](test-results/2026-11-25-linux-0cc72af.md). Tests: `test_gateway2.py`. **TESTED (LINUX)** | 2026-11-28, `5c83c2e`, full suite: 712 passed / 40 failed / 32 skipped / 0 errors; `test_gateway2.py`: no failures — [results](test-results/2026-11-28-windows-5c83c2e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | Cloud escalation needs a user-configured cloud provider (none by default) |
| Capability benchmark | PR #4 | 2026-11-25, `2d7403f`, 634 passed / 1 skipped — [results](test-results/2026-11-25-linux-2d7403f.md). Tests: `test_benchmark.py`, `test_evals.py`. **TESTED (LINUX)** | 2026-11-28, `5c83c2e`, full suite: 712 passed / 40 failed / 32 skipped / 0 errors; `test_evals.py::test_task_suite_all_pass` failed (asserts the whole suite passes, so it fails while any test fails); `test_benchmark.py`: no failures — [results](test-results/2026-11-28-windows-5c83c2e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | Text-only benchmark; vision not covered. Live-model result on the laptop (llama3.1:8b 1.00, 2026-11-25) is chat-reported only — no results file |
| Read-only mode | PR #4 | 2026-11-25, `2d7403f`, 634 passed / 1 skipped — [results](test-results/2026-11-25-linux-2d7403f.md). Tests: `test_readonly.py`. **TESTED (LINUX)** | 2026-11-28, `5c83c2e`, full suite: 712 passed / 40 failed / 32 skipped / 0 errors; `test_readonly.py::test_readonly_persists_across_engine_restart` failed (known leftover) — [results](test-results/2026-11-28-windows-5c83c2e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | None open |
| Web UI | PR #4; ADR-003, ADR-009 | 2026-11-27, `5004c60`, 788 passed / 4 skipped — [results](test-results/2026-11-27-linux-5004c60.md). Tests: `test_webui.py` (31 tests incl. 8 new: Origin allowlist + login rate limiting). **TESTED (LINUX)** | 2026-11-28, `5c83c2e`, full suite: 712 passed / 40 failed / 32 skipped / 0 errors; `test_benchmark_endpoint_returns_report` and `test_backend_status_falls_back_when_policyd_down` failed. Prior §10 login/logout/stop checks passed — [results](test-results/2026-11-28-windows-5c83c2e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | R-025 mitigated in this branch (Origin allowlist on POSTs + login rate limiting, 5 per 15 min; see `docs/threat-model.md` §4.3); session cookie has no `Secure` flag (deliberate — breaks login over plain loopback HTTP); see `docs/WINDOWS_TESTING.md` §10 |
| Linux adapter | PR #2; ADR-001 | 2026-11-25, `2d7403f`, 634 passed / 1 skipped — [results](test-results/2026-11-25-linux-2d7403f.md). Tests: `test_tools.py` (indirect coverage only). **TESTED (LINUX)** | 2026-11-28, `5c83c2e`, full suite: 712 passed / 40 failed / 32 skipped / 0 errors; `test_tools.py` (indirect coverage only): 2 failed — the same symlink + `list_dir_and_verify` failures as the Tools row — [results](test-results/2026-11-28-windows-5c83c2e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | No dedicated `test_linux_adapter.py`; Wayland not covered (xdg-desktop-portal) |
| Windows adapter | PR #7; ADR-008 | 2026-11-25, `2d7403f`, 634 passed / 1 skipped — [results](test-results/2026-11-25-linux-2d7403f.md). Tests: `test_windows_adapter.py`, `test_windows_wiring.py` (mock-based, run on Linux). **TESTED (LINUX)** | 2026-11-28, `5c83c2e`, full suite: 712 passed / 40 failed / 32 skipped / 0 errors; `test_windows_adapter.py`, `test_windows_wiring.py`: no failures — [results](test-results/2026-11-28-windows-5c83c2e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | Live verification NOT VERIFIED (R-015, R-016, R-019); `process_info` / `launch_app` are Linux-shaped and fail cleanly on Windows |
| Named-pipe transport | PR #7 (client), PR #8 (server ACLs); ADR-008, ADR-010 | 2026-11-28, `8ece1e9`, 802 passed / 4 skipped — [results](test-results/2026-11-28-linux-8ece1e9.md). Tests: `test_windows_transport.py`, `test_windows_pipe_server.py` (new: 11 tests driving the real `_CtypesWindowsPipeApi` against a scripted windll — `ERROR_PIPE_CONNECTED` counts as connected, real error codes surface, overlapped read/write), `test_daemon_transport.py`, `test_policyd_reachable.py` (mock-based, run on Linux). **TESTED (LINUX)** | 2026-11-28, `5c83c2e`, full suite: 712 passed / 40 failed / 32 skipped / 0 errors; `test_unix_client_unavailable_without_server` and `test_named_pipe_client_selected_on_windows` failed. Prior §9/§10 & Node `client.js` live pipe checks passed — [results](test-results/2026-11-28-windows-5c83c2e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | DACL implemented-but-unverified on a real host (R-017); different-user negative check never run; ADR-010's honest limit stands; per-test pipe isolation added in PR #36 (mock-verified on Linux); live concurrent-status check 2026-11-28 FAILED — daemon + policyd crashed on `ConnectNamedPipe` (Win32 error 0); fixed in this branch (`use_last_error=True` + `FILE_FLAG_OVERLAPPED`, 11 new tests) — laptop re-check pending; instance cap is now 8 (was 1) for thread-per-connection — the single-daemon guarantee rests on the reachable probe + daemon.pid check, see threat-model.md (R-017) |
| Red-team suite | PR #2 (`evals/redteam.py`); updated PR #5 | 2026-11-25, `2d7403f`, 634 passed / 1 skipped — [results](test-results/2026-11-25-linux-2d7403f.md). Tests: `test_evals.py` wraps the suite; `evals/redteam.py` run directly the same day: 8/8 blocked. **TESTED (LINUX)** | 2026-11-28, `5c83c2e`, full suite: 712 passed / 40 failed / 32 skipped / 0 errors; `test_evals.py::test_redteam_all_blocked` passed; `test_task_suite_all_pass` failed (asserts the whole suite passes) — [results](test-results/2026-11-28-windows-5c83c2e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | 8 cases only — no skills, remote/IPC auth, supply-chain, secrets-in-logs, approval-forgery, audit-tampering or kill-switch case (threat-model §5, gap 12) |
| CI | PR #3 | **BUILT (UNTESTED)** — CI runs are observed on GitHub, not recorded by `record_run.py`. Two jobs exist (`test` on ubuntu-latest, `test-windows`); both completed success on PR #54 head `8d6444ce` (checked 2026-11-28). The merge commit's run conclusion was not confirmed (GitHub API rate-limited). | A `test-windows` job exists and completed success on PR #54 head `8d6444ce` (checked 2026-11-28); the merge commit's run conclusion was not confirmed. | Two jobs (`test` on ubuntu-latest, `test-windows`); no lint, typecheck, license or secret scan | CI does not implement the SPEC §17.7 gates (lint, typecheck, license, secret scans) |
| Orchestrator (Phase 3) | ADR-011; this PR | 2026-11-28, `80b6bb9`, 792 passed / 1 skipped — [results](test-results/2026-11-28-linux-80b6bb9.md). Tests: `test_orchestrator.py` (mock gateway + fake runtime; one real-Runtime integration test; new `test_no_provider_run_is_bounded` — no-provider run finishes in ~2x timeout) + `test_daemon_orchestrator.py` (daemon ops `orchestrator_run`/`orchestrator_status`/`orchestrator_retry` over a scripted gateway + real Runtime + allow-all fake policy client). **TESTED (LINUX)** | 2026-11-28, `5c83c2e`, full suite: 712 passed / 40 failed / 32 skipped / 0 errors; neither `test_orchestrator.py` nor `test_daemon_orchestrator.py` appears among failures — [results](test-results/2026-11-28-windows-5c83c2e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | Decomposition JSON schema unproven against real architect models (strict parser + deterministic fallback); no live Windows run (mock/Linux only); R-026–R-028 mitigations land here, risks stay Open until review; daemon ops are synchronous (each connection runs in its own thread) — no async/polling yet; the IDE-facing API + VS Code client are documented in `docs/IDE_API.md` and shipped in `extensions/vscode/` (see the row below) |
| Window control (Phase 3) | ADR-012; this PR | 2026-11-27, `0364986`, 783 passed / 1 skipped — [results](test-results/2026-11-27-linux-0364986.md). Tests: `test_window_control.py` 65 passed (fake AT-SPI + fake X11 + fake PowerShell runner for UIA; 3 live AT-SPI tests pass when the Xvfb stack is present, skip cleanly when it is missing). **TESTED (LINUX)** | 2026-11-28, `5c83c2e`, full suite: 712 passed / 40 failed / 32 skipped / 0 errors; `test_window_control.py`: 0 failed, 6 skipped. Live on the real desktop 2026-11-27 (after PR #53): `list_windows` returns 7 windows (Notepad `uia:919770`, Calculator `uia:526604`); `window_focus` on `uia:919770` and `uia:526604` both returned `ok=true, verified=true`; negative check `window_focus("99999999")` cleanly returned `ok=false` — [results](test-results/2026-11-28-windows-5c83c2e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job | AT-SPI discovers windows/bounds; activation is EWMH `_NET_ACTIVE_WINDOW` via libX11 (`grab_focus` is NotSupported on toplevel frames — verified live); active is read from the WM, STATE_ACTIVE is only the no-X fallback; no X display → focus returns False; libatspi init never recovers in-process after a failure (daemon restart needed); UIA list script runs on real Windows (PR #52 fixed `$pid`); focus now uses Win32 `SetForegroundWindow` + `ShowWindow(SW_RESTORE)` after UIA `SetFocus` proved unusable on real top-level windows (2026-11-27); UIA `available()` probe is cached per process |
| IDE API + VS Code extension (Phase 3) | ADR-011 (d); this PR | 2026-11-27, `56eef83`, 780 passed / 4 skipped — [results](test-results/2026-11-27-linux-56eef83.md). Tests: `test_ide_api_doc.py` (every op in `docs/IDE_API.md` exists in `Daemon.handle_request`; worked example end to end) + Node `extensions/vscode/test/client.test.js` (12 tests, fake daemon on the platform transport; 12/12 pass on Linux). **TESTED (LINUX)** | 2026-11-28, `5c83c2e`, full suite: 712 passed / 40 failed / 32 skipped / 0 errors; `test_ide_api_doc.py` was not among failures. Prior Node `client.js` named-pipe checks (`daemonStatus`, `orchestratorRun`, `orchestratorStatus`) over `\\.\pipe\opencobot-daemon` succeeded (run `428d6eafe1b0` queued with `no provider available or budget exceeded`), VS Code extension GUI verified live 2026-11-28 on the real desktop: extension v0.1.0 installed, `runTask` 'List the files in the workspace root and report their names.' completed server-side as run `fe28a423da28` (queued: 'no provider available or budget exceeded'), and `Show last orchestrator run` displayed the full summary (`ok=false`, queued: the task). Node `client.test.js` harness fix in this branch (fake daemon on the platform transport via `OPENCOBOT_DAEMON_ADDRESS`; 12/12 on Linux) — laptop Windows run pending — [results](test-results/2026-11-28-windows-5c83c2e.md). **TESTED (WINDOWS)** | ubuntu-latest, Python 3.12, `pytest -q`; no Windows job; Node 24 `node --test` for the client | The VS Code extension is a thin client over the documented daemon protocol (no model calls, no file writes, no policy decisions in the client); any IDE can port `client.js`. `orchestrator_run` is synchronous — clients must use a long timeout and never retry on timeout. |

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
