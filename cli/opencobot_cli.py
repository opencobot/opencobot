"""OpenCobot command-line client (Phase 1, Linux MVP).

Usage: ``python -m cli.opencobot_cli [--state-dir DIR] [--json] <command> ...``
or, once installed, ``opencobot [--state-dir DIR] [--json] <command> ...``.

Exit codes: 0 = ok (and, for ``tool run``, verified); 1 = the action
failed / was denied; 2 = usage error or policy unavailable.

Safety: the CLI never executes a tool itself — it issues a short-lived
capability token scoped to the working directory (plus any paths named
in ``--args-json``) and runs the tool through
``core.runtime.Runtime`` with the policy client. Level 3+ tools need an
explicit approval; without one the run is refused *before* execution.
The policyd auth secret is never printed.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

# Allow both `python -m cli.opencobot_cli` and `python cli/opencobot_cli.py`.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cli._compat import (  # noqa: E402
    PolicyUnavailable,
    RuntimeUnavailable,
    adapt_token_for_runtime,
    audit_read_last,
    audit_verify,
    call_approve,
    call_check,
    call_issue_token,
    default_state_dir,
    ensure_policyd,
    get_audit_log,
    get_policy_client,
    get_runtime,
    get_tool,
    get_tools,
    normalize_run_result,
    public_token_record,
    token_scope_folders,
)
from cli._fallback import FallbackPolicyEngine  # noqa: E402

__version__ = "0.1.0"


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _emit(payload, as_json, human_lines=None):
    if as_json:
        print(json.dumps(payload, indent=2, default=str))
    elif human_lines:
        for line in human_lines:
            print(line)
    else:
        print(json.dumps(payload, indent=2, default=str))


def _err(message):
    print(f"opencobot: error: {message}", file=sys.stderr)


def _parse_args_json(text):
    if text is None:
        return {}
    try:
        parsed = json.loads(text)
    except ValueError as exc:
        raise ValueError(f"invalid --args-json: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("--args-json must be a JSON object")
    return parsed


def _state_dir(args):
    return Path(args.state_dir).expanduser() if args.state_dir else default_state_dir()


def _spec_available(name):
    """Safe ``importlib.util.find_spec``: False when the module or any
    parent package is missing (stock find_spec raises in that case)."""
    try:
        import importlib.util
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _require_policyd(state_dir):
    """Ensure policyd (or the in-process fallback) is available.

    Returns a policy client, or raises :class:`PolicyUnavailable`.
    """
    status, _proc = ensure_policyd(state_dir)
    if status == "failed":
        raise PolicyUnavailable(
            f"policyd did not start (see {state_dir / 'policyd.log'})")
    return get_policy_client(state_dir)


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_tools_list(args):
    tools = get_tools()
    tools = sorted(tools, key=lambda t: (t["level"], t["name"]))
    payload = {"tools": tools, "count": len(tools)}
    lines = [f"{t['name']:<22} L{t['level']}  {t['description']}" for t in tools]
    _emit(payload, args.json, lines)
    return 0


def cmd_tool_run(args):
    try:
        tool_args = _parse_args_json(args.args_json)
    except ValueError as exc:
        _err(str(exc))
        return 2
    tool = get_tool(args.name)
    if tool is None:
        _err(f"unknown tool: {args.name} (see `opencobot tools list`)")
        return 2
    state_dir = _state_dir(args)
    try:
        client = _require_policyd(state_dir)
    except PolicyUnavailable as exc:
        _err(str(exc))
        return 2
    folders = token_scope_folders(tool_args)
    try:
        token = call_issue_token(client, folders, [args.name], 600)
    except Exception as exc:
        _err(f"could not issue capability token: {exc}")
        return 2
    if args.approve:
        # The human at this terminal explicitly approves this run.
        # The approval is bound to the token just issued (the engine
        # keys approvals by token_id), so it applies to this run only.
        try:
            token_id = public_token_record(token)["token_id"]
            call_approve(client, token_id, args.name, 600)
        except Exception as exc:
            _err(f"approval failed: {exc}")
            return 1
    decision = call_check(client, args.name, tool["level"], tool_args,
                          token=token, tainted=bool(args.tainted))
    if not decision.get("allowed"):
        reason = decision.get("reason", "")
        error = f"needs approval: {reason}" if decision.get("needs_approval") \
            else f"denied: {reason}"
        payload = {"ok": False, "verified": False, "tool": args.name,
                   "error": error, "decision": decision}
        _emit(payload, True)  # tool run always prints machine-readable JSON
        return 1
    try:
        runtime = get_runtime(state_dir, policy=client)
    except RuntimeUnavailable as exc:
        _err(str(exc))
        return 2
    # The tool layer scopes paths from the token's `folders` name (see
    # adapt_token_for_runtime); pass the adapted token to the runtime.
    runtime_token = adapt_token_for_runtime(token)
    try:
        raw = runtime.run_tool(runtime_token, args.name, tool_args,
                               tainted=bool(args.tainted))
    except TypeError:
        raw = runtime.run_tool(runtime_token, args.name, tool_args)
    result = normalize_run_result(raw, args.name)
    _emit(result, True)  # tool run always prints machine-readable JSON
    return 0 if result.get("ok") and result.get("verified") else 1


def _read_daemon_auth(state_dir):
    auth_path = Path(state_dir) / "daemon.auth"
    if not auth_path.exists():
        return None
    raw = auth_path.read_text(encoding="utf-8").strip()
    if not raw:
        return None
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return data.get("token") or data.get("auth") or data.get("secret")
    except ValueError:
        pass
    return raw


def _query_daemon(state_dir, op, timeout=3.0):
    """Send one JSON request to the daemon Unix socket. Returns dict or None."""
    sock_path = Path(state_dir) / "daemon.sock"
    if not sock_path.exists():
        return None
    auth = _read_daemon_auth(state_dir)
    request = {"op": op}
    if auth:
        request["auth"] = auth
    try:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.settimeout(timeout)
        conn.connect(str(sock_path))
        conn.sendall((json.dumps(request) + "\n").encode("utf-8"))
        chunks = []
        try:
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                if b"\n" in chunk:
                    break
        finally:
            conn.close()
    except OSError:
        return None
    try:
        return json.loads(b"".join(chunks).decode("utf-8").strip().splitlines()[0])
    except (ValueError, IndexError):
        return None


def _pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError, OSError):
        return False


def cmd_daemon_start(args):
    state_dir = _state_dir(args)
    state_dir.mkdir(parents=True, exist_ok=True)
    pid_path = state_dir / "daemon.pid"
    if pid_path.exists():
        try:
            pid = int(pid_path.read_text(encoding="utf-8").strip())
            if _pid_alive(pid):
                _emit({"running": True, "pid": pid, "note": "daemon already running"},
                      args.json, [f"daemon already running (pid {pid})"])
                return 0
        except ValueError:
            pass
        pid_path.unlink(missing_ok=True)
    if not _spec_available("core.daemon"):
        _err("core.daemon is not installed yet (core slice not built); "
             "cannot start the daemon")
        return 1
    log_path = state_dir / "daemon.log"
    log_fh = open(log_path, "ab")
    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", "core.daemon", "--state-dir", str(state_dir)],
            stdin=subprocess.DEVNULL, stdout=log_fh, stderr=log_fh,
            start_new_session=True, close_fds=True)
    finally:
        log_fh.close()
    pid_path.write_text(str(proc.pid), encoding="utf-8")
    deadline = time.time() + 5.0
    while time.time() < deadline:
        if (state_dir / "daemon.sock").exists():
            break
        if proc.poll() is not None:
            _err(f"daemon exited immediately (see {log_path})")
            pid_path.unlink(missing_ok=True)
            return 1
        time.sleep(0.1)
    payload = {"running": True, "pid": proc.pid,
               "socket": str(state_dir / "daemon.sock")}
    _emit(payload, args.json,
          [f"daemon started (pid {proc.pid}, socket {state_dir / 'daemon.sock'})"])
    return 0


def cmd_daemon_stop(args):
    state_dir = _state_dir(args)
    pid_path = state_dir / "daemon.pid"
    sock_path = state_dir / "daemon.sock"
    if not pid_path.exists():
        if sock_path.exists():
            _err("daemon socket exists but no PID file; refusing to guess — "
                 f"remove {sock_path} manually if the daemon is really gone")
            return 1
        _emit({"running": False}, args.json, ["daemon not running"])
        return 1
    try:
        pid = int(pid_path.read_text(encoding="utf-8").strip())
    except ValueError:
        _err(f"corrupt PID file {pid_path}")
        return 1
    if _pid_alive(pid):
        os.kill(pid, signal.SIGTERM)
        deadline = time.time() + 5.0
        while time.time() < deadline and _pid_alive(pid):
            time.sleep(0.1)
        if _pid_alive(pid):
            os.kill(pid, signal.SIGKILL)
    pid_path.unlink(missing_ok=True)
    if sock_path.exists() and not _pid_alive(pid):
        sock_path.unlink(missing_ok=True)
    _emit({"running": False, "pid": pid}, args.json,
          [f"daemon stopped (pid {pid})"])
    return 0


def cmd_daemon_status(args):
    state_dir = _state_dir(args)
    pid, running = None, False
    pid_path = state_dir / "daemon.pid"
    if pid_path.exists():
        try:
            pid = int(pid_path.read_text(encoding="utf-8").strip())
            running = _pid_alive(pid)
        except ValueError:
            pid = None
    sock_exists = (state_dir / "daemon.sock").exists()
    status = _query_daemon(state_dir, "status") if sock_exists else None
    if status is not None:
        running = True
    elif sock_exists and running:
        status = {"note": "socket reachable, status query failed"}
    payload = {"running": running, "pid": pid,
               "socket": str(state_dir / "daemon.sock") if sock_exists else None,
               "status": status}
    if running:
        lines = [f"daemon running (pid {pid})" if pid else "daemon running"]
        if status:
            lines.append(f"status: {json.dumps(status)}")
    else:
        lines = ["daemon not running"]
    _emit(payload, args.json, lines)
    return 0 if running else 1


def cmd_policy_check(args):
    try:
        tool_args = _parse_args_json(args.args_json)
    except ValueError as exc:
        _err(str(exc))
        return 2
    tool = get_tool(args.tool)
    if tool is None:
        _err(f"unknown tool: {args.tool} (see `opencobot tools list`)")
        return 2
    level = int(args.level) if args.level is not None else int(tool["level"])
    state_dir = _state_dir(args)
    try:
        client = _require_policyd(state_dir)
    except PolicyUnavailable as exc:
        _err(str(exc))
        return 2
    # The policy decision is always relative to a capability token, so
    # mint a fresh one scoped like a real run would be (cwd + any paths
    # in --args-json, this tool only, 600s). Nothing is executed.
    try:
        token = call_issue_token(
            client, token_scope_folders(tool_args), [args.tool], 600)
    except Exception as exc:
        _err(f"could not issue capability token: {exc}")
        return 2
    decision = call_check(client, args.tool, level, tool_args, token=token,
                          tainted=False)
    payload = {"tool": args.tool, "level": level,
               "allowed": bool(decision.get("allowed")),
               "needs_approval": bool(decision.get("needs_approval")),
               "reason": decision.get("reason", "")}
    lines = [f"tool:           {args.tool} (level {level})",
             f"allowed:        {'yes' if payload['allowed'] else 'no'}",
             f"needs_approval: {'yes' if payload['needs_approval'] else 'no'}",
             f"reason:         {payload['reason']}"]
    _emit(payload, args.json, lines)
    return 0


def cmd_policy_approve(args):
    state_dir = _state_dir(args)
    try:
        client = _require_policyd(state_dir)
    except PolicyUnavailable as exc:
        _err(str(exc))
        return 2
    if get_tool(args.tool) is None:
        _err(f"unknown tool: {args.tool}")
        return 2
    # Approvals are bound to a (token_id, tool) pair in the real engine,
    # so mint the token being approved and report its id: a later
    # `tool run` mints its own token, so this approval applies to the
    # token printed here (e.g. a task token held by the UI/phone), not
    # to future unrelated runs.
    try:
        token = call_issue_token(
            client, token_scope_folders({}), [args.tool], int(args.duration))
        token_id = public_token_record(token)["token_id"]
        approval_id = call_approve(client, token_id, args.tool, int(args.duration))
    except Exception as exc:
        _err(f"approval failed: {exc}")
        return 1
    payload = {"tool": args.tool, "approved": True, "token_id": token_id,
               "approval_id": approval_id if isinstance(approval_id, str) else None,
               "expiry": public_token_record(token)["expiry"]}
    _emit(payload, args.json,
          [f"approved {args.tool} for token {token_id} "
           f"(approval {payload['approval_id']}) until {payload['expiry']}"])
    return 0


def cmd_token_issue(args):
    folders = [f.strip() for f in (args.folders or "").split(",") if f.strip()]
    tools = [t.strip() for t in (args.tools or "").split(",") if t.strip()]
    if not folders:
        folders = [os.getcwd()]
    if not tools:
        tools = ["*"]
    if int(args.duration) <= 0:
        _err("--duration must be positive")
        return 2
    state_dir = _state_dir(args)
    try:
        client = _require_policyd(state_dir)
    except PolicyUnavailable as exc:
        _err(str(exc))
        return 2
    try:
        token = call_issue_token(client, folders, tools, int(args.duration))
    except Exception as exc:
        _err(f"could not issue token: {exc}")
        return 1
    # Print the public token record only — never the token secret and
    # never the policyd auth secret.
    payload = public_token_record(token, duration_seconds=int(args.duration))
    lines = [f"token_id: {payload['token_id']}",
             f"expiry:   {payload['expiry']}",
             f"folders:  {', '.join(payload['folders'])}",
             f"tools:    {', '.join(payload['tools'])}"]
    _emit(payload, args.json, lines)
    return 0


def cmd_audit_verify(args):
    state_dir = _state_dir(args)
    log = get_audit_log(state_dir)
    ok, count, errors = audit_verify(log)
    payload = {"ok": ok, "entries": count, "errors": errors}
    if ok:
        lines = [f"audit OK — {count} entries, hash chain valid"]
    else:
        lines = [f"audit FAIL — {count} entries checked: {'; '.join(errors) or 'unknown error'}"]
    _emit(payload, args.json, lines)
    return 0 if ok else 1


def cmd_audit_show(args):
    state_dir = _state_dir(args)
    log = get_audit_log(state_dir)
    entries = audit_read_last(log, int(args.limit))
    payload = {"entries": entries, "count": len(entries)}
    if args.json:
        _emit(payload, True)
        return 0
    if not entries:
        print("(audit log is empty)")
        return 0
    for entry in entries:
        print(json.dumps(entry, sort_keys=True, default=str))
    return 0


def cmd_kill(args):
    state_dir = _state_dir(args)
    try:
        client = _require_policyd(state_dir)
    except PolicyUnavailable as exc:
        _err(str(exc))
        return 2
    client.kill()
    _emit({"kill_switch": True}, args.json, ["kill switch ON — all tool runs blocked"])
    return 0


def cmd_unkill(args):
    state_dir = _state_dir(args)
    try:
        client = _require_policyd(state_dir)
    except PolicyUnavailable as exc:
        _err(str(exc))
        return 2
    client.unkill()
    _emit({"kill_switch": False}, args.json, ["kill switch OFF"])
    return 0


def cmd_doctor(args):
    state_dir = _state_dir(args)
    checks = []  # (name, status, detail, essential) status in PASS/FAIL/INFO

    if sys.version_info >= (3, 10):
        checks.append(("python", "PASS", f"{sys.version.split()[0]} (>= 3.10)", True))
    else:
        checks.append(("python", "FAIL", f"{sys.version.split()[0]} (< 3.10 required)", True))

    try:
        import pytest  # noqa: F401
        checks.append(("pytest", "PASS", f"pytest {pytest.__version__} available", True))
    except ImportError:
        checks.append(("pytest", "FAIL", "pytest not importable", True))

    try:
        state_dir.mkdir(parents=True, exist_ok=True)
        probe = state_dir / ".doctor-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        checks.append(("state dir", "PASS", f"{state_dir} writable", True))
    except OSError as exc:
        checks.append(("state dir", "FAIL", f"{state_dir} not writable: {exc}", True))

    # policyd: real process if installed, else the in-process fallback
    # engine (weaker isolation — reported as such, still a PASS for the
    # essential "can I get a policy decision?" check).
    if _spec_available("policy.policyd"):
        status, _proc = ensure_policyd(state_dir)
        if status == "running":
            checks.append(("policyd", "PASS", "reachable (socket)", True))
        else:
            checks.append(("policyd", "FAIL", "could not start; see policyd.log", True))
    else:
        try:
            FallbackPolicyEngine(state_dir).status()
            checks.append(("policyd", "PASS",
                           "in-process fallback engine (policyd module not installed yet)", True))
        except Exception as exc:
            checks.append(("policyd", "FAIL", f"fallback engine failed: {exc}", True))

    sock = state_dir / "daemon.sock"
    if sock.exists() and _query_daemon(state_dir, "status") is not None:
        checks.append(("daemon", "PASS", "reachable (socket)", False))
    elif sock.exists():
        checks.append(("daemon", "INFO", "socket exists but status query failed", False))
    else:
        checks.append(("daemon", "INFO", "not running", False))

    try:
        conn = socket.create_connection(("127.0.0.1", 11434), timeout=1.0)
        conn.close()
        checks.append(("ollama", "PASS", "reachable at localhost:11434", False))
    except OSError:
        checks.append(("ollama", "INFO", "not running (localhost:11434 unreachable)", False))

    display = os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
    if display:
        checks.append(("display", "PASS", f"present ({display})", False))
    else:
        checks.append(("display", "INFO", "not present (headless, no DISPLAY/WAYLAND_DISPLAY)", False))

    payload = {"checks": [{"name": n, "status": s, "detail": d, "essential": e}
                          for n, s, d, e in checks]}
    lines = [f"{status:<4} {name:<10} {detail}" for name, status, detail, _e in checks]
    _emit(payload, args.json, lines)
    essential_failed = any(s == "FAIL" and e for _n, s, _d, e in checks)
    return 0 if not essential_failed else 1


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="opencobot",
        description="OpenCobot CLI — local-first computer control (Phase 1 Linux MVP).")
    parser.add_argument("--state-dir", default=None,
                        help="state directory (default: $OPENCOBOT_STATE or ~/.opencobot)")
    parser.add_argument("--json", action="store_true", default=False,
                        help="machine-readable JSON output")
    parser.add_argument("--version", action="version", version=f"opencobot {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # tools list
    p_tools = sub.add_parser("tools", help="inspect the tool registry")
    tools_sub = p_tools.add_subparsers(dest="tools_command", required=True)
    p_list = tools_sub.add_parser("list", help="list tools (no daemon needed)")
    p_list.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    p_list.set_defaults(func=cmd_tools_list)

    # tool run
    p_tool = sub.add_parser("tool", help="run a tool through policy + runtime")
    tool_sub = p_tool.add_subparsers(dest="tool_command", required=True)
    p_run = tool_sub.add_parser("run", help="run one tool with a scoped token")
    p_run.add_argument("name", help="tool name (see `opencobot tools list`)")
    p_run.add_argument("--args-json", default=None,
                       help='JSON object of arguments, e.g. \'{"path": "/tmp"}\'')
    p_run.add_argument("--tainted", action="store_true",
                       help="mark the call as tainted (untrusted context)")
    p_run.add_argument("--approve", action="store_true",
                       help="explicitly approve this run (human at the terminal; "
                            "needed for level 3+ tools, applies to this run only)")
    p_run.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    p_run.set_defaults(func=cmd_tool_run)

    # daemon
    p_daemon = sub.add_parser("daemon", help="manage the local daemon")
    daemon_sub = p_daemon.add_subparsers(dest="daemon_command", required=True)
    for name, func, help_text in (
            ("start", cmd_daemon_start, "start the daemon (detached)"),
            ("stop", cmd_daemon_stop, "stop the daemon"),
            ("status", cmd_daemon_status, "report daemon status")):
        p = daemon_sub.add_parser(name, help=help_text)
        p.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
        p.set_defaults(func=func)

    # policy
    p_policy = sub.add_parser("policy", help="query the policy engine")
    policy_sub = p_policy.add_subparsers(dest="policy_command", required=True)
    p_check = policy_sub.add_parser("check", help="print the policy decision without executing")
    p_check.add_argument("--tool", required=True, help="tool name")
    p_check.add_argument("--level", type=int, default=None,
                         help="permission level (default: the tool's registered level)")
    p_check.add_argument("--args-json", default=None, help="JSON object of arguments")
    p_check.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    p_check.set_defaults(func=cmd_policy_check)
    p_approve = policy_sub.add_parser("approve", help="approve a tool for a limited time")
    p_approve.add_argument("--tool", required=True, help="tool name")
    p_approve.add_argument("--duration", type=int, default=600,
                           help="approval lifetime in seconds (default 600)")
    p_approve.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    p_approve.set_defaults(func=cmd_policy_approve)

    # token
    p_token = sub.add_parser("token", help="capability tokens")
    token_sub = p_token.add_subparsers(dest="token_command", required=True)
    p_issue = token_sub.add_parser("issue", help="issue a scoped capability token")
    p_issue.add_argument("--folders", default="", help="comma-separated folders, e.g. /home/u/work,/tmp")
    p_issue.add_argument("--tools", default="", help="comma-separated tools, e.g. list_dir,read_file")
    p_issue.add_argument("--duration", type=int, default=600,
                         help="lifetime in seconds (default 600)")
    p_issue.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    p_issue.set_defaults(func=cmd_token_issue)

    # audit
    p_audit = sub.add_parser("audit", help="inspect the audit log")
    audit_sub = p_audit.add_subparsers(dest="audit_command", required=True)
    p_verify = audit_sub.add_parser("verify", help="verify the audit hash chain")
    p_verify.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    p_verify.set_defaults(func=cmd_audit_verify)
    p_show = audit_sub.add_parser("show", help="print the last N audit entries")
    p_show.add_argument("--limit", type=int, default=20, help="entries to show (default 20)")
    p_show.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    p_show.set_defaults(func=cmd_audit_show)

    # kill / unkill / doctor
    p_kill = sub.add_parser("kill", help="engage the kill switch (blocks all tool runs)")
    p_kill.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    p_kill.set_defaults(func=cmd_kill)
    p_unkill = sub.add_parser("unkill", help="release the kill switch")
    p_unkill.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    p_unkill.set_defaults(func=cmd_unkill)
    p_doctor = sub.add_parser("doctor", help="environment check")
    p_doctor.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    p_doctor.set_defaults(func=cmd_doctor)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "json"):
        args.json = False
    try:
        return int(args.func(args))
    except PolicyUnavailable as exc:
        _err(f"policy unavailable: {exc}")
        return 2
    except RuntimeUnavailable as exc:
        _err(f"runtime unavailable: {exc}")
        return 2
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        _err("interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
