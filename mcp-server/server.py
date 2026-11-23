#!/usr/bin/env python3
"""OpenCobot MCP server (Phase 1, Linux MVP) — stdio JSON-RPC 2.0.

Run as a script (the directory name is hyphenated, so it cannot be a
package)::

    python mcp-server/server.py --state-dir ~/.opencobot

Protocol: line-delimited JSON-RPC 2.0 over stdin/stdout (batched
requests — a JSON array on one line — are also accepted). Methods:

* ``initialize`` -> protocol version, capabilities, server info
* ``ping`` -> ``{}``
* ``tools/list`` -> tools from the tool registry
* ``tools/call`` -> run one tool through the policy engine + runtime

Standalone-mode note: this server uses the policy engine **in-process**
(``policy.engine.PolicyEngine`` when installed, else the same fallback
engine the CLI uses), backed by the shared state dir and audit log.
That is weaker isolation than the separate ``policyd`` process the
daemon/CLI path uses. When ``policyd`` (or the daemon) is running, the
daemon path should be preferred; a future version of this server will
route ``tools/call`` through the daemon socket instead. Tool calls here
still go through the same policy code: short-lived token scoped to the
working directory (+ any paths named in the arguments), 600s, single
tool, Level 3+ needs an explicit approval.

Nothing is ever printed to stdout except JSON-RPC responses; diagnostics
go to stderr.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# The directory is hyphenated, so this file runs as a script: put the
# repo root on sys.path so `cli` / `policy` / `tools` / `core` import.
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from cli._compat import (  # noqa: E402
    adapt_token_for_runtime,
    call_issue_token,
    default_state_dir,
    get_policy_engine,
    get_runtime,
    get_tools,
    normalize_run_result,
    token_scope_folders,
)

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "opencobot"
SERVER_VERSION = "0.1.0"


def _log(message):
    print(f"mcp-server: {message}", file=sys.stderr, flush=True)


class MCPServer:
    def __init__(self, state_dir):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._runtime = None
        self._runtime_error = None

    # -- runtime (lazy: initialize/tools/list must work even if the
    #    policy engine cannot start) -------------------------------------
    def _get_runtime(self):
        if self._runtime is not None:
            return self._runtime
        if self._runtime_error is not None:
            raise self._runtime_error
        try:
            policy = get_policy_engine(self.state_dir)
            self._runtime = get_runtime(self.state_dir, policy=policy)
            return self._runtime
        except Exception as exc:
            self._runtime_error = exc
            raise

    # -- JSON-RPC plumbing --------------------------------------------------
    def handle(self, request):
        """Handle one decoded request; return a response dict or None."""
        if not isinstance(request, dict):
            return {"jsonrpc": "2.0", "id": None,
                    "error": {"code": -32600, "message": "Invalid Request: expected an object"}}
        method = request.get("method")
        req_id = request.get("id")
        params = request.get("params") or {}
        is_notification = "id" not in request

        if not isinstance(method, str):
            if is_notification:
                return None
            return {"jsonrpc": "2.0", "id": req_id,
                    "error": {"code": -32600, "message": "Invalid Request: missing method"}}

        if method.startswith("notifications/"):
            return None  # notifications never get a reply

        handlers = {
            "initialize": self._initialize,
            "ping": self._ping,
            "tools/list": self._tools_list,
            "tools/call": self._tools_call,
        }
        handler = handlers.get(method)
        if handler is None:
            return {"jsonrpc": "2.0", "id": req_id,
                    "error": {"code": -32601, "message": f"Method not found: {method}"}}
        try:
            result = handler(params)
        except Exception as exc:
            _log(f"{method} failed: {exc}")
            return {"jsonrpc": "2.0", "id": req_id,
                    "error": {"code": -32603, "message": f"Internal error: {exc}"}}
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    def handle_line(self, line):
        """Handle one input line; return the response text or None."""
        line = line.strip()
        if not line:
            return None
        try:
            decoded = json.loads(line)
        except ValueError:
            return json.dumps({"jsonrpc": "2.0", "id": None,
                               "error": {"code": -32700, "message": "Parse error"}})
        if isinstance(decoded, list):
            responses = [r for r in (self.handle(req) for req in decoded) if r is not None]
            return json.dumps(responses) if responses else None
        response = self.handle(decoded)
        return json.dumps(response) if response is not None else None

    # -- methods ------------------------------------------------------------
    def _initialize(self, params):
        return {"protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION}}

    def _ping(self, params):
        return {}

    def _tools_list(self, params):
        tools = []
        for tool in get_tools():
            tools.append({"name": tool["name"],
                          "description": tool.get("description", ""),
                          "inputSchema": tool.get("inputSchema") or {
                              "type": "object", "properties": {}}})
        return {"tools": tools}

    def _tools_call(self, params):
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            return {"content": [{"type": "text",
                                 "text": json.dumps({"ok": False, "verified": False,
                                                     "error": "arguments must be an object"})}] ,
                    "isError": True}
        if not name:
            return {"content": [{"type": "text",
                                 "text": json.dumps({"ok": False, "verified": False,
                                                     "error": "tools/call needs a tool name"})}] ,
                    "isError": True}
        try:
            runtime = self._get_runtime()
        except Exception as exc:
            return {"content": [{"type": "text",
                                 "text": json.dumps({"ok": False, "verified": False,
                                                     "error": f"runtime unavailable: {exc}"})}] ,
                    "isError": True}
        # Short-lived token scoped to cwd (+ paths named in the call),
        # 600s, this one tool only.
        try:
            policy = runtime.policy
            folders = token_scope_folders(arguments)
            token = call_issue_token(policy, folders, [name], 600)
        except Exception as exc:
            return {"content": [{"type": "text",
                                 "text": json.dumps({"ok": False, "verified": False,
                                                     "error": f"could not issue token: {exc}"})}] ,
                    "isError": True}
        try:
            result = runtime.run_tool(adapt_token_for_runtime(token), name, arguments)
        except TypeError:
            try:
                result = runtime.run_tool(adapt_token_for_runtime(token), name,
                                          arguments, False)
            except Exception as exc:
                result = {"ok": False, "verified": False, "tool": name, "error": str(exc)}
        except Exception as exc:
            result = {"ok": False, "verified": False, "tool": name, "error": str(exc)}
        result = normalize_run_result(result, name)
        is_error = not (result.get("ok") and result.get("verified"))
        return {"content": [{"type": "text", "text": json.dumps(result, default=str)}],
                "isError": is_error}


def main(argv=None):
    parser = argparse.ArgumentParser(description="OpenCobot MCP server (stdio JSON-RPC 2.0).")
    parser.add_argument("--state-dir", default=None,
                        help="state directory (default: $OPENCOBOT_STATE or ~/.opencobot)")
    args = parser.parse_args(argv)
    state_dir = Path(args.state_dir).expanduser() if args.state_dir else default_state_dir()
    server = MCPServer(state_dir)
    _log(f"started (state dir {state_dir})")
    try:
        for line in sys.stdin:
            try:
                response = server.handle_line(line)
            except Exception as exc:  # never die on one bad line
                _log(f"line handling failed: {exc}")
                response = json.dumps({"jsonrpc": "2.0", "id": None,
                                       "error": {"code": -32603, "message": str(exc)}})
            if response is not None:
                sys.stdout.write(response + "\n")
                sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
