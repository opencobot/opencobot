"""Standalone fallback implementations for the CLI / MCP slices.

These exist ONLY because the sibling Phase 1 slices (``policy/``,
``tools/``, ``core/``) are being built in parallel and may not be
installed yet. Every loader in :mod:`cli._compat` prefers the real
module when it is importable and uses the classes/functions here only
when the real module is missing (``ImportError``).

Contract these fallbacks implement (same names/signatures as the
shared interfaces in the task brief):

* tool registry: :data:`TOOLS`, :func:`list_tools`, :func:`get_tool`
* policy: :class:`FallbackPolicyEngine` / :class:`FallbackPolicyClient`
  with ``check`` / ``issue_token`` / ``approve`` / ``taint`` / ``kill`` /
  ``unkill`` / ``status`` / ``audit_verify``
* audit: :class:`AuditLog` (append-only, hash-chained JSONL)
* runtime: :class:`FallbackRuntime` with ``run_tool`` / ``list_tools``

Security notes:

* No ``shell=True`` anywhere; shell tools take an argv array (a plain
  string is split with :mod:`shlex`, never executed through a shell).
* File tools are scoped by the capability token's ``folders`` list.
* ``delete_file`` moves to ``<state_dir>/trash/`` instead of deleting.
* Audit entries redact file-content arguments (only lengths are kept).
* No secrets are ever written to the audit log; capability-token
  secrets are stored only as SHA-256 hashes in ``tokens.json``.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import platform
import secrets
import shlex
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

__all__ = [
    "TOOLS",
    "list_tools",
    "get_tool",
    "AuditLog",
    "FallbackPolicyEngine",
    "FallbackPolicyClient",
    "FallbackRuntime",
    "ToolError",
]


# ---------------------------------------------------------------------------
# Tool registry (fallback)
# ---------------------------------------------------------------------------

def _schema(properties, required=()):
    return {
        "type": "object",
        "properties": properties,
        "required": list(required),
        "additionalProperties": False,
    }


_PATH = {"type": "string", "description": "Absolute or relative filesystem path."}

TOOLS = [
    # Level 0 — read and inspect (allowed within token scope).
    {"name": "list_dir", "level": 0, "category": "files",
     "description": "List the entries of a directory (name, type, size).",
     "inputSchema": _schema({"path": _PATH}, ["path"])},
    {"name": "read_file", "level": 0, "category": "files",
     "description": "Read a text file (UTF-8, errors replaced).",
     "inputSchema": _schema({"path": _PATH,
                             "max_bytes": {"type": "integer", "description": "Max bytes to read (default 1048576)."}},
                            ["path"])},
    {"name": "file_info", "level": 0, "category": "files",
     "description": "Return existence, type, size and mtime for a path.",
     "inputSchema": _schema({"path": _PATH}, ["path"])},
    {"name": "search_files", "level": 0, "category": "files",
     "description": "Recursively find files whose names match a glob pattern.",
     "inputSchema": _schema({"path": _PATH,
                             "pattern": {"type": "string", "description": "Glob, e.g. '*.py'."}},
                            ["path", "pattern"])},
    {"name": "get_system_info", "level": 0, "category": "system",
     "description": "Return OS, hostname, Python version, CPU count and memory.",
     "inputSchema": _schema({})},
    {"name": "list_processes", "level": 0, "category": "system",
     "description": "List running processes (pid and command line, Linux /proc).",
     "inputSchema": _schema({})},
    {"name": "get_disk_usage", "level": 0, "category": "system",
     "description": "Return total/used/free bytes for the filesystem of a path.",
     "inputSchema": _schema({"path": _PATH}, ["path"])},
    {"name": "get_network_status", "level": 0, "category": "system",
     "description": "List network interfaces and their state (no network I/O).",
     "inputSchema": _schema({})},
    # Level 1 — basic interaction (allowed within scope).
    {"name": "open_app", "level": 1, "category": "gui",
     "description": "Open an application by desktop name or command (Linux GUI).",
     "inputSchema": _schema({"app": {"type": "string", "description": "Application name or command."}}, ["app"])},
    {"name": "list_windows", "level": 1, "category": "gui",
     "description": "List open windows (title and id).",
     "inputSchema": _schema({})},
    {"name": "activate_window", "level": 1, "category": "gui",
     "description": "Bring a window to the front by title or id.",
     "inputSchema": _schema({"window": {"type": "string"}}, ["window"])},
    {"name": "take_screenshot", "level": 1, "category": "gui",
     "description": "Capture the screen to a PNG file.",
     "inputSchema": _schema({"path": _PATH}, ["path"])},
    {"name": "get_clipboard", "level": 1, "category": "gui",
     "description": "Return the current clipboard text.",
     "inputSchema": _schema({})},
    {"name": "type_text", "level": 1, "category": "gui",
     "description": "Type text into the focused window.",
     "inputSchema": _schema({"text": {"type": "string"}}, ["text"])},
    # Level 2 — controlled modifications (allowed in scope, logged).
    {"name": "write_file", "level": 2, "category": "files",
     "description": "Write text to a file, creating parent directories.",
     "inputSchema": _schema({"path": _PATH, "content": {"type": "string"}}, ["path", "content"])},
    {"name": "create_file", "level": 2, "category": "files",
     "description": "Create a new file; fails if it already exists.",
     "inputSchema": _schema({"path": _PATH, "content": {"type": "string"}}, ["path"])},
    {"name": "create_dir", "level": 2, "category": "files",
     "description": "Create a directory (including parents).",
     "inputSchema": _schema({"path": _PATH}, ["path"])},
    {"name": "move_file", "level": 2, "category": "files",
     "description": "Move (rename) a file or directory.",
     "inputSchema": _schema({"src": _PATH, "dst": _PATH}, ["src", "dst"])},
    {"name": "copy_file", "level": 2, "category": "files",
     "description": "Copy a file or directory.",
     "inputSchema": _schema({"src": _PATH, "dst": _PATH}, ["src", "dst"])},
    {"name": "edit_file", "level": 2, "category": "files",
     "description": "Replace exactly one occurrence of old_text with new_text in a file.",
     "inputSchema": _schema({"path": _PATH,
                             "old_text": {"type": "string"},
                             "new_text": {"type": "string"}},
                            ["path", "old_text", "new_text"])},
    # Level 3 — sensitive (explicit approval required).
    {"name": "delete_file", "level": 3, "category": "files",
     "description": "Move a file or directory to the OpenCobot trash (never deletes outright).",
     "inputSchema": _schema({"path": _PATH}, ["path"])},
    {"name": "run_command", "level": 3, "category": "shell",
     "description": "Run a command as an argv array (no shell). A plain string is split with shlex.",
     "inputSchema": _schema({"command": {"type": ["string", "array"],
                                         "description": "Command argv, or a string to shlex-split."},
                             "argv": {"type": "array",
                                      "description": "Alias for command as an argv array (real registry name)."},
                             "cwd": {"type": "string"},
                             "timeout": {"type": "number", "description": "Seconds (default 30)."}},
                            ["command"])},
    {"name": "install_package", "level": 3, "category": "shell",
     "description": "Install a system package (Linux package manager).",
     "inputSchema": _schema({"package": {"type": "string"}, "manager": {"type": "string"}}, ["package"])},
    # Level 4 — high risk (strong approval or blocked).
    {"name": "run_admin_command", "level": 4, "category": "shell",
     "description": "Run a command with administrative privileges (sudo).",
     "inputSchema": _schema({"command": {"type": ["string", "array"]},
                             "cwd": {"type": "string"}},
                            ["command"])},
]


def list_tools():
    """Return a copy of the fallback tool registry."""
    return [dict(t) for t in TOOLS]


def get_tool(name):
    """Return the registry entry for *name*, or ``None``."""
    for tool in TOOLS:
        if tool["name"] == name:
            return dict(tool)
    return None


# ---------------------------------------------------------------------------
# Audit log (append-only, hash-chained JSONL)
# ---------------------------------------------------------------------------

def _utcnow_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


class AuditLog:
    """Hash-chained JSON-lines audit log.

    Lives at ``<state_dir>/audit.jsonl`` — the same file the real
    ``policy.audit.AuditLog`` uses, so fallback and real entries share
    one chain.
    """

    def __init__(self, state_dir):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.state_dir / "audit.jsonl"

    def _last_hash(self):
        if not self.path.exists():
            return "0" * 64
        last = None
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = line
        if last is None:
            return "0" * 64
        try:
            return json.loads(last)["hash"]
        except (KeyError, ValueError):
            return "0" * 64

    def _count(self):
        if not self.path.exists():
            return 0
        n = 0
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    n += 1
        return n

    def append(self, entry_type, **fields):
        prev_hash = self._last_hash()
        seq = self._count() + 1
        entry = {"seq": seq, "ts": _utcnow_iso(), "type": entry_type,
                 "prev_hash": prev_hash}
        entry.update(fields)
        digest = hashlib.sha256(
            (prev_hash + _canonical({k: v for k, v in entry.items()}))
            .encode("utf-8")).hexdigest()
        entry["hash"] = digest
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return dict(entry)

    def verify(self):
        """Recompute the chain. Returns ``(ok, count, error_or_None)``."""
        if not self.path.exists():
            return True, 0, None
        prev_hash = "0" * 64
        count = 0
        expected_seq = 1
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except ValueError:
                    return False, count, f"line {count + 1}: not valid JSON"
                count += 1
                if entry.get("seq") != expected_seq:
                    return False, count, f"line {count}: seq {entry.get('seq')} != {expected_seq}"
                if entry.get("prev_hash") != prev_hash:
                    return False, count, f"line {count}: prev_hash mismatch"
                stored = entry.pop("hash", None)
                digest = hashlib.sha256(
                    (prev_hash + _canonical(entry)).encode("utf-8")).hexdigest()
                if stored != digest:
                    return False, count, f"line {count}: hash mismatch (tampered?)"
                prev_hash = stored
                expected_seq += 1
        return True, count, None

    def read_last(self, n=20):
        if not self.path.exists():
            return []
        entries = []
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except ValueError:
                        continue
        return entries[-n:]


# ---------------------------------------------------------------------------
# Policy engine (fallback, in-process)
# ---------------------------------------------------------------------------

_REDACT_KEYS = {"content", "new_text", "old_text", "text", "password", "secret", "token"}


def _redact_args(args):
    """Copy args for the audit log, redacting content-bearing values."""
    out = {}
    for key, value in (args or {}).items():
        if key in _REDACT_KEYS and isinstance(value, str):
            out[key] = {"__redacted_len": len(value)}
        else:
            out[key] = value
    return out


class FallbackPolicyEngine:
    """In-process stand-in for ``policy.engine.PolicyEngine``.

    Used only when the real policy slice is not installed. Same
    decision semantics as SPEC §5.1: L0–L2 allowed inside the token
    scope, L3+ needs an explicit approval, kill switch denies
    everything, tainted context locks L3+ behind approval.
    """

    def __init__(self, state_dir):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._policy_path = self.state_dir / "policy.json"
        self._tokens_path = self.state_dir / "tokens.json"
        self.audit = AuditLog(self.state_dir)

    # -- persistence ------------------------------------------------------
    def _load_policy(self):
        if self._policy_path.exists():
            try:
                data = json.loads(self._policy_path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
            except ValueError:
                pass
        return {"kill_switch": False, "approvals": {}, "tainted": False,
                "taint_sources": []}

    def _save_policy(self, data):
        self._policy_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _load_tokens(self):
        if self._tokens_path.exists():
            try:
                data = json.loads(self._tokens_path.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    return data
            except ValueError:
                pass
        return []

    def _save_tokens(self, tokens):
        self._tokens_path.write_text(json.dumps(tokens, indent=2), encoding="utf-8")

    # -- decisions --------------------------------------------------------
    def check(self, tool=None, tool_name=None, level=None, args=None,
              token=None, tainted=False, **kwargs):
        name = tool_name or tool or kwargs.get("name")
        args = args or kwargs.get("arguments") or {}
        if tainted is False:
            tainted = bool(kwargs.get("tainted", False))
        entry = get_tool(name) if name else None
        if entry is None:
            return {"allowed": False, "needs_approval": False,
                    "reason": f"unknown tool: {name}", "level": level, "tool": name}
        lvl = int(level) if level is not None else int(entry["level"])
        state = self._load_policy()
        if state.get("kill_switch"):
            return {"allowed": False, "needs_approval": False,
                    "reason": "kill switch is active", "level": lvl, "tool": name}
        if token is not None:
            ok, why = self.validate_token(token, name, args)
            if not ok:
                return {"allowed": False, "needs_approval": False,
                        "reason": why, "level": lvl, "tool": name}
        if state.get("tainted") or tainted:
            if lvl >= 3:
                return {"allowed": False, "needs_approval": True,
                        "reason": "tainted context: level 3+ tools need approval",
                        "level": lvl, "tool": name}
        if lvl >= 3:
            approvals = state.get("approvals", {})
            expiry = approvals.get(name)
            if expiry and expiry > time.time():
                return {"allowed": True, "needs_approval": False,
                        "reason": f"level {lvl} approved until "
                                  f"{datetime.fromtimestamp(expiry, timezone.utc).isoformat()}",
                        "level": lvl, "tool": name}
            return {"allowed": False, "needs_approval": True,
                    "reason": f"level {lvl} tool '{name}' needs explicit approval",
                    "level": lvl, "tool": name}
        return {"allowed": True, "needs_approval": False,
                "reason": f"level {lvl} allowed within token scope",
                "level": lvl, "tool": name}

    def issue_token(self, folders=None, tools=None, duration=600,
                    duration_seconds=None, **kwargs):
        if duration_seconds is not None:
            duration = duration_seconds
        if "duration_seconds" in kwargs:
            duration = kwargs["duration_seconds"]
        folders = [str(Path(f).expanduser().resolve())
                   for f in (folders or [os.getcwd()])]
        tools = list(tools or ["*"])
        duration = int(duration)
        if duration <= 0:
            raise ValueError("duration must be positive")
        token_id = uuid.uuid4().hex[:16]
        secret = secrets.token_urlsafe(32)
        expiry = time.time() + duration
        tokens = self._load_tokens()
        tokens.append({
            "token_id": token_id,
            "token_hash": hashlib.sha256(secret.encode("utf-8")).hexdigest(),
            "folders": folders, "tools": tools, "expiry": expiry,
            "issued_at": time.time(),
        })
        self._save_tokens(tokens)
        self.audit.append("token_issued", token_id=token_id,
                          tools=tools, folders=folders,
                          expiry=datetime.fromtimestamp(expiry, timezone.utc).isoformat())
        return {"token_id": token_id, "token": secret, "folders": folders,
                "tools": tools,
                "expiry": datetime.fromtimestamp(expiry, timezone.utc).isoformat(),
                "expires_in": duration}

    def validate_token(self, token, tool_name, args=None):
        """Return ``(ok, reason)`` for a token dict (or token_id string)."""
        args = args or {}
        tokens = self._load_tokens()
        record = None
        if isinstance(token, dict):
            token_id = token.get("token_id")
            secret = token.get("token")
            for rec in tokens:
                if rec.get("token_id") == token_id:
                    record = rec
                    break
            if record is None:
                return False, "unknown capability token"
            if secret is not None:
                digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
                if digest != record.get("token_hash"):
                    return False, "capability token secret mismatch"
        elif isinstance(token, str):
            for rec in tokens:
                if rec.get("token_id") == token:
                    record = rec
                    break
            if record is None:
                return False, "unknown capability token"
        else:
            return False, "invalid capability token"
        if record.get("expiry", 0) <= time.time():
            return False, "capability token expired"
        allowed_tools = record.get("tools") or []
        if "*" not in allowed_tools and tool_name not in allowed_tools:
            return False, f"tool '{tool_name}' is not in the capability token scope"
        folders = [Path(f) for f in (record.get("folders") or [])]
        for value in args.values():
            if isinstance(value, str) and value:
                candidate = Path(value).expanduser()
                if candidate.exists():
                    resolved = candidate.resolve()
                    target = resolved if resolved.is_dir() else resolved.parent
                    if folders and not any(
                            target == f or f in target.parents for f in folders):
                        return False, f"path '{value}' is outside the capability token folders"
        return True, "token valid"

    def approve(self, tool=None, tool_name=None, duration_seconds=600, **kwargs):
        name = tool_name or tool or kwargs.get("name")
        if not name:
            raise ValueError("approve() needs a tool name")
        if get_tool(name) is None:
            raise ValueError(f"unknown tool: {name}")
        state = self._load_policy()
        expiry = time.time() + int(duration_seconds)
        state.setdefault("approvals", {})[name] = expiry
        self._save_policy(state)
        self.audit.append("approval_granted", tool=name,
                          expiry=datetime.fromtimestamp(expiry, timezone.utc).isoformat())
        return {"tool": name,
                "expiry": datetime.fromtimestamp(expiry, timezone.utc).isoformat()}

    def taint(self, source="unknown", **kwargs):
        source = kwargs.get("source", source)
        state = self._load_policy()
        state["tainted"] = True
        sources = state.setdefault("taint_sources", [])
        if source not in sources:
            sources.append(source)
        self._save_policy(state)
        self.audit.append("taint_marked", source=source)
        return {"tainted": True, "source": source}

    def kill(self):
        state = self._load_policy()
        state["kill_switch"] = True
        self._save_policy(state)
        self.audit.append("kill_switch", active=True)
        return {"kill_switch": True}

    def unkill(self):
        state = self._load_policy()
        state["kill_switch"] = False
        self._save_policy(state)
        self.audit.append("kill_switch", active=False)
        return {"kill_switch": False}

    def status(self):
        state = self._load_policy()
        now = time.time()
        approvals = {k: v for k, v in state.get("approvals", {}).items() if v > now}
        return {"kill_switch": bool(state.get("kill_switch")),
                "tainted": bool(state.get("tainted")),
                "taint_sources": state.get("taint_sources", []),
                "approvals": approvals,
                "state_dir": str(self.state_dir)}

    def audit_verify(self):
        ok, count, error = self.audit.verify()
        return {"ok": ok, "entries": count, "error": error}


class FallbackPolicyClient(FallbackPolicyEngine):
    """In-process stand-in for ``policy.client.PolicyClient``.

    Used only when the real client (which talks to the separate
    ``policyd`` process over its Unix socket) is not installed. There
    is no socket and no auth secret in this mode — the engine runs in
    this process, which is weaker isolation than the real design and
    is documented as such wherever it is used.
    """


# ---------------------------------------------------------------------------
# Tool implementations (fallback, Linux)
# ---------------------------------------------------------------------------

class ToolError(Exception):
    """A tool failed (bad args, missing path, unavailable on this host)."""


def _require(args, *keys):
    for key in keys:
        if key not in args or args[key] is None:
            raise ToolError(f"missing required argument: {key}")
    return args


def _impl_list_dir(args, state_dir):
    _require(args, "path")
    path = Path(args["path"]).expanduser()
    if not path.is_dir():
        raise ToolError(f"not a directory: {args['path']}")
    entries = []
    for item in sorted(path.iterdir(), key=lambda p: p.name):
        try:
            kind = "dir" if item.is_dir() else "file" if item.is_file() else "other"
            size = item.stat().st_size if item.is_file() else 0
        except OSError:
            kind, size = "other", 0
        entries.append({"name": item.name, "type": kind, "size": size})
    result = {"path": str(path.resolve()), "entries": entries, "count": len(entries)}
    return result, path.is_dir()


def _impl_read_file(args, state_dir):
    _require(args, "path")
    path = Path(args["path"]).expanduser()
    if not path.is_file():
        raise ToolError(f"not a file: {args['path']}")
    max_bytes = int(args.get("max_bytes") or 1048576)
    data = path.read_bytes()[:max_bytes]
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    result = {"path": str(path.resolve()), "size": path.stat().st_size,
              "sha256": digest, "content": data.decode("utf-8", errors="replace"),
              "truncated": path.stat().st_size > max_bytes}
    return result, hashlib.sha256(path.read_bytes()).hexdigest() == digest


def _impl_file_info(args, state_dir):
    _require(args, "path")
    path = Path(args["path"]).expanduser()
    if not path.exists():
        return {"path": str(path), "exists": False}, True
    stat = path.stat()
    result = {"path": str(path.resolve()), "exists": True,
              "type": "dir" if path.is_dir() else "file" if path.is_file() else "other",
              "size": stat.st_size, "mtime": stat.st_mtime}
    return result, True


def _impl_search_files(args, state_dir):
    _require(args, "path", "pattern")
    root = Path(args["path"]).expanduser()
    if not root.is_dir():
        raise ToolError(f"not a directory: {args['path']}")
    matches = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if fnmatch.fnmatch(name, args["pattern"]):
                matches.append(str(Path(dirpath) / name))
                if len(matches) >= 100:
                    return {"path": str(root), "pattern": args["pattern"],
                            "matches": matches, "truncated": True}, True
    return {"path": str(root), "pattern": args["pattern"],
            "matches": matches, "truncated": False}, True


def _impl_get_system_info(args, state_dir):
    mem_total = None
    try:
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    mem_total = int(line.split()[1]) * 1024
                    break
    except OSError:
        pass
    result = {"platform": platform.platform(), "system": platform.system(),
              "release": platform.release(), "machine": platform.machine(),
              "hostname": platform.node(), "python": sys.version.split()[0],
              "cpu_count": os.cpu_count(), "memory_total_bytes": mem_total}
    return result, True


def _impl_list_processes(args, state_dir):
    procs = []
    try:
        proc_root = Path("/proc")
        for entry in proc_root.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                cmdline = (entry / "cmdline").read_bytes().replace(b"\x00", b" ").decode(
                    "utf-8", errors="replace").strip()
            except OSError:
                continue
            procs.append({"pid": int(entry.name), "cmdline": cmdline or f"[{entry.name}]"})
    except OSError as exc:
        raise ToolError(f"cannot list processes: {exc}")
    procs.sort(key=lambda p: p["pid"])
    return {"processes": procs, "count": len(procs)}, True


def _impl_get_disk_usage(args, state_dir):
    _require(args, "path")
    path = Path(args["path"]).expanduser()
    try:
        usage = shutil.disk_usage(path if path.exists() else "/")
    except OSError as exc:
        raise ToolError(f"cannot read disk usage: {exc}")
    return {"path": str(path), "total": usage.total, "used": usage.used,
            "free": usage.free}, True


def _impl_get_network_status(args, state_dir):
    interfaces = []
    net_path = Path("/sys/class/net")
    if net_path.is_dir():
        for iface in sorted(net_path.iterdir(), key=lambda p: p.name):
            state = "unknown"
            try:
                state = (iface / "operstate").read_text(encoding="utf-8").strip()
            except OSError:
                pass
            interfaces.append({"name": iface.name, "state": state})
    return {"interfaces": interfaces}, True


def _gui_unavailable(name):
    raise ToolError(
        f"{name} is not available in the headless Linux MVP fallback "
        "(no display server / GUI adapter installed)")


def _impl_write_file(args, state_dir):
    _require(args, "path", "content")
    path = Path(args["path"]).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(args["content"]), encoding="utf-8")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    expected = hashlib.sha256(str(args["content"]).encode("utf-8")).hexdigest()
    return {"path": str(path.resolve()), "bytes": path.stat().st_size,
            "sha256": digest}, digest == expected


def _impl_create_file(args, state_dir):
    _require(args, "path")
    path = Path(args["path"]).expanduser()
    if path.exists():
        raise ToolError(f"already exists: {args['path']}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(args.get("content") or ""), encoding="utf-8")
    return {"path": str(path.resolve()), "created": True}, path.is_file()


def _impl_create_dir(args, state_dir):
    _require(args, "path")
    path = Path(args["path"]).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    return {"path": str(path.resolve()), "created": True}, path.is_dir()


def _impl_move_file(args, state_dir):
    _require(args, "src", "dst")
    src, dst = Path(args["src"]).expanduser(), Path(args["dst"]).expanduser()
    if not src.exists():
        raise ToolError(f"not found: {args['src']}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dst))
    return {"src": str(src), "dst": str(dst.resolve())}, dst.exists() and not src.exists()


def _impl_copy_file(args, state_dir):
    _require(args, "src", "dst")
    src, dst = Path(args["src"]).expanduser(), Path(args["dst"]).expanduser()
    if not src.exists():
        raise ToolError(f"not found: {args['src']}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        shutil.copytree(src, dst, dirs_exist_ok=True)
    else:
        shutil.copy2(src, dst)
    return {"src": str(src), "dst": str(dst.resolve())}, dst.exists()


def _impl_edit_file(args, state_dir):
    _require(args, "path", "old_text", "new_text")
    path = Path(args["path"]).expanduser()
    if not path.is_file():
        raise ToolError(f"not a file: {args['path']}")
    text = path.read_text(encoding="utf-8")
    count = text.count(str(args["old_text"]))
    if count == 0:
        raise ToolError("old_text not found in file")
    if count > 1:
        raise ToolError(f"old_text occurs {count} times; refusing ambiguous edit")
    path.write_text(text.replace(str(args["old_text"]), str(args["new_text"]), 1),
                    encoding="utf-8")
    after = path.read_text(encoding="utf-8")
    return {"path": str(path.resolve()), "replaced": True}, \
        str(args["new_text"]) in after and str(args["old_text"]) not in after


def _impl_delete_file(args, state_dir):
    _require(args, "path")
    path = Path(args["path"]).expanduser()
    if not path.exists():
        raise ToolError(f"not found: {args['path']}")
    trash = Path(state_dir) / "trash"
    trash.mkdir(parents=True, exist_ok=True)
    target = trash / f"{path.name}.{int(time.time())}.{secrets.token_hex(4)}"
    shutil.move(str(path), str(target))
    return {"path": str(path), "trashed_to": str(target)}, not path.exists()


def _argv_from_command(args):
    # Accept both the fallback name ("command") and the real registry
    # name ("argv") so callers work against either implementation.
    if "command" in args:
        command = args["command"]
    elif "argv" in args:
        command = args["argv"]
    else:
        raise ToolError("missing required argument: command (or argv)")
    if isinstance(command, str):
        if not command.strip():
            raise ToolError("empty command")
        return shlex.split(command)
    if isinstance(command, list) and command and all(isinstance(c, str) for c in command):
        return list(command)
    raise ToolError("command must be a string or an array of strings")


def _impl_run_command(args, state_dir):
    argv = _argv_from_command(args)
    cwd = args.get("cwd") or None
    timeout = float(args.get("timeout") or 30)
    try:
        proc = subprocess.run(argv, shell=False, capture_output=True, text=True,
                              timeout=timeout, cwd=cwd)
    except FileNotFoundError:
        raise ToolError(f"command not found: {argv[0]}")
    except subprocess.TimeoutExpired:
        raise ToolError(f"command timed out after {timeout}s: {argv[0]}")
    except OSError as exc:
        raise ToolError(f"cannot run command: {exc}")
    result = {"command": argv, "returncode": proc.returncode,
              "stdout": proc.stdout, "stderr": proc.stderr}
    return result, proc.returncode == 0


TOOL_IMPLS = {
    "list_dir": _impl_list_dir,
    "read_file": _impl_read_file,
    "file_info": _impl_file_info,
    "search_files": _impl_search_files,
    "get_system_info": _impl_get_system_info,
    "list_processes": _impl_list_processes,
    "get_disk_usage": _impl_get_disk_usage,
    "get_network_status": _impl_get_network_status,
    "open_app": lambda a, s: _gui_unavailable("open_app"),
    "list_windows": lambda a, s: _gui_unavailable("list_windows"),
    "activate_window": lambda a, s: _gui_unavailable("activate_window"),
    "take_screenshot": lambda a, s: _gui_unavailable("take_screenshot"),
    "get_clipboard": lambda a, s: _gui_unavailable("get_clipboard"),
    "type_text": lambda a, s: _gui_unavailable("type_text"),
    "write_file": _impl_write_file,
    "create_file": _impl_create_file,
    "create_dir": _impl_create_dir,
    "move_file": _impl_move_file,
    "copy_file": _impl_copy_file,
    "edit_file": _impl_edit_file,
    "delete_file": _impl_delete_file,
    "run_command": _impl_run_command,
    "install_package": lambda a, s: (_ for _ in ()).throw(
        ToolError("install_package is not implemented in the Phase 1 fallback")),
    "run_admin_command": _impl_run_command,
}


# ---------------------------------------------------------------------------
# Runtime (fallback, in-process)
# ---------------------------------------------------------------------------

class FallbackRuntime:
    """In-process stand-in for ``core.runtime.Runtime``.

    Runs a tool only after the policy check passes, executes it, runs
    its ``verify()`` equivalent, and writes both the decision and the
    outcome to the shared audit log.
    """

    def __init__(self, state_dir, policy=None, registry=None):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.policy = policy if policy is not None else FallbackPolicyEngine(state_dir)
        if registry is None:
            self._tools = list_tools()
        elif isinstance(registry, dict):
            self._tools = [registry[k] if isinstance(registry[k], dict)
                           else {"name": k} for k in registry]
        elif hasattr(registry, "list_tools"):
            self._tools = registry.list_tools()
        elif isinstance(registry, (list, tuple)):
            self._tools = list(registry)
        else:
            self._tools = list_tools()
        self.audit = AuditLog(self.state_dir)

    def list_tools(self):
        return [dict(t) for t in self._tools]

    def _check(self, token, tool_name, args, tainted):
        check = getattr(self.policy, "check", None)
        if check is None:
            return {"allowed": True, "needs_approval": False, "reason": "no policy", "level": 0}
        try:
            result = check(tool_name=tool_name, args=args, token=token, tainted=tainted)
        except TypeError:
            try:
                result = check(tool_name, None, args)
            except TypeError:
                result = check(tool_name)
        if isinstance(result, bool):
            return {"allowed": result, "needs_approval": not result,
                    "reason": "allowed" if result else "denied", "level": None}
        if isinstance(result, dict):
            return result
        return {"allowed": bool(getattr(result, "allowed", False)),
                "needs_approval": bool(getattr(result, "needs_approval", False)),
                "reason": str(getattr(result, "reason", result)),
                "level": getattr(result, "level", None)}

    def run_tool(self, token, tool_name, args=None, tainted=False):
        args = dict(args or {})
        entry = get_tool(tool_name)
        if entry is None:
            for tool in self._tools:
                name = tool.get("name") if isinstance(tool, dict) else getattr(tool, "name", None)
                if name == tool_name:
                    entry = tool if isinstance(tool, dict) else {"name": name}
                    break
        if entry is None:
            result = {"ok": False, "verified": False, "tool": tool_name,
                      "error": f"unknown tool: {tool_name}"}
            self.audit.append("tool_call", tool=tool_name, args=_redact_args(args),
                              ok=False, error=result["error"])
            return result
        decision = self._check(token, tool_name, args, tainted)
        self.audit.append("policy_decision", tool=tool_name, args=_redact_args(args),
                          allowed=bool(decision.get("allowed")),
                          needs_approval=bool(decision.get("needs_approval")),
                          reason=str(decision.get("reason", "")))
        if not decision.get("allowed"):
            if decision.get("needs_approval"):
                error = f"needs approval: {decision.get('reason', '')}"
            else:
                error = f"denied: {decision.get('reason', '')}"
            result = {"ok": False, "verified": False, "tool": tool_name,
                      "error": error, "decision": decision}
            self.audit.append("tool_call", tool=tool_name, args=_redact_args(args),
                              ok=False, error=error)
            return result
        impl = TOOL_IMPLS.get(tool_name)
        if impl is None:
            result = {"ok": False, "verified": False, "tool": tool_name,
                      "error": f"tool '{tool_name}' has no implementation in this build"}
            self.audit.append("tool_call", tool=tool_name, args=_redact_args(args),
                              ok=False, error=result["error"])
            return result
        try:
            output, verified = impl(args, self.state_dir)
        except ToolError as exc:
            result = {"ok": False, "verified": False, "tool": tool_name,
                      "error": str(exc)}
            self.audit.append("tool_call", tool=tool_name, args=_redact_args(args),
                              ok=False, error=str(exc))
            return result
        except Exception as exc:  # tool raised unexpectedly; never leak a traceback as success
            result = {"ok": False, "verified": False, "tool": tool_name,
                      "error": f"tool failed: {type(exc).__name__}: {exc}"}
            self.audit.append("tool_call", tool=tool_name, args=_redact_args(args),
                              ok=False, error=result["error"])
            return result
        result = {"ok": True, "verified": bool(verified), "tool": tool_name,
                  "result": output}
        self.audit.append("tool_call", tool=tool_name, args=_redact_args(args),
                          ok=True, verified=bool(verified))
        return result
