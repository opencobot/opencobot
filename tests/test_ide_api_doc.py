"""Doc-consistency test for docs/IDE_API.md.

The ops listed in the protocol doc (``### `op` `` headings under
"## Ops") must exist in ``Daemon.handle_request``: a minimal
request for each one must NOT come back as "unknown op". This keeps
the any-IDE contract honest — a client built from the doc alone
must be able to call every op the doc promises.

Scripted fake gateway + real Runtime + allow-all fake policy
client; no network, no real models, no real policyd.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from core.daemon import Daemon  # noqa: E402

DOC = REPO_ROOT / "docs" / "IDE_API.md"


def _doc_ops() -> list[str]:
    """Op names from the doc's `### `op`` headings."""
    ops: list[str] = []
    in_ops = False
    for line in DOC.read_text().splitlines():
        if line.startswith("## Ops"):
            in_ops = True
            continue
        if in_ops and line.startswith("## "):
            break
        if in_ops and line.startswith("### "):
            ops.extend(re.findall(r"`([a-z_]+)`", line))
    return ops


class _FakeGateway:
    def __init__(self):
        self.configs = [SimpleNamespace(name="arch", model="fake-model"),
                        SimpleNamespace(name="w1", model="fake-model")]
        self._roles: dict[str, str] = {}
        self.calls: list[tuple] = []

    def set_role_provider(self, role, name):
        self._roles[role] = name

    def role_provider(self, role):
        return self._roles.get(role) or self.configs[0].name

    def ping(self, config):
        return True

    def complete(self, role, prompt, sensitivity, **kwargs):
        self.calls.append((role, prompt, sensitivity))
        if role == "PLANNER":
            return {"text": json.dumps({"subtasks": [{
                "title": "say hi", "goal": "say hi", "context": "",
                "provider": "w1", "output": {"kind": "text"},
                "checks": [], "sensitivity": "public",
                "verify_model": False}]}),
                "provider": "arch", "role": role,
                "cost_estimate": 0.0, "needs_approval": False,
                "escalated": False}
        return {"text": "hi", "provider": "w1", "role": role,
                "cost_estimate": 0.0, "needs_approval": False,
                "escalated": False}


class _AllowPolicy:
    def is_killed(self):
        return False

    def status(self):
        return {"reachable": True, "killed": False}

    def ping(self):
        return {"reachable": True}

    def get_readonly(self):
        return False

    def set_readonly(self, enabled):
        return bool(enabled)

    def kill(self):
        return None

    def unkill(self):
        return None

    def check(self, token, tool_name, level, args, tainted=False,
              network_call=False):
        return {"allowed": True, "reason": "allowed",
                "needs_approval": False}


@pytest.fixture()
def daemon(tmp_path, monkeypatch):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    ws = tmp_path / "ws"
    ws.mkdir()
    gw_config = tmp_path / "gateway.json"
    gw_config.write_text(json.dumps({"providers": []}))
    monkeypatch.setenv("OPENCOBOT_GATEWAY_CONFIG", str(gw_config))
    monkeypatch.setattr(Daemon, "_policy_client",
                        lambda self: _AllowPolicy())
    d = Daemon(state_dir=state_dir, gateway=_FakeGateway())
    return d, ws


def _minimal_requests(ws: Path) -> dict[str, dict]:
    token = {"folders": [str(ws)]}
    return {
        "status": {},
        "readonly_get": {},
        "readonly_set": {"enabled": False},
        "list_tools": {},
        "run_tool": {"tool_name": "system_info", "args": {},
                     "token": token},
        "kill": {},
        "unkill": {},
        "gateway_status": {},
        "orchestrator_run": {"task": "say hi", "token": token,
                             "workspace": str(ws)},
        "orchestrator_status": {"run_id": "nope"},
        "orchestrator_retry": {"run_id": "nope", "token": token,
                               "workspace": str(ws)},
    }


def test_doc_lists_ops(daemon):
    ops = _doc_ops()
    assert ops, "no ops parsed from docs/IDE_API.md"
    assert {"orchestrator_run", "orchestrator_status",
            "orchestrator_retry"} <= set(ops)
    assert set(ops) <= set(_minimal_requests(daemon[1]))


def test_every_doc_op_exists(daemon):
    d, ws = daemon
    minimal = _minimal_requests(ws)
    for op in _doc_ops():
        req = {"auth": d.auth_token, "op": op}
        req.update(minimal[op])
        reply = d.handle_request(req)
        assert isinstance(reply, dict), op
        assert reply.get("error", "") != f"unknown op: {op}", op


def test_doc_example_run_completes(daemon):
    """The doc's worked example, end to end (text subtask, no files)."""
    d, ws = daemon
    status = d.handle_request({"auth": d.auth_token, "op": "status"})
    assert status["ok"] is True
    assert status["policyd_reachable"] is True
    run = d.handle_request({
        "auth": d.auth_token, "op": "orchestrator_run",
        "task": "say hi",
        "token": {"folders": [str(ws)]},
        "workspace": str(ws), "sensitivity": "public"})
    assert run["ok"] is True
    assert run["run"]["ok"] is True
    assert run["run"]["done"] == ["say hi"]
    again = d.handle_request(
        {"auth": d.auth_token, "op": "orchestrator_status",
         "run_id": run["run"]["run_id"]})
    assert again["ok"] is True
    assert again["run"]["run_id"] == run["run"]["run_id"]
