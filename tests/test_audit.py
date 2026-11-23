"""Tests for the tamper-evident audit log (policy/audit.py)."""

import json
import multiprocessing as mp
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from policy.audit import AuditLog  # noqa: E402


def _append_many(path_str: str, worker: int, count: int) -> None:
    log = AuditLog(Path(path_str))
    for i in range(count):
        log.append({"type": "test", "worker": worker, "i": i})


def test_append_assigns_seq_and_chain(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    first = log.append({"type": "policy_decision", "tool": "read_file"})
    second = log.append({"type": "policy_decision", "tool": "write_file"})

    assert first["seq"] == 1
    assert first["prev_hash"] == "0" * 64
    assert len(first["hash"]) == 64
    assert "ts" in first
    assert second["seq"] == 2
    assert second["prev_hash"] == first["hash"]
    assert second["hash"] != first["hash"]

    entries = log.read_all()
    assert len(entries) == 2
    assert entries[0]["tool"] == "read_file"
    assert entries[1]["tool"] == "write_file"


def test_verify_passes_on_clean_log(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    for i in range(5):
        log.append({"type": "x", "i": i})
    valid, errors = log.verify()
    assert valid is True
    assert errors == []


def test_verify_fails_and_names_seq_after_tamper(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(3):
        log.append({"type": "x", "i": i})

    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[1])
    tampered["i"] = 999  # change a payload field, keep the stored hash
    lines[1] = json.dumps(tampered)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    valid, errors = log.verify()
    assert valid is False
    assert errors
    assert any("seq 2" in e for e in errors), errors


def test_verify_fails_when_hash_field_tampered(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append({"type": "x"})
    log.append({"type": "y"})

    lines = path.read_text(encoding="utf-8").splitlines()
    second = json.loads(lines[1])
    second["prev_hash"] = "f" * 64
    lines[1] = json.dumps(second)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    valid, errors = log.verify()
    assert valid is False
    assert any("seq 2" in e for e in errors), errors


def test_verify_empty_and_missing_log(tmp_path):
    log = AuditLog(tmp_path / "does-not-exist.jsonl")
    assert log.read_all() == []
    valid, errors = log.verify()
    assert valid is True
    assert errors == []


def test_concurrent_appends_from_two_processes_keep_chain(tmp_path):
    """Two processes appending at once must not interleave/corrupt the chain."""
    path = tmp_path / "audit.jsonl"
    ctx = mp.get_context("fork")
    with ctx.Pool(2) as pool:
        pool.starmap(_append_many, [(str(path), 0, 20), (str(path), 1, 20)])

    log = AuditLog(path)
    entries = log.read_all()
    assert len(entries) == 40
    assert sorted(e["seq"] for e in entries) == list(range(1, 41))
    valid, errors = log.verify()
    assert valid is True, errors
