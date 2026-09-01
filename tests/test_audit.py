from __future__ import annotations

from anvil.controller.audit import AuditLog


def test_empty_log_verifies(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    assert log.verify_chain() is True


def test_appends_and_verifies(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record("scan_started", {"target": "/repo"})
    log.record("scanner_completed", {"findings": 3})
    log.record("report_written", {"path": "report.md"})
    assert log.verify_chain() is True


def test_edit_breaks_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.record("a", {"x": 1})
    log.record("b", {"x": 2})
    assert log.verify_chain() is True

    # Tamper with a recorded value without recomputing hashes.
    text = path.read_text()
    assert '{"x":2}' in text
    path.write_text(text.replace('{"x":2}', '{"x":99}'))
    assert log.verify_chain() is False


def test_deleting_an_entry_breaks_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.record("a", {})
    log.record("b", {})
    log.record("c", {})
    lines = path.read_text().splitlines()
    # Drop the middle entry — the prev_hash linkage must fail.
    path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    assert log.verify_chain() is False


def test_new_records_chain_onto_existing_file(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLog(path).record("first", {})
    # A fresh AuditLog over the same file must continue the chain, not reset it.
    log2 = AuditLog(path)
    log2.record("second", {})
    assert log2.verify_chain() is True
    assert len(path.read_text().splitlines()) == 2
