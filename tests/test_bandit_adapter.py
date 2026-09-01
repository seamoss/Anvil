"""Bandit adapter mapping tests (using the real bandit JSON record shape)."""

from __future__ import annotations

from anvil.pipelines.sast.bandit import BanditAdapter
from anvil.schemas.finding import Confidence, Pipeline, Severity

A = BanditAdapter()

REC = {
    "filename": "app.py",
    "line_number": 31,
    "line_range": [31, 32],
    "col_offset": 4,
    "code": "subprocess.check_output('ping -c 1 ' + host, shell=True)",
    "issue_confidence": "HIGH",
    "issue_severity": "HIGH",
    "issue_cwe": {"id": 78, "link": "https://cwe.mitre.org/data/definitions/78.html"},
    "issue_text": "subprocess call with shell=True identified.",
    "test_id": "B602",
    "test_name": "subprocess_popen_with_shell_equals_true",
    "more_info": "https://bandit.readthedocs.io/",
}


def test_bandit_mapping():
    f = A._to_finding("E", REC, "ref")
    assert f.source_tool == "bandit"
    assert f.pipeline is Pipeline.SAST
    assert f.rule_id == "B602"
    assert f.severity is Severity.HIGH
    assert f.confidence is Confidence.HIGH
    assert f.cwe == ["CWE-78"]
    assert f.location.file_path == "app.py"
    assert f.location.start_line == 31
    assert f.location.end_line == 32
    assert "shell=True" in (f.location.snippet or "")


def test_bandit_without_cwe():
    rec = dict(REC, issue_cwe={})
    assert A._to_finding("E", rec, "ref").cwe == []


def test_bandit_severity_map():
    assert A._to_finding("E", dict(REC, issue_severity="LOW"), "r").severity is Severity.LOW
    assert A._to_finding("E", dict(REC, issue_severity="MEDIUM"), "r").severity is Severity.MEDIUM
