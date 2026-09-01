"""CodeQL adapter tests — SARIF parsing, CWE extraction, language detection."""

from __future__ import annotations

from anvil.pipelines.sast.codeql import CodeqlAdapter
from anvil.schemas.finding import Confidence, Pipeline, Severity

A = CodeqlAdapter()

SARIF = {
    "runs": [
        {
            "tool": {"driver": {"rules": [
                {
                    "id": "py/sql-injection",
                    "shortDescription": {"text": "SQL query built from user-controlled sources"},
                    "properties": {"security-severity": "8.8", "tags": ["security", "external/cwe/cwe-089"]},
                    "help": {"text": "Use parameterized queries."},
                },
                {
                    "id": "py/clear-text-logging",
                    "properties": {"tags": ["external/cwe/cwe-312"]},
                    "defaultConfiguration": {"level": "note"},
                },
            ]}},
            "results": [
                {
                    "ruleId": "py/sql-injection",
                    "message": {"text": "This SQL query depends on a user-provided value."},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "app/db.py"},
                        "region": {"startLine": 42, "endLine": 42, "snippet": {"text": "cursor.execute(q)"}},
                    }}],
                },
                {
                    "ruleId": "py/clear-text-logging",
                    "message": {"text": "Sensitive data logged in clear text."},
                    "locations": [{"physicalLocation": {
                        "artifactLocation": {"uri": "app/log.py"},
                        "region": {"startLine": 7},
                    }}],
                },
            ],
        }
    ]
}


def test_parse_counts():
    findings = A.parse_sarif("E", SARIF, "ref")
    assert len(findings) == 2
    assert all(f.pipeline is Pipeline.SAST and f.source_tool == "codeql" for f in findings)


def test_security_severity_and_cwe():
    by_id = {f.rule_id: f for f in A.parse_sarif("E", SARIF, "ref")}
    sqli = by_id["py/sql-injection"]
    assert sqli.severity is Severity.HIGH  # 8.8 → high
    assert sqli.cwe == ["CWE-89"]
    assert sqli.confidence is Confidence.HIGH
    assert sqli.location.file_path == "app/db.py"
    assert sqli.location.start_line == 42
    assert "parameterized" in sqli.remediation.lower()
    assert "SQL query" in sqli.title


def test_level_fallback_when_no_security_severity():
    by_id = {f.rule_id: f for f in A.parse_sarif("E", SARIF, "ref")}
    note = by_id["py/clear-text-logging"]
    assert note.severity is Severity.LOW  # level "note" → low
    assert note.cwe == ["CWE-312"]


def test_severity_from_score_bands():
    assert A._to_finding("E", {"ruleId": "r"}, {"r": {"properties": {"security-severity": "9.5"}}}, "x").severity is Severity.CRITICAL
    assert A._to_finding("E", {"ruleId": "r"}, {"r": {"properties": {"security-severity": "5.0"}}}, "x").severity is Severity.MEDIUM


def test_cwe_extraction_strips_leading_zeros():
    assert A._cwes(["external/cwe/cwe-079", "external/cwe/cwe-089", "security"]) == ["CWE-79", "CWE-89"]


def test_empty_sarif():
    assert A.parse_sarif("E", {"runs": []}, "ref") == []


def test_detect_language(tmp_path):
    (tmp_path / "a.py").write_text("x=1")
    (tmp_path / "b.py").write_text("y=2")
    (tmp_path / "c.js").write_text("var z")
    assert CodeqlAdapter.detect_language(str(tmp_path)) == "python"


def test_detect_language_none(tmp_path):
    (tmp_path / "readme.txt").write_text("hi")
    assert CodeqlAdapter.detect_language(str(tmp_path)) is None
