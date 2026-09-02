"""Reachability harvesting from CodeQL codeFlows and semgrep dataflow_trace."""

from __future__ import annotations

from anvil.pipelines.sast.codeql import CodeqlAdapter
from anvil.pipelines.sast.semgrep import SemgrepAdapter
from anvil.schemas.finding import Reachability


# --- CodeQL codeFlows ------------------------------------------------------
def _codeql_result(with_flow: bool):
    r = {
        "ruleId": "py/sql-injection",
        "message": {"text": "tainted query"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "db.py"}, "region": {"startLine": 42}}}],
    }
    if with_flow:
        r["codeFlows"] = [{"threadFlows": [{"locations": [
            {"location": {"physicalLocation": {
                "artifactLocation": {"uri": "routes.py"}, "region": {"startLine": 10}}}},
            {"location": {"physicalLocation": {
                "artifactLocation": {"uri": "db.py"}, "region": {"startLine": 42}}}},
        ]}]}]
    return r


_RULES = {"py/sql-injection": {"properties": {"security-severity": "8.8", "tags": ["external/cwe/cwe-089"]}}}


def test_codeql_flow_marks_reachable_with_path():
    f = CodeqlAdapter()._to_finding("E", _codeql_result(True), _RULES, "ref")
    assert f.reachability is Reachability.REACHABLE
    assert f.reachability_source == "codeql-flow"
    assert f.taint_path == ["routes.py:10", "db.py:42"]


def test_codeql_without_flow_is_unknown():
    f = CodeqlAdapter()._to_finding("E", _codeql_result(False), _RULES, "ref")
    assert f.reachability is Reachability.UNKNOWN
    assert f.taint_path == []


# --- semgrep dataflow_trace ------------------------------------------------
def _semgrep_result(with_trace: bool):
    extra = {"message": "m", "severity": "ERROR", "metadata": {}, "lines": "x"}
    if with_trace:
        extra["dataflow_trace"] = {
            "taint_source": [{"path": "routes.py", "start": {"line": 10}}],
            "taint_sink": [{"path": "db.py", "start": {"line": 42}}],
        }
    return {"check_id": "py.taint.sqli", "path": "db.py",
            "start": {"line": 42}, "end": {"line": 42}, "extra": extra}


def test_semgrep_trace_marks_reachable():
    f = SemgrepAdapter()._to_finding("E", _semgrep_result(True), "ref")
    assert f.reachability is Reachability.REACHABLE
    assert f.reachability_source == "semgrep-trace"
    assert "routes.py:10" in f.taint_path
    assert "db.py:42" in f.taint_path


def test_semgrep_pattern_rule_is_unknown():
    f = SemgrepAdapter()._to_finding("E", _semgrep_result(False), "ref")
    assert f.reachability is Reachability.UNKNOWN
    assert f.taint_path == []
