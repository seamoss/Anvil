from __future__ import annotations

from anvil.schemas.finding import Finding, FindingStatus, Location, Pipeline, Severity
from anvil.triage.engine import TriageEngine


def _finding(cwe):
    return Finding(
        finding_id=Finding.make_id("E", "semgrep", "r", "a.py:1"),
        engagement_id="E",
        pipeline=Pipeline.SAST,
        source_tool="semgrep",
        rule_id="r",
        title="t",
        severity=Severity.HIGH,
        cwe=cwe,
        location=Location(file_path="a.py", start_line=1),
    )


def test_engine_is_offline_without_key():
    # hermetic_env unsets ANTHROPIC_API_KEY and blocks .env loading.
    assert TriageEngine().online is False


def test_offline_triage_maps_cwe_to_owasp():
    eng = TriageEngine()
    out = eng.triage([_finding(["CWE-89"]), _finding(["CWE-327"])])
    assert out[0].owasp_category == "A03:2021-Injection"
    assert out[1].owasp_category == "A02:2021-Cryptographic Failures"
    assert all(f.status is FindingStatus.TRIAGED for f in out)


def test_offline_triage_empty_input():
    assert TriageEngine().triage([]) == []


def test_offline_logic_review_returns_empty():
    # No network / no client offline; logic pass is a no-op.
    assert TriageEngine().logic_review("E", {"a.py": "code"}, "ref") == []
