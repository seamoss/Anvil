"""SCA fast-path triage tests: deps skip the LLM by default, opt-in via deep_deps."""

from __future__ import annotations

import json

from anvil.schemas.finding import (
    Finding,
    FindingStatus,
    Location,
    Pipeline,
    Severity,
)
from anvil.triage.engine import TriageEngine


class _Resp:
    stop_reason = "end_turn"
    usage = type("U", (), {k: 0 for k in
                ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")})()

    def __init__(self, text):
        self.content = [type("B", (), {"type": "text", "text": text})()]


class _Recorder:
    def __init__(self):
        self.calls = 0
        self.sent_ids = []

    def create(self, **kwargs):
        self.calls += 1
        payload = json.loads(kwargs["messages"][0]["content"])["findings"]
        ids = [f["finding_id"] for f in payload]
        self.sent_ids += ids
        return _Resp(json.dumps({"decisions": [{"finding_id": i, "status": "confirmed"} for i in ids]}))


class _Client:
    def __init__(self, rec):
        self.messages = rec


def _engine():
    eng = TriageEngine()
    rec = _Recorder()
    eng._client = _Client(rec)
    return eng, rec


def _f(source, i):
    return Finding(
        finding_id=f"{source}-{i}",
        engagement_id="E",
        pipeline=Pipeline.SAST,
        source_tool=source,
        rule_id=f"r{i}",
        title=f"{source} {i}",
        severity=Severity.HIGH,
        owasp_category="A06:2021-Vulnerable and Outdated Components" if source == "trivy" else None,
        cvss_score=7.5 if source == "trivy" else None,
        location=Location(file_path="requirements.txt" if source == "trivy" else "a.py", start_line=1),
    )


def test_sca_fast_pathed_by_default():
    eng, rec = _engine()
    findings = [_f("semgrep", 1), _f("semgrep", 2), _f("trivy", 1), _f("trivy", 2)]
    out = eng.triage(findings)  # deep_deps=False (default)

    # Only the non-SCA findings were sent to the LLM.
    assert set(rec.sent_ids) == {"semgrep-1", "semgrep-2"}
    # Trivy findings are marked reportable via fast-path, not dropped.
    trivy = [f for f in out if f.source_tool == "trivy"]
    assert all(f.status is FindingStatus.TRIAGED for f in trivy)
    assert all("fast-path" in (f.triage_note or "") for f in trivy)
    assert len(out) == 4


def test_deep_deps_sends_everything_to_llm():
    eng, rec = _engine()
    findings = [_f("semgrep", 1), _f("trivy", 1), _f("trivy", 2)]
    eng.triage(findings, deep_deps=True)
    assert set(rec.sent_ids) == {"semgrep-1", "trivy-1", "trivy-2"}


def test_all_sca_makes_no_llm_call():
    eng, rec = _engine()
    out = eng.triage([_f("trivy", 1), _f("trivy", 2)])  # default
    assert rec.calls == 0
    assert all(f.status is FindingStatus.TRIAGED for f in out)
