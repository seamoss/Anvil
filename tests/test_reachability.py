"""Tier-2 reachability analyzer tests (fake client, no network)."""

from __future__ import annotations

import json

from anvil.enrich.reachability import ReachabilityAnalyzer
from anvil.schemas.finding import (
    Finding,
    FindingStatus,
    Location,
    Pipeline,
    Reachability,
    Severity,
)


class _Usage:
    input_tokens = output_tokens = cache_creation_input_tokens = cache_read_input_tokens = 0


class _Resp:
    stop_reason = "end_turn"
    usage = _Usage()

    def __init__(self, text):
        self.content = [type("B", (), {"type": "text", "text": text})()]


class _Messages:
    def __init__(self, fn):
        self.calls = 0
        self.sent_ids = []
        self._fn = fn

    def create(self, **kwargs):
        self.calls += 1
        payload = json.loads(kwargs["messages"][0]["content"])["findings"]
        self.sent_ids += [f["finding_id"] for f in payload]
        return _Resp(self._fn(payload))


class _Client:
    def __init__(self, fn):
        self.messages = _Messages(fn)


def _reachable_all(payload):
    return json.dumps({"decisions": [
        {"finding_id": f["finding_id"], "reachability": "reachable",
         "entry_point": "POST /x", "rationale": "r"} for f in payload
    ]})


def _engine(fn=_reachable_all):
    a = ReachabilityAnalyzer()
    a._client = _Client(fn)
    return a


def mk(fid, source="semgrep", severity=Severity.HIGH, reach=Reachability.UNKNOWN,
       local=False, status=FindingStatus.CONFIRMED):
    return Finding(
        finding_id=fid, engagement_id="E", pipeline=Pipeline.SAST, source_tool=source,
        rule_id="r", title="t", severity=severity, reachability=reach, local_only=local,
        status=status, location=Location(file_path="a.py", start_line=1),
    )


def test_only_eligible_findings_are_analyzed():
    a = _engine()
    findings = [
        mk("ok", source="semgrep"),                       # eligible
        mk("codeql", source="codeql"),                    # not a pattern tool
        mk("secret", source="gitleaks"),                  # not eligible
        mk("already", reach=Reachability.REACHABLE),      # already resolved
        mk("low", severity=Severity.LOW),                 # below floor
        mk("local", local=True),                          # local-only
    ]
    a.analyze(findings, repo_path="/nonexistent")
    assert a._client.messages.sent_ids == ["ok"]
    ok = next(f for f in findings if f.finding_id == "ok")
    assert ok.reachability is Reachability.REACHABLE
    assert ok.reachability_source == "llm"
    assert ok.entry_point == "POST /x"


def test_offline_is_noop():
    a = ReachabilityAnalyzer(api_key=None)
    a._client = None
    f = mk("x")
    a.analyze([f], repo_path="/x")
    assert f.reachability is Reachability.UNKNOWN  # unchanged


def test_garbage_response_leaves_unknown():
    a = _engine(lambda payload: '{"decisions": [ {bad json')
    f = mk("x")
    a.analyze([f], repo_path="/x")
    assert f.reachability is Reachability.UNKNOWN  # never worse


def test_no_eligible_makes_no_call():
    a = _engine()
    a.analyze([mk("s", source="gitleaks")], repo_path="/x")
    assert a._client.messages.calls == 0


def test_code_window_reads_around_line(tmp_path):
    src = tmp_path / "app.py"
    src.write_text("\n".join(f"line{i}" for i in range(1, 101)))
    window = ReachabilityAnalyzer._code_window(str(tmp_path), "app.py", 50, radius=3)
    assert "47: line47" in window
    assert "53: line53" in window
    assert "line10" not in window
