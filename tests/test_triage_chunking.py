"""Triage chunking + graceful-degradation tests (fake client, no network)."""

from __future__ import annotations

import json

import pytest

from anvil.schemas.finding import Finding, FindingStatus, Location, Pipeline, Severity
from anvil.triage.engine import _TRIAGE_CHUNK, TriageEngine


class _Usage:
    input_tokens = output_tokens = cache_creation_input_tokens = cache_read_input_tokens = 0


class _Resp:
    stop_reason = "end_turn"
    usage = _Usage()

    def __init__(self, text):
        self.content = [type("B", (), {"type": "text", "text": text})()]


class _Messages:
    def __init__(self, text_fn):
        self.calls = 0
        self._text_fn = text_fn

    def create(self, **kwargs):
        self.calls += 1
        return _Resp(self._text_fn(kwargs))


class _Client:
    def __init__(self, text_fn):
        self.messages = _Messages(text_fn)


def _findings(n):
    return [
        Finding(
            finding_id=f"id{i}",
            engagement_id="E",
            pipeline=Pipeline.SAST,
            source_tool="semgrep",
            rule_id=f"r{i}",
            title=f"f{i}",
            severity=Severity.MEDIUM,
            location=Location(file_path=f"f{i}.py", start_line=1),
        )
        for i in range(n)
    ]


def _confirm_all(kwargs):
    """Return a valid decision confirming every finding in the request."""
    payload = json.loads(kwargs["messages"][0]["content"])["findings"]
    return json.dumps({"decisions": [{"finding_id": f["finding_id"], "status": "confirmed"} for f in payload]})


def _engine(text_fn):
    eng = TriageEngine()
    eng._client = _Client(text_fn)
    return eng


def test_chunks_large_sets_into_multiple_calls():
    eng = _engine(_confirm_all)
    n = _TRIAGE_CHUNK * 2 + 3  # 43
    out = eng.triage(_findings(n))
    assert eng._client.messages.calls == 3  # ceil(43/20)
    assert all(f.status is FindingStatus.CONFIRMED for f in out)


def test_single_chunk_when_small():
    eng = _engine(_confirm_all)
    eng.triage(_findings(5))
    assert eng._client.messages.calls == 1


def test_garbage_response_degrades_without_crashing():
    # Simulate a truncated / invalid JSON response (the DSVW crash scenario).
    eng = _engine(lambda kw: '{"decisions": [{"finding_id": "id0", "sta')  # unterminated
    out = eng.triage(_findings(3))
    # No exception, and findings are retained (heuristic fallback), not dropped.
    assert len(out) == 3
    assert all(f.status is not FindingStatus.NEW for f in out)
    assert any("parse failed" in (f.triage_note or "") for f in out)


def test_undecided_findings_retained_not_dropped():
    # Model returns an empty decision list → findings must not silently vanish.
    eng = _engine(lambda kw: '{"decisions": []}')
    out = eng.triage(_findings(4))
    assert all(f.status is FindingStatus.TRIAGED for f in out)
