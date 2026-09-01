"""Guardrails for prompt caching.

Caching is a prefix match, so it silently breaks if anyone (a) drops a
cache_control marker, (b) reorders so volatile content precedes a cached block,
or (c) exceeds the 4-breakpoint limit. These tests pin the request *structure*
using a fake client, so they run offline and cost nothing — and they fail loudly
the moment the caching contract regresses.
"""

from __future__ import annotations

import json

import pytest

from anvil.schemas.finding import Finding, Location, Pipeline, Severity
from anvil.triage.engine import _EPHEMERAL, _LOGIC_SYSTEM, _SYSTEM, TriageEngine


# --- fake Anthropic client -------------------------------------------------
class _Usage:
    input_tokens = 0
    output_tokens = 0
    cache_creation_input_tokens = 0
    cache_read_input_tokens = 0


class _Block:
    type = "text"
    # Satisfies both parsers (triage wants "decisions", logic wants "findings").
    text = json.dumps({"decisions": [], "findings": []})


class _Resp:
    stop_reason = "end_turn"
    usage = _Usage()
    content = [_Block()]


class _Messages:
    def __init__(self):
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return _Resp()


class FakeClient:
    def __init__(self):
        self.messages = _Messages()


@pytest.fixture
def online_engine():
    eng = TriageEngine()
    eng._client = FakeClient()  # force online without a real key or network
    assert eng.online is True
    return eng


def _count_breakpoints(kwargs) -> int:
    n = 0
    for block in kwargs.get("system", []):
        n += "cache_control" in block
    for msg in kwargs.get("messages", []):
        content = msg["content"]
        if isinstance(content, list):
            for block in content:
                n += isinstance(block, dict) and "cache_control" in block
    return n


def _last_block_is_volatile(kwargs) -> bool:
    """The final content block sent must NOT carry a cache breakpoint."""
    last_msg_content = kwargs["messages"][-1]["content"]
    if isinstance(last_msg_content, str):
        return True  # a bare string is inherently uncached
    return "cache_control" not in last_msg_content[-1]


# --- triage ----------------------------------------------------------------
def test_triage_caches_rubric(online_engine):
    f = Finding(
        finding_id="id-abc",
        engagement_id="E",
        pipeline=Pipeline.SAST,
        source_tool="semgrep",
        rule_id="r",
        title="t",
        severity=Severity.HIGH,
        location=Location(file_path="a.py", start_line=1),
    )
    online_engine.triage([f])
    kwargs = online_engine._client.messages.calls[0]

    system = kwargs["system"]
    assert isinstance(system, list)
    assert system[0]["text"] == _SYSTEM
    assert system[0]["cache_control"] == _EPHEMERAL


def test_triage_findings_are_volatile_after_the_cached_prefix(online_engine):
    f = Finding(
        finding_id="id-xyz",
        engagement_id="E",
        pipeline=Pipeline.SAST,
        source_tool="semgrep",
        rule_id="r",
        title="t",
        location=Location(file_path="a.py", start_line=1),
    )
    online_engine.triage([f])
    kwargs = online_engine._client.messages.calls[0]

    content = kwargs["messages"][0]["content"]
    assert isinstance(content, str)  # not a cached block
    assert "id-xyz" in content  # the volatile payload lives here, last
    assert _last_block_is_volatile(kwargs)


def test_triage_request_shape(online_engine):
    f = Finding(
        finding_id="id-1", engagement_id="E", pipeline=Pipeline.SAST,
        source_tool="semgrep", rule_id="r", title="t",
        location=Location(file_path="a.py", start_line=1),
    )
    online_engine.triage([f])
    kwargs = online_engine._client.messages.calls[0]
    assert kwargs["model"] == online_engine.model
    assert kwargs["thinking"] == {"type": "adaptive"}
    assert kwargs["output_config"] == {"effort": "high"}


# --- logic review ----------------------------------------------------------
def test_logic_review_caches_rubric_and_bundle(online_engine):
    online_engine.logic_review("E", {"a.py": "def f():\n    pass\n"}, "ref")
    kwargs = online_engine._client.messages.calls[0]

    # rubric cached in system
    assert kwargs["system"][0]["text"] == _LOGIC_SYSTEM
    assert kwargs["system"][0]["cache_control"] == _EPHEMERAL

    blocks = kwargs["messages"][0]["content"]
    assert isinstance(blocks, list) and len(blocks) == 2
    bundle, ask = blocks

    # cached-first: the big per-repo source bundle carries a breakpoint
    assert bundle["cache_control"] == _EPHEMERAL
    assert "a.py" in bundle["text"]

    # volatile-last: the trailing ask must NOT be cached
    assert "cache_control" not in ask
    assert _last_block_is_volatile(kwargs)


def test_breakpoint_budget_respected(online_engine):
    """Never exceed the API's 4 cache breakpoints per request."""
    f = Finding(
        finding_id="id-1", engagement_id="E", pipeline=Pipeline.SAST,
        source_tool="semgrep", rule_id="r", title="t",
        location=Location(file_path="a.py", start_line=1),
    )
    online_engine.triage([f])
    online_engine.logic_review("E", {"a.py": "code"}, "ref")
    for kwargs in online_engine._client.messages.calls:
        assert _count_breakpoints(kwargs) <= 4


def test_ephemeral_marker_is_valid():
    assert _EPHEMERAL == {"type": "ephemeral"}
