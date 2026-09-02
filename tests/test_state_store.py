"""State store tests: cross-run diffing and suppressions."""

from __future__ import annotations

import pytest

from anvil.schemas.finding import Finding, FindingStatus, Location, Pipeline, Severity
from anvil.state.store import StateStore


@pytest.fixture
def store(tmp_path):
    s = StateStore(tmp_path / "anvil.db")
    yield s
    s.close()


def mk(fid, status=FindingStatus.CONFIRMED, rule_id="r", source="semgrep"):
    return Finding(
        finding_id=fid,
        engagement_id="E",
        pipeline=Pipeline.SAST,
        source_tool=source,
        rule_id=rule_id,
        title=f"finding {fid}",
        severity=Severity.HIGH,
        status=status,
        location=Location(file_path=f"{fid}.py", start_line=1),
    )


# --- diffing ---------------------------------------------------------------
def test_first_run_all_new(store):
    diff = store.record_run("E", [mk("a"), mk("b")])
    assert sorted(diff.new) == ["a", "b"]
    assert diff.resolved == [] and diff.existing == []
    assert diff.is_first_run


def test_second_identical_run_all_existing(store):
    store.record_run("E", [mk("a"), mk("b")])
    diff = store.record_run("E", [mk("a"), mk("b")])
    assert diff.new == []
    assert sorted(diff.existing) == ["a", "b"]
    assert diff.resolved == []


def test_resolved_when_finding_disappears(store):
    store.record_run("E", [mk("a"), mk("b")])
    diff = store.record_run("E", [mk("a")])  # b fixed
    assert diff.resolved == ["b"]
    assert diff.existing == ["a"]
    assert diff.new == []


def test_new_finding_in_later_run(store):
    store.record_run("E", [mk("a")])
    diff = store.record_run("E", [mk("a"), mk("c")])
    assert diff.new == ["c"]
    assert diff.existing == ["a"]


def test_reappearance_counts_as_new(store):
    store.record_run("E", [mk("a")])
    store.record_run("E", [])            # a resolved
    diff = store.record_run("E", [mk("a")])  # a reappears
    assert diff.new == ["a"]


def test_only_reportable_findings_tracked(store):
    diff = store.record_run("E", [mk("a"), mk("b", status=FindingStatus.FALSE_POSITIVE)])
    assert diff.new == ["a"]  # false positive not tracked


def test_duplicate_finding_ids_in_one_run(store):
    # Same finding_id twice in a run (e.g. one CVE across two lockfiles) must not
    # crash on the UNIQUE constraint — it's one logical finding.
    a1, a2 = mk("dup"), mk("dup")
    diff = store.record_run("E", [a1, a2])
    assert diff.new == ["dup"]
    # and a clean re-run still recognizes it as existing, not new
    assert store.record_run("E", [mk("dup")]).existing == ["dup"]


def test_engagements_are_isolated(store):
    store.record_run("E", [mk("a")])
    diff = store.record_run("OTHER", [mk("a")])
    assert diff.new == ["a"]  # same id, different engagement → still new there


def test_history_and_count(store):
    store.record_run("E", [mk("a")], target="/repo")
    store.record_run("E", [mk("a")], target="/repo")
    assert store.previous_run_count("E") == 2
    assert len(store.history("E")) == 2


# --- suppressions ----------------------------------------------------------
def test_suppress_by_finding_id(store):
    store.add_suppression("finding_id", "a", reason="accepted risk", by="sec@org")
    findings = [mk("a"), mk("b")]
    n = store.apply_suppressions(findings)
    assert n == 1
    assert findings[0].suppressed is True
    assert findings[1].suppressed is False


def test_suppress_by_rule_id(store):
    store.add_suppression("rule_id", "noisy-rule")
    findings = [mk("a", rule_id="noisy-rule"), mk("b", rule_id="other")]
    store.apply_suppressions(findings)
    assert findings[0].suppressed is True
    assert findings[1].suppressed is False


def test_list_and_remove_suppression(store):
    store.add_suppression("finding_id", "a", reason="x")
    assert len(store.list_suppressions()) == 1
    store.remove_suppression("finding_id", "a")
    assert store.list_suppressions() == []


def test_invalid_suppression_scope(store):
    with pytest.raises(ValueError):
        store.add_suppression("bogus", "a")
