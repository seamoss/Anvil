"""Contextual risk scoring tests."""

from __future__ import annotations

from anvil.enrich.risk import enrich, score
from anvil.schemas.authorization import AssetContext, Criticality
from anvil.schemas.finding import (
    Finding,
    FindingStatus,
    Location,
    Pipeline,
    Priority,
    Reachability,
    Severity,
)


def mk(source="semgrep", severity=Severity.HIGH, reach=Reachability.UNKNOWN,
       cvss=None, status=FindingStatus.CONFIRMED):
    return Finding(
        finding_id="x", engagement_id="E", pipeline=Pipeline.SAST, source_tool=source,
        title="t", severity=severity, reachability=reach, cvss_score=cvss, status=status,
        location=Location(file_path="a.py", start_line=1),
    )


def test_reachable_crownjewel_internet_is_p1():
    asset = AssetContext(criticality=Criticality.CROWN_JEWEL, internet_facing=True)
    s, p, _ = score(mk(reach=Reachability.REACHABLE), asset)
    assert s == 75.0  # 7.5 × 1 × 1 × 1 × 10
    assert p is Priority.P1


def test_unreachable_low_internal_is_p4():
    asset = AssetContext(criticality=Criticality.LOW, internet_facing=False)
    _, p, _ = score(mk(reach=Reachability.UNREACHABLE), asset)
    assert p is Priority.P4  # 7.5 × 0.2 × 0.4 × 0.6 × 10 = 3.6


def test_context_flips_ranking():
    # A reachable MEDIUM on a crown-jewel internet asset outranks an unreachable
    # HIGH on a low internal asset — the whole point of contextual risk.
    hot = score(mk(severity=Severity.MEDIUM, reach=Reachability.REACHABLE),
                AssetContext(criticality=Criticality.CROWN_JEWEL, internet_facing=True))[0]
    cold = score(mk(severity=Severity.HIGH, reach=Reachability.UNREACHABLE),
                 AssetContext(criticality=Criticality.LOW, internet_facing=False))[0]
    assert hot > cold


def test_deps_ignore_reachability():
    # A critical dependency CVE isn't penalized for unknown reachability.
    _, p, _ = score(
        mk(source="trivy", severity=Severity.CRITICAL, reach=Reachability.UNKNOWN, cvss=9.8),
        AssetContext(criticality=Criticality.STANDARD, internet_facing=True),
    )
    assert p is Priority.P1  # 9.8 × 1 × 0.7 × 1 × 10 = 68.6


def test_no_asset_uses_defaults():
    _, p, _ = score(mk(severity=Severity.MEDIUM, reach=Reachability.REACHABLE), None)
    assert p is Priority.P3  # 5 × 1 × 0.7 × 0.8 × 10 = 28


def test_enrich_scores_only_reportable():
    ok = mk(status=FindingStatus.CONFIRMED)
    fp = mk(status=FindingStatus.FALSE_POSITIVE)
    enrich([ok, fp], AssetContext())
    assert ok.priority is not None and ok.risk_score is not None
    assert fp.priority is None
