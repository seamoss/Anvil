"""Contextual risk scoring — priority beyond raw CVSS.

    risk = base(CVSS/severity) × reachability × asset_criticality × exposure

Reachability only weights code-analysis findings (where "can input reach the
sink" is meaningful); dependency/secret/DAST findings use their own severity
directly. The result is a 0-100 score and a P1-P4 band, so a reachable medium on
an internet-facing crown-jewel outranks an unreachable high on an internal tool.
"""

from __future__ import annotations

from typing import Optional, Tuple

from anvil.schemas.authorization import AssetContext, Criticality
from anvil.schemas.finding import (
    Finding,
    FindingStatus,
    Priority,
    Reachability,
    Severity,
)

_SEVERITY_BASE = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.5,
    Severity.INFO: 1.0,
}
_REACH_MULT = {
    Reachability.REACHABLE: 1.0,
    Reachability.UNKNOWN: 0.6,
    Reachability.UNREACHABLE: 0.2,
}
_CRIT_MULT = {
    Criticality.CROWN_JEWEL: 1.0,
    Criticality.STANDARD: 0.7,
    Criticality.LOW: 0.4,
}
# Tools where reachability is a meaningful weight (code analysis).
_CODE_TOOLS = {"semgrep", "codeql", "bandit", "llm-logic"}
_REPORTABLE = {FindingStatus.CONFIRMED, FindingStatus.TRIAGED}


def _base(f: Finding) -> float:
    if f.cvss_score is not None:
        return min(float(f.cvss_score), 10.0)
    return _SEVERITY_BASE[f.severity]


def _exposure(asset: Optional[AssetContext]) -> float:
    if asset is None or asset.internet_facing is None:
        return 0.8  # unknown exposure — mild default
    return 1.0 if asset.internet_facing else 0.6


def _priority(score: float) -> Priority:
    if score >= 60:
        return Priority.P1
    if score >= 35:
        return Priority.P2
    if score >= 15:
        return Priority.P3
    return Priority.P4


def score(f: Finding, asset: Optional[AssetContext] = None) -> Tuple[float, Priority, str]:
    base = _base(f)
    reach = _REACH_MULT[f.reachability] if f.source_tool in _CODE_TOOLS else 1.0
    crit = _CRIT_MULT[asset.criticality] if asset else _CRIT_MULT[Criticality.STANDARD]
    expo = _exposure(asset)
    # Local/dev-only findings are real but lower production risk — down-weight so
    # production issues out-rank a dev's local config in the priority ranking.
    local_mult = 0.5 if f.local_only else 1.0

    risk = round(base * reach * crit * expo * local_mult * 10, 1)
    rationale = (
        f"base {base:.1f} × reach {reach:g} × "
        f"{(asset.criticality.value if asset else 'standard')} {crit:g} × exposure {expo:g}"
        + (" × local 0.5" if f.local_only else "")
    )
    return risk, _priority(risk), rationale


def enrich(findings, asset: Optional[AssetContext] = None) -> None:
    """Score reportable findings in place with risk_score / priority / rationale."""
    for f in findings:
        if f.status in _REPORTABLE:
            f.risk_score, f.priority, f.risk_rationale = score(f, asset)
