"""Report generator — renders confirmed findings into a compliance Markdown
report mapped to OWASP Top 10 (2021), SOC 2 Trust Services Criteria, and
CWE/CVSS. Every finding line carries its evidence_ref so a reviewer can trace it
back to the exact scanner output in the evidence store.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List

from anvil.schemas.finding import Finding, FindingStatus, Severity

# OWASP Top-10 categories → the SOC 2 Common Criteria they most bear on. This is
# a defensible default mapping; refine with your auditor.
_OWASP_TO_SOC2 = {
    "A01:2021": "CC6.1, CC6.3 (Logical access controls)",
    "A02:2021": "CC6.1, CC6.7 (Encryption of data)",
    "A03:2021": "CC6.1, CC7.1 (Input validation / vuln management)",
    "A05:2021": "CC6.1, CC7.1 (Secure configuration)",
    "A06:2021": "CC7.1 (Vulnerable components / patch mgmt)",
    "A07:2021": "CC6.1 (Authentication)",
    "A09:2021": "CC7.2, CC7.3 (Logging & monitoring)",
}

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


class ReportGenerator:
    def render_markdown(
        self,
        engagement_id: str,
        scope_summary: List[str],
        findings: List[Finding],
    ) -> str:
        reportable = [
            f
            for f in findings
            if f.status in (FindingStatus.CONFIRMED, FindingStatus.TRIAGED)
        ]
        reportable.sort(key=lambda f: (f.severity.rank, f.title))

        counts = Counter(f.severity for f in reportable)
        excluded = [f for f in findings if f.status == FindingStatus.FALSE_POSITIVE]
        dupes = [f for f in findings if f.status == FindingStatus.DUPLICATE]

        out: List[str] = []
        out.append(f"# Security Assessment Report — {engagement_id}")
        out.append("")
        out.append(f"_Generated {datetime.now(timezone.utc).isoformat()} UTC by Anvil._")
        out.append("")

        out.append("## Scope")
        out.append("")
        for line in scope_summary:
            out.append(f"- {line}")
        out.append("")

        out.append("## Executive Summary")
        out.append("")
        out.append(
            f"- **{len(reportable)}** findings to report "
            f"({len(excluded)} triaged out as false positives, "
            f"{len(dupes)} merged as duplicates)."
        )
        for sev in _SEVERITY_ORDER:
            if counts.get(sev):
                out.append(f"- {sev.value.title()}: **{counts[sev]}**")
        out.append("")

        out.append("## Findings by Severity")
        out.append("")
        for sev in _SEVERITY_ORDER:
            group = [f for f in reportable if f.severity == sev]
            if not group:
                continue
            out.append(f"### {sev.value.upper()}")
            out.append("")
            for f in group:
                out.extend(self._render_finding(f))
            out.append("")

        out.append(self._compliance_matrix(reportable))
        out.append(self._audit_footer())
        return "\n".join(out)

    def _render_finding(self, f: Finding) -> List[str]:
        lines = [f"#### {f.title}  \n`{f.finding_id}`"]
        lines.append("")
        meta = [
            f"**Severity:** {f.severity.value}",
            f"**Confidence:** {f.confidence.value}",
            f"**Source:** {f.source_tool}" + (f" ({f.rule_id})" if f.rule_id else ""),
        ]
        if f.cwe:
            meta.append(f"**CWE:** {', '.join(f.cwe)}")
        if f.owasp_category:
            meta.append(f"**OWASP:** {f.owasp_category}")
        if f.cvss_score is not None:
            meta.append(f"**CVSS:** {f.cvss_score} `{f.cvss_vector or ''}`")
        lines.append("  \n".join(meta))
        lines.append("")
        lines.append(f"**Location:** `{f.location.as_ref()}`")
        lines.append("")
        if f.description:
            lines.append(f.description.strip())
            lines.append("")
        if f.remediation:
            lines.append(f"**Remediation:** {f.remediation.strip()}")
            lines.append("")
        if f.triage_note:
            lines.append(f"> _Triage: {f.triage_note.strip()}_")
            lines.append("")
        if f.evidence_ref:
            lines.append(f"_Evidence: `{f.evidence_ref}`_")
            lines.append("")
        return lines

    def _compliance_matrix(self, findings: List[Finding]) -> str:
        rows = ["## Compliance Mapping", "", "| OWASP (2021) | SOC 2 Criteria | Findings |", "|---|---|---|"]
        by_owasp: Dict[str, int] = Counter(
            f.owasp_category for f in findings if f.owasp_category
        )
        for owasp, n in sorted(by_owasp.items()):
            key = owasp.split("-")[0].strip() if owasp else ""
            soc2 = _OWASP_TO_SOC2.get(key, "—")
            rows.append(f"| {owasp} | {soc2} | {n} |")
        if not by_owasp:
            rows.append("| _none mapped_ | — | 0 |")
        rows.append("")
        return "\n".join(rows)

    def _audit_footer(self) -> str:
        return (
            "\n---\n\n_All findings trace to raw scanner output in the engagement "
            "evidence store; the run's audit log is hash-chained and verifiable._\n"
        )
