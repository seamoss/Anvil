"""Dependency lane — SCA findings rendered separately from first-party code.

Dependency CVEs and license concerns are a different remediation workstream
(lockfile bump / policy review) than code findings (code review), and there are
often hundreds of them — so they get their own section, deduplicated across
sources (Trivy + OSV), instead of flooding the risk-ranked findings.
"""

from __future__ import annotations

import re
from html import escape
from typing import List, Tuple

from anvil.schemas.finding import Finding


def _fixed_version(remediation: str) -> str:
    m = re.search(r" to (\S+?)(?: or later)?\.?$", remediation or "")
    return m.group(1) if m else "—"


def aggregate(dep_findings: List[Finding]) -> Tuple[list, list]:
    """Return (vulns, licenses). Vulns are deduped across sources by
    (component, advisory id), merging which scanners flagged each."""
    vuln_map = {}
    licenses = []
    for f in dep_findings:
        if f.is_license:
            licenses.append(f)
            continue
        key = (f.component or f.title, f.rule_id)
        rec = vuln_map.get(key)
        if rec is None:
            rec = {
                "component": f.component or "—",
                "id": f.rule_id or "—",
                "severity": f.severity,
                "cvss": f.cvss_score,
                "fix": _fixed_version(f.remediation),
                "sources": set(),
            }
            vuln_map[key] = rec
        rec["sources"].add(f.source_tool)
        if f.cvss_score is not None and (rec["cvss"] is None or f.cvss_score > rec["cvss"]):
            rec["cvss"] = f.cvss_score
        if f.severity.rank < rec["severity"].rank:
            rec["severity"] = f.severity
    vulns = sorted(vuln_map.values(), key=lambda r: (r["severity"].rank, -(r["cvss"] or 0)))
    licenses.sort(key=lambda f: f.severity.rank)
    return vulns, licenses


def _summary_line(vulns, licenses) -> str:
    srcs = sorted({s for v in vulns for s in v["sources"]})
    parts = [f"**{len(vulns)}** vulnerable dependency finding(s)"]
    if licenses:
        parts.append(f"**{len(licenses)}** license concern(s)")
    src = f" (deduplicated across {', '.join(srcs)})" if srcs else ""
    return ", ".join(parts) + src + "."


def markdown_section(dep_findings: List[Finding]) -> str:
    if not dep_findings:
        return ""
    vulns, licenses = aggregate(dep_findings)
    out = ["## Dependencies", "", _summary_line(vulns, licenses), ""]
    if vulns:
        out.append("| Severity | Package | Advisory | CVSS | Sources | Fix |")
        out.append("|---|---|---|---|---|---|")
        for v in vulns:
            out.append(
                f"| {v['severity'].value} | `{v['component']}` | {v['id']} | "
                f"{v['cvss'] if v['cvss'] is not None else '—'} | "
                f"{', '.join(sorted(v['sources']))} | {v['fix']} |"
            )
        out.append("")
    if licenses:
        out.append("### License concerns")
        out.append("")
        out.append("| Severity | Package | License |")
        out.append("|---|---|---|")
        for f in licenses:
            out.append(f"| {f.severity.value} | `{f.component or '—'}` | {f.rule_id} |")
        out.append("")
    return "\n".join(out)


def html_section(dep_findings: List[Finding]) -> str:
    if not dep_findings:
        return ""
    vulns, licenses = aggregate(dep_findings)
    p = ["<h2>Dependencies</h2>", f"<p class='sub'>{_summary_line(vulns, licenses)}</p>"]
    if vulns:
        p.append("<table><tr><th>Severity</th><th>Package</th><th>Advisory</th>"
                 "<th>CVSS</th><th>Sources</th><th>Fix</th></tr>")
        for v in vulns:
            p.append(
                f"<tr><td>{escape(v['severity'].value)}</td>"
                f"<td><span class='loc'>{escape(v['component'])}</span></td>"
                f"<td>{escape(v['id'])}</td>"
                f"<td>{v['cvss'] if v['cvss'] is not None else '—'}</td>"
                f"<td>{escape(', '.join(sorted(v['sources'])))}</td>"
                f"<td>{escape(v['fix'])}</td></tr>"
            )
        p.append("</table>")
    if licenses:
        p.append("<h3>License concerns</h3>")
        p.append("<table><tr><th>Severity</th><th>Package</th><th>License</th></tr>")
        for f in licenses:
            p.append(f"<tr><td>{escape(f.severity.value)}</td>"
                     f"<td><span class='loc'>{escape(f.component or '—')}</span></td>"
                     f"<td>{escape(f.rule_id or '—')}</td></tr>")
        p.append("</table>")
    return "".join(p)
