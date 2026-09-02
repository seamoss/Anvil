"""HTML report renderer (+ optional PDF).

Produces a self-contained, print-optimized HTML report — no external assets, so
it renders identically offline and "Save as PDF" from any browser yields a clean
deliverable. `to_pdf()` renders straight to PDF when WeasyPrint is installed,
otherwise it raises with guidance (the HTML print path always works).
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import List

from anvil import __version__
from anvil.reporting.report import _OWASP_TO_SOC2
from anvil.schemas.finding import Finding, FindingStatus, Severity

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

_SEV_COLOR = {
    Severity.CRITICAL: "#b3123b",
    Severity.HIGH: "#d1442f",
    Severity.MEDIUM: "#c07a00",
    Severity.LOW: "#2f7d3a",
    Severity.INFO: "#5a6472",
}

_CSS = """
:root { --fg:#1a1d21; --muted:#5a6472; --line:#e3e6ea; --bg:#ffffff; --card:#f7f8fa; }
* { box-sizing: border-box; }
body { font: 14px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
       color: var(--fg); background: var(--bg); margin: 0; padding: 2.5rem; max-width: 60rem; }
h1 { font-size: 1.6rem; margin: 0 0 .25rem; }
h2 { font-size: 1.15rem; margin: 2rem 0 .75rem; border-bottom: 2px solid var(--line); padding-bottom: .3rem; }
.sub { color: var(--muted); margin: 0 0 1.5rem; }
.chips { display: flex; flex-wrap: wrap; gap: .5rem; margin: 1rem 0; }
.chip { border-radius: 999px; padding: .2rem .7rem; color: #fff; font-weight: 600; font-size: .8rem; }
.card { background: var(--card); border: 1px solid var(--line); border-left-width: 4px;
        border-radius: 8px; padding: 1rem 1.15rem; margin: .8rem 0; }
.card h3 { margin: 0 0 .5rem; font-size: 1.02rem; }
.badges { display: flex; flex-wrap: wrap; gap: .4rem; margin: .4rem 0 .7rem; }
.badge { font-size: .72rem; background: #eceef1; color: #333; border-radius: 5px; padding: .12rem .5rem; }
.badge.sev { color: #fff; }
.badge.local { background: #ede7ff; color: #5b3fa8; font-weight: 600; }
.loc { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .82rem;
       background: #eceef1; padding: .12rem .4rem; border-radius: 4px; }
.fid { color: var(--muted); font-family: ui-monospace, monospace; font-size: .75rem; }
.rem { margin-top: .5rem; }
.note { color: var(--muted); font-style: italic; font-size: .85rem; margin-top: .5rem; }
.ev { color: var(--muted); font-family: ui-monospace, monospace; font-size: .7rem; margin-top: .4rem; }
table { border-collapse: collapse; width: 100%; font-size: .88rem; }
th, td { text-align: left; border: 1px solid var(--line); padding: .45rem .6rem; }
th { background: var(--card); }
footer { color: var(--muted); font-size: .8rem; margin-top: 2.5rem; border-top: 1px solid var(--line); padding-top: .8rem; }
@media print {
  body { padding: 0; max-width: none; font-size: 11pt; }
  .card { break-inside: avoid; }
  h2 { break-after: avoid; }
}
"""


class HtmlReporter:
    def render(self, engagement_id: str, scope_summary: List[str], findings: List[Finding]) -> str:
        reportable = [
            f for f in findings
            if f.status in (FindingStatus.CONFIRMED, FindingStatus.TRIAGED)
        ]
        reportable.sort(key=lambda f: (f.severity.rank, f.title))
        counts = Counter(f.severity for f in reportable)
        excluded = sum(1 for f in findings if f.status == FindingStatus.FALSE_POSITIVE)
        dupes = sum(1 for f in findings if f.status == FindingStatus.DUPLICATE)

        p: List[str] = []
        p.append(f"<h1>Security Assessment — {escape(engagement_id)}</h1>")
        p.append(
            f'<p class="sub">Generated {datetime.now(timezone.utc).isoformat()} UTC by Anvil · '
            f"{len(reportable)} findings ({excluded} false positives, {dupes} duplicates removed)</p>"
        )

        # severity chips
        p.append('<div class="chips">')
        for sev in _SEVERITY_ORDER:
            if counts.get(sev):
                p.append(
                    f'<span class="chip" style="background:{_SEV_COLOR[sev]}">'
                    f"{counts[sev]} {escape(sev.value.title())}</span>"
                )
        p.append("</div>")

        local_count = sum(1 for f in reportable if f.local_only)
        if local_count:
            p.append(
                f'<p class="sub">🔒 {local_count} local-only finding(s) — reported here, '
                "excluded from workflow integrations.</p>"
            )

        # scope
        p.append("<h2>Scope</h2><ul>")
        for line in scope_summary:
            p.append(f"<li>{escape(line)}</li>")
        p.append("</ul>")

        # findings
        p.append("<h2>Findings</h2>")
        for sev in _SEVERITY_ORDER:
            group = [f for f in reportable if f.severity == sev]
            for f in group:
                p.append(self._card(f))

        p.append(self._matrix(reportable))
        p.append(
            "<footer>All findings trace to raw scanner output in the engagement "
            "evidence store; the run's audit log is hash-chained and verifiable."
            f"<br><br>Generated by <strong>Anvil</strong> v{__version__} — "
            "authorization-gated SAST/DAST scanning with hybrid LLM triage (Claude)."
            "</footer>"
        )
        body = "\n".join(p)
        return f"<!doctype html><html><head><meta charset='utf-8'>" \
               f"<title>Anvil — {escape(engagement_id)}</title><style>{_CSS}</style></head>" \
               f"<body>{body}</body></html>"

    def _card(self, f: Finding) -> str:
        color = _SEV_COLOR[f.severity]
        badges = [f'<span class="badge sev" style="background:{color}">{escape(f.severity.value)}</span>']
        if f.local_only:
            badges.append('<span class="badge local">🔒 local-only</span>')
        badges.append(f'<span class="badge">confidence: {escape(f.confidence.value)}</span>')
        src = f.source_tool + (f" · {f.rule_id}" if f.rule_id else "")
        badges.append(f'<span class="badge">{escape(src)}</span>')
        if f.cwe:
            badges.append(f'<span class="badge">{escape(", ".join(f.cwe))}</span>')
        if f.owasp_category:
            badges.append(f'<span class="badge">{escape(f.owasp_category)}</span>')
        if f.cvss_score is not None:
            badges.append(f'<span class="badge">CVSS {f.cvss_score}</span>')

        parts = [f'<div class="card" style="border-left-color:{color}">']
        parts.append(f"<h3>{escape(f.title)}</h3>")
        parts.append(f'<div class="fid">{escape(f.finding_id)}</div>')
        parts.append('<div class="badges">' + "".join(badges) + "</div>")
        parts.append(f'<div>Location: <span class="loc">{escape(f.location.as_ref())}</span></div>')
        if f.description:
            parts.append(f"<p>{escape(f.description)}</p>")
        if f.remediation:
            parts.append(f'<div class="rem"><strong>Remediation:</strong> {escape(f.remediation)}</div>')
        if f.triage_note:
            parts.append(f'<div class="note">Triage: {escape(f.triage_note)}</div>')
        if f.evidence_ref:
            parts.append(f'<div class="ev">Evidence: {escape(f.evidence_ref)}</div>')
        parts.append("</div>")
        return "".join(parts)

    def _matrix(self, findings: List[Finding]) -> str:
        by_owasp = Counter(f.owasp_category for f in findings if f.owasp_category)
        rows = ["<h2>Compliance Mapping</h2>",
                "<table><tr><th>OWASP (2021)</th><th>SOC 2 Criteria</th><th>Findings</th></tr>"]
        for owasp, n in sorted(by_owasp.items()):
            key = owasp.split("-")[0].strip()
            soc2 = _OWASP_TO_SOC2.get(key, "—")
            rows.append(f"<tr><td>{escape(owasp)}</td><td>{escape(soc2)}</td><td>{n}</td></tr>")
        if not by_owasp:
            rows.append("<tr><td>none mapped</td><td>—</td><td>0</td></tr>")
        rows.append("</table>")
        return "".join(rows)


def to_pdf(html: str, path: Path) -> Path:
    """Render HTML to PDF via WeasyPrint if available, else raise with guidance."""
    try:
        from weasyprint import HTML  # optional dependency
    except ImportError as exc:
        raise RuntimeError(
            "PDF output needs WeasyPrint (`uv pip install weasyprint`, plus its "
            "system libs). Alternatively open the .html report and 'Save as PDF' — "
            "it is print-optimized."
        ) from exc
    HTML(string=html).write_pdf(str(path))
    return path
