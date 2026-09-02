"""OSV-Scanner adapter — a second, independent SCA source.

Google's OSV-Scanner queries the open OSV.dev database (no account, no paid
tier, no LLM). Running it alongside Trivy gives dual-source dependency-CVE
coverage: what one advisory DB misses, the other often catches, and agreement
between them raises confidence. Findings are SCA (fast-pathed, dependency lane).

Install:  brew install osv-scanner   (or github.com/google/osv-scanner)
"""

from __future__ import annotations

import json
import subprocess
from typing import List, Optional, Tuple

from anvil.evidence.store import EvidenceStore
from anvil.pipelines.sast.base import SastAdapter
from anvil.schemas.finding import (
    Confidence,
    Finding,
    Location,
    Pipeline,
    Severity,
)

# Duplicate/vendored lockfiles (a .claude/worktrees copy, installed deps) would
# multiply the same CVEs — filter results from these paths.
_EXCLUDE = ("node_modules", ".claude", "/dist/", "/build/", "/vendor/")


def _severity(score: Optional[str]) -> Severity:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return Severity.INFO
    if s >= 9.0:
        return Severity.CRITICAL
    if s >= 7.0:
        return Severity.HIGH
    if s >= 4.0:
        return Severity.MEDIUM
    if s > 0:
        return Severity.LOW
    return Severity.INFO


class OsvScannerAdapter(SastAdapter):
    binary = "osv-scanner"

    def __init__(self, timeout: int = 600):
        self.timeout = timeout

    @property
    def name(self) -> str:
        return "osv"

    def scan(
        self, engagement_id: str, repo_path: str, evidence: EvidenceStore
    ) -> Tuple[str, List[Finding]]:
        proc = subprocess.run(
            [self.binary, "--format", "json", "--recursive", repo_path],
            capture_output=True,
            text=True,
            timeout=self.timeout,
        )
        raw = proc.stdout or proc.stderr
        ref = evidence.put(raw, label=f"osv_{engagement_id}")
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"osv-scanner did not return JSON: {exc}") from exc

        return ref, self.parse(engagement_id, data, ref)

    def parse(self, engagement_id: str, data: dict, ref: str) -> List[Finding]:
        findings: List[Finding] = []
        for result in data.get("results", []):
            source = (result.get("source", {}) or {}).get("path", "")
            if any(x in source for x in _EXCLUDE):
                continue
            for pkg in result.get("packages", []):
                info = pkg.get("package", {})
                vulns_by_id = {v.get("id"): v for v in pkg.get("vulnerabilities", [])}
                # One finding per group (a group merges a vuln's aliases).
                for group in pkg.get("groups", []):
                    findings.append(
                        self._to_finding(engagement_id, source, info, group, vulns_by_id, ref)
                    )
        return findings

    def _to_finding(self, engagement_id, source, info, group, vulns_by_id, ref) -> Finding:
        aliases = group.get("aliases", []) or group.get("ids", [])
        canonical = next((a for a in aliases if a.startswith("CVE-")), None) or \
            (group.get("ids") or ["unknown"])[0]
        pkg = info.get("name", "")
        version = info.get("version", "")

        vuln = next((vulns_by_id[i] for i in group.get("ids", []) if i in vulns_by_id), {})
        summary = (vuln.get("summary") or vuln.get("details") or "")[:400]

        return Finding(
            finding_id=Finding.make_id(engagement_id, self.name, canonical, f"{pkg}@{version}"),
            engagement_id=engagement_id,
            pipeline=Pipeline.SAST,
            source_tool=self.name,
            rule_id=canonical,
            title=f"{pkg} {version}: {canonical}",
            description=summary,
            remediation=self._remediation(pkg, vuln),
            severity=_severity(group.get("max_severity")),
            confidence=Confidence.HIGH,
            cwe=[],
            owasp_category="A06:2021-Vulnerable and Outdated Components",
            location=Location(file_path=source),
            evidence_ref=ref,
            component=f"{pkg}@{version}",
        )

    @staticmethod
    def _remediation(pkg: str, vuln: dict) -> str:
        for affected in vuln.get("affected", []) or []:
            for rng in affected.get("ranges", []) or []:
                for event in rng.get("events", []) or []:
                    if event.get("fixed"):
                        return f"Upgrade {pkg} to {event['fixed']} or later."
        return f"Upgrade {pkg} to a non-vulnerable version."
