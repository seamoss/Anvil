"""Trivy adapter — software composition analysis (SCA) for the SAST pipeline.

Scans dependency manifests/lockfiles for known-vulnerable packages (CVEs).
Findings map to OWASP A06:2021 (Vulnerable and Outdated Components), carry the
CVE as the rule id, and reuse Trivy's own CVSS v3 score/vector and CWE list.

Install:  brew install trivy    (or see github.com/aquasecurity/trivy)
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

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}

# Directories to skip — duplicate/vendored lockfiles (e.g. a .claude/worktrees
# copy of the repo) otherwise multiply the same CVEs across the tree.
_EXCLUDE_DIRS = ["node_modules", ".claude", "dist", "build", "vendor", ".venv"]


class TrivyAdapter(SastAdapter):
    binary = "trivy"

    def __init__(self, timeout: int = 900):
        self.timeout = timeout

    @property
    def name(self) -> str:
        return "trivy"

    def scan(
        self, engagement_id: str, repo_path: str, evidence: EvidenceStore
    ) -> Tuple[str, List[Finding]]:
        skips = []
        for pattern in _EXCLUDE_DIRS:
            skips += ["--skip-dirs", f"**/{pattern}"]
        proc = subprocess.run(
            [
                self.binary,
                "fs",
                "--quiet",
                "--format", "json",
                "--scanners", "vuln",
                *skips,
                repo_path,
            ],
            capture_output=True,
            text=True,
            timeout=self.timeout,
        )
        raw = proc.stdout or proc.stderr
        ref = evidence.put(raw, label=f"trivy_{engagement_id}")

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"trivy did not return JSON (exit {proc.returncode}): {proc.stderr[:500]}"
            ) from exc

        findings: List[Finding] = []
        for result in data.get("Results") or []:
            target = result.get("Target", "")
            for vuln in result.get("Vulnerabilities") or []:
                findings.append(self._to_finding(engagement_id, target, vuln, ref))
        return ref, findings

    @staticmethod
    def _cvss(vuln: dict) -> Tuple[Optional[float], Optional[str]]:
        cvss = vuln.get("CVSS") or {}
        # Prefer NVD, then Red Hat, then GHSA, then whatever's present.
        for source in ("nvd", "redhat", "ghsa", *cvss.keys()):
            entry = cvss.get(source)
            if entry and entry.get("V3Score") is not None:
                return entry.get("V3Score"), entry.get("V3Vector")
        return None, None

    def _to_finding(self, engagement_id: str, target: str, vuln: dict, ref: str) -> Finding:
        cve = vuln.get("VulnerabilityID", "unknown")
        pkg = vuln.get("PkgName", "")
        installed = vuln.get("InstalledVersion", "")
        fixed = vuln.get("FixedVersion")
        score, vector = self._cvss(vuln)

        location = Location(file_path=target)
        remediation = (
            f"Upgrade {pkg} from {installed} to {fixed} or later."
            if fixed
            else f"No fixed version published for {pkg} {installed}; evaluate mitigations or replace the dependency."
        )

        return Finding(
            finding_id=Finding.make_id(
                engagement_id, self.name, cve, f"{pkg}@{installed}"
            ),
            engagement_id=engagement_id,
            pipeline=Pipeline.SAST,
            source_tool=self.name,
            rule_id=cve,
            title=f"{pkg} {installed}: {cve}",
            description=(vuln.get("Title") or vuln.get("Description") or "")[:500],
            remediation=remediation,
            severity=_SEVERITY_MAP.get(vuln.get("Severity", "UNKNOWN"), Severity.INFO),
            confidence=Confidence.HIGH,  # SCA is exact version matching — high signal
            cwe=vuln.get("CweIDs", []) or [],
            owasp_category="A06:2021-Vulnerable and Outdated Components",
            cvss_score=score,
            cvss_vector=vector,
            location=location,
            evidence_ref=ref,
        )
