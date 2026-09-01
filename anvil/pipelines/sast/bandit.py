"""Bandit adapter — Python-focused static analysis for the SAST pipeline.

Bandit finds common Python security issues (subprocess/shell, weak crypto,
insecure deserialization, hardcoded passwords, etc.). It's Python-only, so on a
repo with no Python it simply returns no findings. CWE comes straight from
Bandit's per-test metadata; OWASP is left for the triage layer to assign.

Install:  uv pip install bandit
"""

from __future__ import annotations

import json
import subprocess
from typing import List, Tuple

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
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNDEFINED": Severity.INFO,
}
_CONFIDENCE_MAP = {
    "HIGH": Confidence.HIGH,
    "MEDIUM": Confidence.MEDIUM,
    "LOW": Confidence.LOW,
    "UNDEFINED": Confidence.LOW,
}


class BanditAdapter(SastAdapter):
    binary = "bandit"

    def __init__(self, timeout: int = 600):
        self.timeout = timeout

    @property
    def name(self) -> str:
        return "bandit"

    def scan(
        self, engagement_id: str, repo_path: str, evidence: EvidenceStore
    ) -> Tuple[str, List[Finding]]:
        proc = subprocess.run(
            [self.binary, "-r", repo_path, "-f", "json", "-q"],
            capture_output=True,
            text=True,
            timeout=self.timeout,
        )
        # Bandit exits 1 when it finds issues; JSON is still on stdout.
        raw = proc.stdout or proc.stderr
        ref = evidence.put(raw, label=f"bandit_{engagement_id}")

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"bandit did not return JSON (exit {proc.returncode}): {proc.stderr[:500]}"
            ) from exc

        return ref, [self._to_finding(engagement_id, r, ref) for r in data.get("results", [])]

    def _to_finding(self, engagement_id: str, r: dict, ref: str) -> Finding:
        test_id = r.get("test_id", "unknown")
        line_range = r.get("line_range") or [r.get("line_number")]

        location = Location(
            file_path=r.get("filename"),
            start_line=r.get("line_number"),
            end_line=line_range[-1] if line_range else None,
            snippet=(r.get("code") or "").strip() or None,
        )

        cwe_meta = r.get("issue_cwe") or {}
        cwe = [f"CWE-{cwe_meta['id']}"] if cwe_meta.get("id") else []

        return Finding(
            finding_id=Finding.make_id(engagement_id, self.name, test_id, location.as_ref()),
            engagement_id=engagement_id,
            pipeline=Pipeline.SAST,
            source_tool=self.name,
            rule_id=test_id,
            title=r.get("test_name", test_id),
            description=r.get("issue_text", ""),
            remediation=f"Review per Bandit guidance: {r.get('more_info', '')}".strip(),
            severity=_SEVERITY_MAP.get(r.get("issue_severity", "UNDEFINED"), Severity.INFO),
            confidence=_CONFIDENCE_MAP.get(r.get("issue_confidence", "UNDEFINED"), Confidence.LOW),
            cwe=cwe,
            location=location,
            evidence_ref=ref,
        )
