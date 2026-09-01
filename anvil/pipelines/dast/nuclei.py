"""nuclei adapter — the first DAST scanner in the vertical slice.

Runs nuclei in a deliberately non-destructive posture: only `info`/`low`/`medium`
severity templates and the safe tag set (misconfigurations, exposures, TLS,
tech detection). No fuzzing, no exploitation, no intrusive templates. This keeps
the live pipeline safe for compliance scanning of running applications.

Install:  brew install nuclei      (or see https://github.com/projectdiscovery/nuclei)
"""

from __future__ import annotations

import json
import subprocess
from typing import List, Tuple

from anvil.controller.scope_guard import ScopeGuard
from anvil.evidence.store import EvidenceStore
from anvil.pipelines.dast.base import DastAdapter
from anvil.schemas.finding import (
    Confidence,
    Finding,
    Location,
    Pipeline,
    Severity,
)

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}

# Safe posture: exclude anything intrusive. Tune per engagement policy.
_SAFE_TAGS = "misconfig,exposure,tech,ssl,dns,tls"
_EXCLUDE_TAGS = "fuzz,intrusive,dos,brute-force,sqli,rce"


class NucleiAdapter(DastAdapter):
    binary = "nuclei"

    def __init__(self, timeout: int = 1800):
        self.timeout = timeout

    @property
    def name(self) -> str:
        return "nuclei"

    def scan(
        self,
        engagement_id: str,
        target_url: str,
        guard: ScopeGuard,
        evidence: EvidenceStore,
    ) -> Tuple[str, List[Finding]]:
        # Re-validate at request time — this is the guard's whole point.
        guard.check_url(target_url)

        proc = subprocess.run(
            [
                self.binary,
                "-u", target_url,
                "-jsonl",
                "-severity", "info,low,medium",
                "-tags", _SAFE_TAGS,
                "-exclude-tags", _EXCLUDE_TAGS,
                "-no-interactsh",  # no out-of-band callbacks
                "-disable-update-check",
                "-silent",
            ],
            capture_output=True,
            text=True,
            timeout=self.timeout,
        )
        raw = proc.stdout or proc.stderr
        ref = evidence.put(raw, label=f"nuclei_{engagement_id}")

        findings: List[Finding] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            findings.append(self._to_finding(engagement_id, json.loads(line), ref))
        return ref, findings

    def _to_finding(self, engagement_id: str, result: dict, ref: str) -> Finding:
        info = result.get("info", {})
        template_id = result.get("template-id", "unknown")
        matched = result.get("matched-at") or result.get("host", "")

        classification = info.get("classification", {}) or {}
        cwe = classification.get("cwe-id", []) or []
        if isinstance(cwe, str):
            cwe = [cwe]
        cwe = [c.upper() for c in cwe]

        location = Location(url=matched, http_method="GET")

        return Finding(
            finding_id=Finding.make_id(engagement_id, self.name, template_id, matched),
            engagement_id=engagement_id,
            pipeline=Pipeline.DAST,
            source_tool=self.name,
            rule_id=template_id,
            title=info.get("name", template_id),
            description=info.get("description", ""),
            remediation=info.get("remediation", "") or "",
            severity=_SEVERITY_MAP.get(info.get("severity", "info"), Severity.INFO),
            confidence=Confidence.MEDIUM,
            cwe=cwe,
            cvss_score=classification.get("cvss-score"),
            cvss_vector=classification.get("cvss-metrics"),
            location=location,
            evidence_ref=ref,
        )
