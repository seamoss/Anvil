"""Semgrep adapter — the first SAST scanner in the vertical slice.

Runs `semgrep --json` and maps each result into a normalized Finding. Semgrep is
a good first choice: fast, multi-language, ships a large managed ruleset, and
emits structured JSON with rule metadata (severity, CWE, OWASP) we can carry
straight into the compliance mapping.

Install:  pip install semgrep     (or: brew install semgrep)
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
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

# Dependency / build / vendored directories we never want to scan as first-party
# code. Shared conceptually with the other SAST adapters.
_EXCLUDE_DIRS = ["node_modules", "dist", "build", "coverage", "vendor", ".git", ".venv", ".claude"]


class SemgrepAdapter(SastAdapter):
    binary = "semgrep"

    def __init__(self, config: str = "p/default", timeout: int = 900):
        # A named registry ruleset (not `auto`): reproducible/audit-stable and it
        # works with telemetry off — `auto` requires metrics to be ON because it
        # phones home to select rules, which we don't want for a compliance scan.
        # Swap for "p/owasp-top-ten" / "p/security-audit" or a pinned local path
        # per engagement policy.
        self.config = config
        self.timeout = timeout

    @property
    def name(self) -> str:
        return "semgrep"

    def scan(
        self, engagement_id: str, repo_path: str, evidence: EvidenceStore
    ) -> Tuple[str, List[Finding]]:
        excludes = []
        for pattern in _EXCLUDE_DIRS:
            excludes += ["--exclude", pattern]
        proc = subprocess.run(
            [
                self.binary,
                "--json",
                "--config",
                self.config,
                "--metrics",
                "off",
                *excludes,
                repo_path,
            ],
            capture_output=True,
            text=True,
            timeout=self.timeout,
        )
        # Semgrep exits non-zero on findings AND on hard errors; distinguish by
        # whether we got parseable JSON on stdout.
        raw = proc.stdout or proc.stderr
        ref = evidence.put(raw, label=f"semgrep_{engagement_id}")

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"semgrep did not return JSON (exit {proc.returncode}): "
                f"{proc.stderr[:500]}"
            ) from exc

        findings: List[Finding] = []
        for result in data.get("results", []):
            findings.append(self._to_finding(engagement_id, result, ref))
        return ref, findings

    def _to_finding(self, engagement_id: str, result: dict, ref: str) -> Finding:
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        rule_id = result.get("check_id", "unknown")

        location = Location(
            file_path=result.get("path"),
            start_line=result.get("start", {}).get("line"),
            end_line=result.get("end", {}).get("line"),
            snippet=(extra.get("lines") or "").strip() or None,
        )

        cwe = metadata.get("cwe", [])
        if isinstance(cwe, str):
            cwe = [cwe]
        # Semgrep CWEs look like "CWE-89: SQL Injection" — keep just the id.
        cwe = [c.split(":")[0].strip() for c in cwe]

        owasp = metadata.get("owasp")
        if isinstance(owasp, list):
            owasp = owasp[0] if owasp else None

        return Finding(
            finding_id=Finding.make_id(
                engagement_id, self.name, rule_id, location.as_ref()
            ),
            engagement_id=engagement_id,
            pipeline=Pipeline.SAST,
            source_tool=self.name,
            rule_id=rule_id,
            title=metadata.get("shortDescription") or rule_id.split(".")[-1],
            description=extra.get("message", ""),
            remediation=metadata.get("fix") or extra.get("fix", "") or "",
            severity=_SEVERITY_MAP.get(extra.get("severity", "INFO"), Severity.LOW),
            confidence=Confidence.MEDIUM,
            cwe=cwe,
            owasp_category=owasp,
            location=location,
            evidence_ref=ref,
        )
