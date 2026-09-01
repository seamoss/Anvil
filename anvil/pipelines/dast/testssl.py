"""testssl.sh adapter — TLS/SSL configuration analysis for the DAST pipeline.

Wraps testssl.sh (a read-only TLS prober) to assess protocol versions, cipher
strength, and certificate health. All findings map to OWASP A02:2021
(Cryptographic Failures). testssl connects only to the single host:port derived
from the authorized target — no redirects, no payloads.

Install:  brew install testssl    (or see github.com/drwetter/testssl.sh)
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from typing import List, Tuple
from urllib.parse import urlparse

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

# testssl severity strings → our severity. OK/INFO/DEBUG are dropped as noise.
_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "WARN": Severity.INFO,
}
_SKIP = {"OK", "INFO", "DEBUG", ""}


class TestSslAdapter(DastAdapter):
    __test__ = False  # not a pytest test class despite the 'Test' prefix
    binary = "testssl.sh"

    def __init__(self, timeout: int = 600, flags: Tuple[str, ...] = ("-p", "-S", "-s")):
        # Default flags: protocols (-p), server defaults / certificate (-S),
        # standard cipher categories (-s). Bounded for scan time; extend per
        # engagement policy (e.g. add -U for the full vulnerability suite).
        self.timeout = timeout
        self.flags = flags

    @property
    def name(self) -> str:
        return "testssl"

    def scan(
        self,
        engagement_id: str,
        target_url: str,
        guard: ScopeGuard,
        evidence: EvidenceStore,
    ) -> Tuple[str, List[Finding]]:
        guard.check_url(target_url)  # re-validate; testssl won't follow redirects
        p = urlparse(target_url)
        host = p.hostname or target_url
        port = p.port or 443  # TLS lives on 443 by default even for an http URL
        hostport = f"{host}:{port}"

        fd, out_path = tempfile.mkstemp(suffix=".json", prefix="testssl_")
        os.close(fd)
        try:
            subprocess.run(
                [self.binary, "--jsonfile", out_path, "--quiet", "--color", "0",
                 "--severity", "LOW", *self.flags, hostport],
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            with open(out_path, encoding="utf-8") as fh:
                raw = fh.read() or "[]"
        finally:
            try:
                os.unlink(out_path)
            except OSError:
                pass

        ref = evidence.put(raw, label=f"testssl_{engagement_id}")
        try:
            records = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"testssl did not return JSON: {exc}") from exc

        return ref, self.parse(engagement_id, hostport, records, ref)

    def parse(self, engagement_id: str, hostport: str, records: list, ref: str) -> List[Finding]:
        """Map testssl JSON records → Findings, dropping OK/INFO/DEBUG noise."""
        findings: List[Finding] = []
        for rec in records:
            sev_str = rec.get("severity", "").upper()
            severity = _SEVERITY_MAP.get(sev_str)
            if severity is None or sev_str in _SKIP:
                continue
            findings.append(self._to_finding(engagement_id, hostport, rec, severity, ref))
        return findings

    def _to_finding(self, engagement_id, hostport, rec, severity, ref) -> Finding:
        rule_id = rec.get("id", "unknown")
        finding_text = rec.get("finding", "")
        cwe = rec.get("cwe", "")
        cwe_list = [cwe] if cwe else []

        return Finding(
            finding_id=Finding.make_id(engagement_id, self.name, rule_id, hostport),
            engagement_id=engagement_id,
            pipeline=Pipeline.DAST,
            source_tool=self.name,
            rule_id=rule_id,
            title=f"TLS: {rule_id}",
            description=f"{rule_id}: {finding_text}",
            remediation=self._remediation(rule_id),
            severity=severity,
            confidence=Confidence.HIGH,
            cwe=cwe_list,
            owasp_category="A02:2021-Cryptographic Failures",
            location=Location(url=hostport),
            evidence_ref=ref,
        )

    @staticmethod
    def _remediation(rule_id: str) -> str:
        rid = rule_id.lower()
        if rid.startswith("cert"):
            return "Fix the certificate issue (valid chain, matching hostname/SAN, and adequate validity/revocation)."
        if rid.startswith(("tls1", "ssl", "sslv")):
            return "Disable deprecated SSL/TLS protocol versions; require TLS 1.2+."
        return "Harden the TLS configuration (strong protocols and ciphers, valid certificate)."
