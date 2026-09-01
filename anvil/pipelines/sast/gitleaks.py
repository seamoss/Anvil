"""gitleaks adapter — secrets scanning for the SAST pipeline.

Detects hardcoded credentials (API keys, tokens, private keys). Findings map to
CWE-798 (Use of Hard-coded Credentials) / OWASP A07:2021. The secret value
itself is REDACTED from the Finding — only the rule, location, and a masked
fingerprint are surfaced. (The raw gitleaks report, which does contain the
secret, is written to the access-controlled evidence store, not the report.)

Install:  brew install gitleaks    (or see github.com/gitleaks/gitleaks)
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
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


_EXCLUDE_DIRS = [
    "node_modules", "dist", "build", "coverage", "vendor", ".git", ".venv",
    ".next", ".turbo", "out", "__snapshots__", ".claude",
]

# File patterns that generate high-entropy false positives (lock-file integrity
# hashes, test snapshots, minified/bundled output, source maps).
_EXCLUDE_FILE_PATTERNS = [
    r"package-lock\.json$",
    r"yarn\.lock$",
    r"pnpm-lock\.yaml$",
    r"composer\.lock$",
    r"Cargo\.lock$",
    r"poetry\.lock$",
    r".*\.snap$",       # Jest snapshots
    r".*\.min\.js$",    # minified bundles
    r".*\.map$",        # source maps
    r".*\.lock$",
]


def _gitleaks_config() -> str:
    """Keeps gitleaks' default rules but allowlists dependency/build directories
    and high-entropy generated files that otherwise flood --no-git scans."""
    dir_paths = [f"(^|/){re.escape(d)}/" for d in _EXCLUDE_DIRS]
    all_paths = dir_paths + _EXCLUDE_FILE_PATTERNS
    paths = ",\n  ".join(f"'''{p}'''" for p in all_paths)
    return f'title = "anvil-gitleaks"\n[extend]\nuseDefault = true\n[allowlist]\npaths = [\n  {paths}\n]\n'


def _mask(secret: str) -> str:
    if not secret:
        return "[redacted]"
    head = secret[:4]
    return f"{head}…[redacted, {len(secret)} chars]"


class GitleaksAdapter(SastAdapter):
    binary = "gitleaks"

    def __init__(self, timeout: int = 600):
        self.timeout = timeout

    @property
    def name(self) -> str:
        return "gitleaks"

    def scan(
        self, engagement_id: str, repo_path: str, evidence: EvidenceStore
    ) -> Tuple[str, List[Finding]]:
        fd, report_path = tempfile.mkstemp(suffix=".json", prefix="gitleaks_")
        os.close(fd)
        cfd, config_path = tempfile.mkstemp(suffix=".toml", prefix="gitleaks_cfg_")
        with os.fdopen(cfd, "w") as cf:
            cf.write(_gitleaks_config())
        try:
            subprocess.run(
                [
                    self.binary,
                    "detect",
                    "--no-git",  # scan the filesystem, not git history
                    "--source", repo_path,
                    "--config", config_path,  # default rules + dependency-dir allowlist
                    "--report-format", "json",
                    "--report-path", report_path,
                    "--exit-code", "0",  # don't fail the process on findings
                    "--no-banner",
                ],
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            with open(report_path, encoding="utf-8") as fh:
                raw = fh.read() or "[]"
        finally:
            for path in (report_path, config_path):
                try:
                    os.unlink(path)
                except OSError:
                    pass

        ref = evidence.put(raw, label=f"gitleaks_{engagement_id}")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"gitleaks did not return JSON: {exc}") from exc

        return ref, [self._to_finding(engagement_id, item, ref) for item in data]

    def _to_finding(self, engagement_id: str, item: dict, ref: str) -> Finding:
        rule_id = item.get("RuleID", "unknown")
        file_path = item.get("File", "")
        start_line = item.get("StartLine")

        location = Location(
            file_path=file_path,
            start_line=start_line,
            snippet=_mask(item.get("Secret", "")),  # never surface the raw secret
        )
        # Generic/entropy rules are noisier than provider-specific ones.
        confidence = Confidence.MEDIUM if "generic" in rule_id else Confidence.HIGH

        return Finding(
            finding_id=Finding.make_id(engagement_id, self.name, rule_id, location.as_ref()),
            engagement_id=engagement_id,
            pipeline=Pipeline.SAST,
            source_tool=self.name,
            rule_id=rule_id,
            title=f"Hardcoded secret: {item.get('Description', rule_id)}",
            description=(
                f"gitleaks matched rule '{rule_id}' at {location.as_ref()}. "
                "A credential appears to be committed in source. Value redacted."
            ),
            remediation=(
                "Remove the secret from source, rotate it immediately, and load it "
                "from a secret manager or environment variable instead."
            ),
            severity=Severity.HIGH,
            confidence=confidence,
            cwe=["CWE-798"],
            owasp_category="A07:2021-Identification and Authentication Failures",
            location=location,
            evidence_ref=ref,
        )
