"""CodeQL adapter — deep semantic static analysis for the SAST pipeline.

Drives the CodeQL CLI: build a database for the repo's dominant language, run the
standard security query pack, and parse the resulting SARIF into normalized
Findings. CodeQL's SARIF carries CWE tags and a numeric `security-severity`,
both of which we map through.

Interpreted languages (Python, JavaScript/TypeScript, Ruby, Go) need no build
command. Compiled languages (Java, C#, C/C++) require a build and may fail
without one — the engagement records that and moves on.

Install:  brew install codeql   (or download from github.com/github/codeql-cli-binaries)
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from anvil.evidence.store import EvidenceStore
from anvil.pipelines.sast.base import SastAdapter
from anvil.schemas.finding import (
    Confidence,
    Finding,
    Location,
    Pipeline,
    Severity,
)

_EXCLUDE_DIRS = ["node_modules", "dist", "build", "coverage", "vendor", ".venv", ".claude"]

_EXT_LANG = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".ts": "javascript", ".tsx": "javascript",
    ".rb": "ruby",
    ".go": "go",
    ".java": "java",
    ".cs": "csharp",
    ".c": "cpp", ".cc": "cpp", ".cpp": "cpp", ".h": "cpp",
}


def _severity_from_score(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


_LEVEL_SEVERITY = {"error": Severity.HIGH, "warning": Severity.MEDIUM, "note": Severity.LOW}


class CodeqlAdapter(SastAdapter):
    binary = "codeql"

    def __init__(self, timeout: int = 3600):
        self.timeout = timeout

    @property
    def name(self) -> str:
        return "codeql"

    @staticmethod
    def detect_language(repo_path: str) -> Optional[str]:
        counts: Counter = Counter()
        for p in Path(repo_path).rglob("*"):
            if p.is_file() and "node_modules" not in p.parts and ".git" not in p.parts:
                lang = _EXT_LANG.get(p.suffix.lower())
                if lang:
                    counts[lang] += 1
        return counts.most_common(1)[0][0] if counts else None

    def scan(
        self, engagement_id: str, repo_path: str, evidence: EvidenceStore
    ) -> Tuple[str, List[Finding]]:
        language = self.detect_language(repo_path)
        if not language:
            ref = evidence.put('{"note": "no CodeQL-supported language detected"}', label=f"codeql_{engagement_id}")
            return ref, []

        with tempfile.TemporaryDirectory(prefix="codeql_") as tmp:
            db = str(Path(tmp) / "db")
            sarif = str(Path(tmp) / "out.sarif")
            # Keep dependency/build dirs out of extraction (huge and slow otherwise).
            config = Path(tmp) / "codeql-config.yml"
            config.write_text(
                "paths-ignore:\n" + "".join(f"  - {d}\n" for d in _EXCLUDE_DIRS),
                encoding="utf-8",
            )
            subprocess.run(
                [self.binary, "database", "create", db,
                 f"--language={language}", f"--source-root={repo_path}",
                 f"--codescanning-config={config}", "--overwrite", "-q"],
                capture_output=True, text=True, timeout=self.timeout, check=True,
            )
            subprocess.run(
                [self.binary, "database", "analyze", db, f"codeql/{language}-queries",
                 "--format=sarif-latest", f"--output={sarif}", "--sarif-add-snippets",
                 "--download", "-q", "--threads=0"],
                capture_output=True, text=True, timeout=self.timeout, check=True,
            )
            raw = Path(sarif).read_text(encoding="utf-8")

        ref = evidence.put(raw, label=f"codeql_{engagement_id}")
        return ref, self.parse_sarif(engagement_id, json.loads(raw), ref)

    # --- pure SARIF parser (unit-tested without the CLI) --------------------
    def parse_sarif(self, engagement_id: str, sarif: dict, ref: str) -> List[Finding]:
        findings: List[Finding] = []
        for run in sarif.get("runs", []):
            driver = run.get("tool", {}).get("driver", {})
            rules: Dict[str, dict] = {r["id"]: r for r in driver.get("rules", []) if "id" in r}
            for result in run.get("results", []):
                findings.append(self._to_finding(engagement_id, result, rules, ref))
        return findings

    def _to_finding(self, engagement_id: str, result: dict, rules: Dict[str, dict], ref: str) -> Finding:
        rule_id = result.get("ruleId", "unknown")
        rule = rules.get(rule_id, {})
        props = rule.get("properties", {}) or {}

        # Severity: prefer the numeric security-severity, else the SARIF level.
        sev: Optional[Severity] = None
        if props.get("security-severity") is not None:
            try:
                sev = _severity_from_score(float(props["security-severity"]))
            except (TypeError, ValueError):
                sev = None
        if sev is None:
            level = result.get("level") or rule.get("defaultConfiguration", {}).get("level", "warning")
            sev = _LEVEL_SEVERITY.get(level, Severity.MEDIUM)

        cwe = self._cwes(props.get("tags", []))
        location = self._location(result)

        title = (rule.get("shortDescription", {}) or {}).get("text") or props.get("name") or rule_id
        message = (result.get("message", {}) or {}).get("text", "")

        return Finding(
            finding_id=Finding.make_id(engagement_id, self.name, rule_id, location.as_ref()),
            engagement_id=engagement_id,
            pipeline=Pipeline.SAST,
            source_tool=self.name,
            rule_id=rule_id,
            title=title[:120],
            description=message,
            remediation=(rule.get("help", {}) or {}).get("text", "")[:300],
            severity=sev,
            confidence=Confidence.HIGH,  # CodeQL is dataflow-based — high signal
            cwe=cwe,
            location=location,
            evidence_ref=ref,
        )

    @staticmethod
    def _cwes(tags: List[str]) -> List[str]:
        out = []
        for tag in tags:
            # e.g. "external/cwe/cwe-079" -> "CWE-79"
            if "cwe/cwe-" in tag:
                num = tag.rsplit("cwe-", 1)[-1].lstrip("0") or "0"
                out.append(f"CWE-{num}")
        return out

    @staticmethod
    def _location(result: dict) -> Location:
        locs = result.get("locations", [])
        if not locs:
            return Location()
        phys = locs[0].get("physicalLocation", {})
        region = phys.get("region", {}) or {}
        return Location(
            file_path=phys.get("artifactLocation", {}).get("uri"),
            start_line=region.get("startLine"),
            end_line=region.get("endLine"),
            snippet=(region.get("snippet", {}) or {}).get("text"),
        )
