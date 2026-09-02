"""SARIF 2.1.0 report renderer.

Emits Static Analysis Results Interchange Format so findings can be ingested by
GitHub code scanning, Azure DevOps, VS Code SARIF viewers, etc. Findings are
grouped into one `run` per source tool, each result carries a `security-severity`
(0-10) so code-scanning UIs rank them, and CWE/OWASP/CVSS ride along as
properties.
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Dict, List

from anvil.schemas.finding import Finding, FindingStatus, Severity

SARIF_VERSION = "2.1.0"
SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# SARIF result levels.
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# Fallback numeric severity (GitHub's security-severity) when no CVSS score.
_SEC_SEVERITY = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 3.0,
    Severity.INFO: 1.0,
}


class SarifReporter:
    def __init__(self, tool_version: str = "0.1.0"):
        self.tool_version = tool_version

    def render(self, engagement_id: str, findings: List[Finding]) -> dict:
        reportable = [
            f
            for f in findings
            if f.status in (FindingStatus.CONFIRMED, FindingStatus.TRIAGED)
        ]
        by_tool: Dict[str, List[Finding]] = defaultdict(list)
        for f in reportable:
            by_tool[f.source_tool].append(f)

        runs = [self._run(engagement_id, tool, fs) for tool, fs in sorted(by_tool.items())]
        return {"version": SARIF_VERSION, "$schema": SCHEMA, "runs": runs}

    def render_json(self, engagement_id: str, findings: List[Finding]) -> str:
        return json.dumps(self.render(engagement_id, findings), indent=2)

    def _run(self, engagement_id: str, tool: str, findings: List[Finding]) -> dict:
        rules: Dict[str, dict] = {}
        results: List[dict] = []
        for f in findings:
            rule_id = f.rule_id or f.finding_id
            if rule_id not in rules:
                rules[rule_id] = self._rule(rule_id, f)
            results.append(self._result(rule_id, f))

        return {
            "tool": {
                "driver": {
                    "name": f"anvil-{tool}",
                    "informationUri": "https://anvil.internal",
                    "version": self.tool_version,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "properties": {"engagementId": engagement_id},
        }

    def _security_severity(self, f: Finding) -> str:
        score = f.cvss_score if f.cvss_score is not None else _SEC_SEVERITY[f.severity]
        return f"{float(score):.1f}"

    def _rule(self, rule_id: str, f: Finding) -> dict:
        tags = list(f.cwe)
        if f.owasp_category:
            tags.append(f.owasp_category)
        tags.append("security")
        return {
            "id": rule_id,
            "name": f.title[:120],
            "shortDescription": {"text": f.title},
            "properties": {
                "tags": tags,
                # GitHub code scanning reads security-severity from the rule.
                "security-severity": self._security_severity(f),
            },
        }

    def _result(self, rule_id: str, f: Finding) -> dict:
        result: dict = {
            "ruleId": rule_id,
            "level": _LEVEL[f.severity],
            "message": {"text": self._message(f)},
            "properties": {
                "anvilFindingId": f.finding_id,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "cwe": f.cwe,
                "owasp": f.owasp_category,
                "cvssScore": f.cvss_score,
                "cvssVector": f.cvss_vector,
                "evidenceRef": f.evidence_ref,
                "sourceTool": f.source_tool,
                "localOnly": f.local_only,
            },
        }
        location = self._location(f)
        if location:
            result["locations"] = [location]
        return result

    @staticmethod
    def _message(f: Finding) -> str:
        parts = [f.description or f.title]
        if f.remediation:
            parts.append(f"Remediation: {f.remediation}")
        return "\n\n".join(parts)

    @staticmethod
    def _location(f: Finding) -> dict:
        uri = f.location.file_path or f.location.url
        if not uri:
            return {}
        physical: dict = {"artifactLocation": {"uri": uri}}
        # SARIF regions must be 1-based; only emit one when we have a real line.
        if f.location.start_line:
            region = {"startLine": f.location.start_line}
            if f.location.end_line:
                region["endLine"] = f.location.end_line
            physical["region"] = region
        return {"physicalLocation": physical}
