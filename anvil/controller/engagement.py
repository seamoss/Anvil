"""Engagement orchestrator — ties the whole flow together.

    load & verify authorization
      → build scope guard (hard gate)
        → run pipeline (SAST or DAST), storing raw output as evidence
          → triage (LLM or offline heuristic)
            → render compliance report
  ...with every step recorded to the hash-chained audit log.

Each engagement writes to  runs/<engagement_id>/  :
    audit.jsonl      the hash-chained event log
    evidence/        content-addressed raw scanner output
    findings.json    normalized findings (post-triage)
    report.md        the compliance report
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from anvil.controller.audit import AuditLog
from anvil.controller.scope_guard import ScopeGuard, ScopeViolation
from anvil.evidence.store import EvidenceStore
from anvil.pipelines.dast.nuclei import NucleiAdapter
from anvil.pipelines.sast.semgrep import SemgrepAdapter
from anvil.reporting.report import ReportGenerator
from anvil.schemas.authorization import AuthorizationRecord
from anvil.schemas.finding import Finding
from anvil.triage.engine import TriageEngine


class Engagement:
    def __init__(self, auth: AuthorizationRecord, runs_dir: Path = Path("runs")):
        self.auth = auth
        self.root = Path(runs_dir) / auth.engagement_id
        self.root.mkdir(parents=True, exist_ok=True)

        self.audit = AuditLog(self.root / "audit.jsonl")
        self.evidence = EvidenceStore(self.root / "evidence")
        self.guard = ScopeGuard(auth)  # raises if unsigned/tampered/expired
        self.triage = TriageEngine()

        self.audit.record(
            "engagement_opened",
            {
                "engagement_id": auth.engagement_id,
                "authorized_by": auth.authorized_by,
                "scope": self.guard.scope_summary(),
                "triage_online": self.triage.online,
            },
        )

    @classmethod
    def from_auth_file(
        cls, path: str, runs_dir: Path = Path("runs")
    ) -> "Engagement":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        auth = AuthorizationRecord(**data)
        return cls(auth, runs_dir=runs_dir)

    # --- SAST --------------------------------------------------------------
    def scan_repo(self, repo_path: str, logic_review: bool = False) -> List[Finding]:
        try:
            self.guard.check_repo(repo_path)
        except ScopeViolation as exc:
            self.audit.record("scope_violation", {"target": repo_path, "error": str(exc)})
            raise

        adapter = SemgrepAdapter()
        if not adapter.is_available():
            self.audit.record("scanner_unavailable", {"tool": adapter.name})
            raise RuntimeError(
                "semgrep is not installed. Install it with `pip install semgrep` "
                "(or `brew install semgrep`) and retry."
            )

        self.audit.record("scan_started", {"pipeline": "sast", "tool": adapter.name, "target": repo_path})
        ref, findings = adapter.scan(self.auth.engagement_id, repo_path, self.evidence)
        self.audit.record("scanner_completed", {"tool": adapter.name, "evidence_ref": ref, "raw_findings": len(findings)})

        if logic_review and self.triage.online:
            findings += self._run_logic_review(repo_path, ref)

        return self._triage_and_persist(findings)

    def _run_logic_review(self, repo_path: str, evidence_ref: str) -> List[Finding]:
        files = self._sample_source(repo_path)
        extra = self.triage.logic_review(self.auth.engagement_id, files, evidence_ref)
        self.audit.record("logic_review_completed", {"files_reviewed": len(files), "new_findings": len(extra)})
        return extra

    @staticmethod
    def _sample_source(repo_path: str, max_files: int = 20) -> Dict[str, str]:
        """A conservative sampler for the logic pass — grabs a bounded set of
        source files. Replace with call-graph/entrypoint selection later."""
        exts = {".py", ".js", ".ts", ".go", ".java", ".rb", ".php"}
        out: Dict[str, str] = {}
        for p in sorted(Path(repo_path).rglob("*")):
            if len(out) >= max_files:
                break
            if p.suffix in exts and p.is_file() and "node_modules" not in p.parts:
                try:
                    out[str(p)] = p.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
        return out

    # --- DAST --------------------------------------------------------------
    def scan_url(self, target_url: str) -> List[Finding]:
        try:
            self.guard.check_url(target_url)
        except ScopeViolation as exc:
            self.audit.record("scope_violation", {"target": target_url, "error": str(exc)})
            raise

        adapter = NucleiAdapter()
        if not adapter.is_available():
            self.audit.record("scanner_unavailable", {"tool": adapter.name})
            raise RuntimeError(
                "nuclei is not installed. See https://github.com/projectdiscovery/nuclei "
                "(or `brew install nuclei`) and retry."
            )

        self.audit.record("scan_started", {"pipeline": "dast", "tool": adapter.name, "target": target_url})
        ref, findings = adapter.scan(self.auth.engagement_id, target_url, self.guard, self.evidence)
        self.audit.record("scanner_completed", {"tool": adapter.name, "evidence_ref": ref, "raw_findings": len(findings)})

        return self._triage_and_persist(findings)

    # --- shared tail -------------------------------------------------------
    def _triage_and_persist(self, findings: List[Finding]) -> List[Finding]:
        self.audit.record("triage_started", {"count": len(findings), "online": self.triage.online})
        triaged = self.triage.triage(findings)
        self.audit.record(
            "triage_completed",
            {
                "decisions": [{"finding_id": f.finding_id, "status": f.status.value} for f in triaged],
                "token_usage": self.triage.usage,
            },
        )

        (self.root / "findings.json").write_text(
            json.dumps([f.model_dump(mode="json") for f in triaged], indent=2),
            encoding="utf-8",
        )
        return triaged

    def write_report(self, findings: List[Finding]) -> Path:
        report = ReportGenerator().render_markdown(
            self.auth.engagement_id, self.guard.scope_summary(), findings
        )
        path = self.root / "report.md"
        path.write_text(report, encoding="utf-8")
        self.audit.record("report_written", {"path": str(path), "chain_ok": self.audit.verify_chain()})
        return path
