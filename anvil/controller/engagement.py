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
from anvil.enrich.risk import enrich
from anvil.evidence.store import EvidenceStore
from anvil.pipelines.dast.http_checks import HttpChecksAdapter
from anvil.pipelines.dast.nuclei import NucleiAdapter
from anvil.pipelines.dast.testssl import TestSslAdapter
from anvil.pipelines.sast.bandit import BanditAdapter
from anvil.pipelines.sast.codeql import CodeqlAdapter
from anvil.pipelines.sast.gitleaks import GitleaksAdapter
from anvil.pipelines.sast.osv import OsvScannerAdapter
from anvil.pipelines.sast.semgrep import SemgrepAdapter
from anvil.pipelines.sast.trivy import TrivyAdapter
from anvil.reporting.html import HtmlReporter, to_pdf
from anvil.reporting.report import ReportGenerator
from anvil.reporting.sarif import SarifReporter
from anvil.schemas.authorization import AuthorizationRecord
from anvil.schemas.finding import Finding
from anvil.state.store import StateStore
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
        self.state = StateStore(self.root.parent / "anvil.db")  # shared across engagements
        self.last_diff = None

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
    @staticmethod
    def _sast_adapters():
        """The SAST scanner set, in report order. Each is independent; adding a
        scanner is one entry here plus its adapter."""
        return [SemgrepAdapter(), BanditAdapter(), CodeqlAdapter(), GitleaksAdapter(),
                TrivyAdapter(), OsvScannerAdapter()]

    def scan_repo(self, repo_path: str, logic_review: bool = False, deep_deps: bool = False) -> List[Finding]:
        try:
            self.guard.check_repo(repo_path)
        except ScopeViolation as exc:
            self.audit.record("scope_violation", {"target": repo_path, "error": str(exc)})
            raise

        adapters = self._sast_adapters()
        if not any(a.is_available() for a in adapters):
            names = [a.name for a in adapters]
            self.audit.record("no_scanners_available", {"pipeline": "sast", "tried": names})
            raise RuntimeError(
                "No SAST scanners installed. Install at least one of: "
                + ", ".join(names)
                + " (e.g. `uv pip install semgrep`, `brew install gitleaks trivy`)."
            )

        findings: List[Finding] = []
        last_ref: Optional[str] = None
        for adapter in adapters:
            if not adapter.is_available():
                self.audit.record("scanner_unavailable", {"tool": adapter.name})
                continue
            self.audit.record("scan_started", {"pipeline": "sast", "tool": adapter.name, "target": repo_path})
            try:
                ref, found = adapter.scan(self.auth.engagement_id, repo_path, self.evidence)
            except Exception as exc:  # a single scanner failure must not abort the run
                self.audit.record("scanner_error", {"tool": adapter.name, "error": str(exc)})
                continue
            self.audit.record(
                "scanner_completed",
                {"tool": adapter.name, "evidence_ref": ref, "raw_findings": len(found)},
            )
            findings += found
            last_ref = ref

        if logic_review and self.triage.online:
            findings += self._run_logic_review(repo_path, last_ref or "")

        return self._triage_and_persist(findings, deep_deps=deep_deps, target=repo_path)

    def _run_logic_review(self, repo_path: str, fallback_ref: str) -> List[Finding]:
        files = self._sample_source(repo_path)
        if files:
            bundle = "\n\n".join(f"=== {p} ===\n{t}" for p, t in files.items())
            ref = self.evidence.put(bundle, label=f"logic_{self.auth.engagement_id}")
        else:
            ref = fallback_ref
        extra = self.triage.logic_review(self.auth.engagement_id, files, ref)
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
    @staticmethod
    def _dast_adapters():
        """The DAST scanner set. http-checks is first-party and always available,
        so the live pipeline works even when nuclei isn't installed."""
        return [HttpChecksAdapter(), TestSslAdapter(), NucleiAdapter()]

    def scan_url(self, target_url: str) -> List[Finding]:
        try:
            self.guard.check_url(target_url)
        except ScopeViolation as exc:
            self.audit.record("scope_violation", {"target": target_url, "error": str(exc)})
            raise

        adapters = self._dast_adapters()
        if not any(a.is_available() for a in adapters):
            names = [a.name for a in adapters]
            self.audit.record("no_scanners_available", {"pipeline": "dast", "tried": names})
            raise RuntimeError("No DAST scanners available: " + ", ".join(names) + ".")

        findings: List[Finding] = []
        for adapter in adapters:
            if not adapter.is_available():
                self.audit.record("scanner_unavailable", {"tool": adapter.name})
                continue
            self.audit.record("scan_started", {"pipeline": "dast", "tool": adapter.name, "target": target_url})
            try:
                ref, found = adapter.scan(self.auth.engagement_id, target_url, self.guard, self.evidence)
            except ScopeViolation as exc:  # e.g. a redirect leaving the authorized scope
                self.audit.record("scope_violation", {"tool": adapter.name, "target": target_url, "error": str(exc)})
                continue
            except Exception as exc:  # a single scanner failure must not abort the run
                self.audit.record("scanner_error", {"tool": adapter.name, "error": str(exc)})
                continue
            self.audit.record(
                "scanner_completed",
                {"tool": adapter.name, "evidence_ref": ref, "raw_findings": len(found)},
            )
            findings += found

        return self._triage_and_persist(findings, target=target_url)

    # --- shared tail -------------------------------------------------------
    def _triage_and_persist(
        self, findings: List[Finding], deep_deps: bool = False, target: str = None
    ) -> List[Finding]:
        sca_count = sum(1 for f in findings if f.source_tool in ("trivy",))
        self.audit.record(
            "triage_started",
            {"count": len(findings), "online": self.triage.online,
             "deep_deps": deep_deps, "sca_fast_pathed": 0 if deep_deps else sca_count},
        )
        triaged = self.triage.triage(findings, deep_deps=deep_deps)
        self.audit.record(
            "triage_completed",
            {
                "decisions": [{"finding_id": f.finding_id, "status": f.status.value} for f in triaged],
                "token_usage": self.triage.usage,
            },
        )

        # Enrich with contextual risk (reachability harvested by the scanners ×
        # asset criticality × exposure), then apply suppressions and record.
        enrich(triaged, asset=self.auth.asset)
        suppressed = self.state.apply_suppressions(triaged)
        self.last_diff = self.state.record_run(self.auth.engagement_id, triaged, target=target)
        self.audit.record(
            "run_recorded",
            {"run_id": self.last_diff.run_id, "new": len(self.last_diff.new),
             "resolved": len(self.last_diff.resolved), "existing": len(self.last_diff.existing),
             "suppressed": suppressed},
        )

        (self.root / "findings.json").write_text(
            json.dumps([f.model_dump(mode="json") for f in triaged], indent=2),
            encoding="utf-8",
        )
        return triaged

    def write_report(self, findings: List[Finding]) -> Path:
        report = ReportGenerator().render_markdown(
            self.auth.engagement_id, self.guard.scope_summary(), findings, diff=self.last_diff
        )
        path = self.root / "report.md"
        path.write_text(report, encoding="utf-8")
        self.audit.record("report_written", {"format": "md", "path": str(path), "chain_ok": self.audit.verify_chain()})
        return path

    def write_sarif(self, findings: List[Finding]) -> Path:
        sarif = SarifReporter().render_json(self.auth.engagement_id, findings)
        path = self.root / "results.sarif"
        path.write_text(sarif, encoding="utf-8")
        self.audit.record("report_written", {"format": "sarif", "path": str(path)})
        return path

    def write_html(self, findings: List[Finding]) -> Path:
        html = HtmlReporter().render(
            self.auth.engagement_id, self.guard.scope_summary(), findings, diff=self.last_diff
        )
        path = self.root / "report.html"
        path.write_text(html, encoding="utf-8")
        self.audit.record("report_written", {"format": "html", "path": str(path)})
        return path

    def write_pdf(self, findings: List[Finding]) -> Path:
        """Render a PDF (requires WeasyPrint). Raises RuntimeError with guidance
        if it is not installed."""
        html = HtmlReporter().render(
            self.auth.engagement_id, self.guard.scope_summary(), findings
        )
        path = to_pdf(html, self.root / "report.pdf")
        self.audit.record("report_written", {"format": "pdf", "path": str(path)})
        return path
