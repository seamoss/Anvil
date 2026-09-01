"""The normalized Finding model — the spine of the whole system.

Every scanner adapter maps its native output into a `Finding`. Everything
downstream (triage, evidence, reporting) speaks only this schema, so adding a
new scanner later is just one adapter that emits `Finding`s.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Ordered so `list(Severity)` and comparisons sort worst-first when needed."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]
        return order.index(self)


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Pipeline(str, Enum):
    SAST = "sast"
    DAST = "dast"


class FindingStatus(str, Enum):
    """Lifecycle of a finding as it moves through triage."""

    NEW = "new"  # raw from a scanner, not yet triaged
    TRIAGED = "triaged"  # LLM has reviewed and scored it
    CONFIRMED = "confirmed"  # a real issue to report
    FALSE_POSITIVE = "false_positive"  # triaged out
    DUPLICATE = "duplicate"  # merged into another finding


class Location(BaseModel):
    """Where a finding lives. SAST fills file/line; DAST fills url/method/param."""

    # SAST
    file_path: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    snippet: Optional[str] = None

    # DAST
    url: Optional[str] = None
    http_method: Optional[str] = None
    parameter: Optional[str] = None

    def as_ref(self) -> str:
        if self.file_path:
            loc = self.file_path
            if self.start_line:
                loc += f":{self.start_line}"
            return loc
        if self.url:
            base = self.url
            if self.parameter:
                base += f" (param: {self.parameter})"
            return base
        return "unknown"


class Finding(BaseModel):
    """One normalized vulnerability finding from any source."""

    finding_id: str = Field(..., description="Stable id, unique within an engagement.")
    engagement_id: str
    pipeline: Pipeline

    source_tool: str = Field(..., description="e.g. 'semgrep', 'nuclei', 'llm-logic'.")
    rule_id: Optional[str] = Field(None, description="Native scanner rule/check id.")

    title: str
    description: str = ""
    remediation: str = ""

    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.MEDIUM

    # Compliance mappings — populated by the scanner where known, otherwise by triage.
    cwe: List[str] = Field(default_factory=list, description="e.g. ['CWE-89'].")
    owasp_category: Optional[str] = Field(None, description="e.g. 'A03:2021-Injection'.")
    cvss_vector: Optional[str] = None
    cvss_score: Optional[float] = None

    location: Location = Field(default_factory=Location)

    # Traceability. `evidence_ref` points into the EvidenceStore at the exact raw
    # scanner output this finding was derived from — the auditor's replay handle.
    evidence_ref: Optional[str] = None

    status: FindingStatus = FindingStatus.NEW
    triage_note: Optional[str] = Field(None, description="Why triage set this status.")
    duplicate_of: Optional[str] = Field(None, description="finding_id it merged into.")

    discovered_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @staticmethod
    def make_id(engagement_id: str, source_tool: str, rule_id: str, location: str) -> str:
        """Deterministic id so re-scans of unchanged code produce stable ids
        (enables diffing findings across runs)."""
        raw = f"{engagement_id}|{source_tool}|{rule_id}|{location}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
