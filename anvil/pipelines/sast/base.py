"""Base class every SAST scanner adapter implements.

An adapter's whole job is: run its tool, hand the raw output to the evidence
store, and map native results into normalized `Finding`s. Nothing downstream
knows or cares which scanner produced a finding.
"""

from __future__ import annotations

import abc
import shutil
from typing import List, Tuple

from anvil.evidence.store import EvidenceStore
from anvil.schemas.finding import Finding


class SastAdapter(abc.ABC):
    #: The binary this adapter shells out to (used by the default is_available()).
    binary: str = ""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        ...

    def is_available(self) -> bool:
        """True if the underlying tool is installed and runnable."""
        return bool(self.binary) and shutil.which(self.binary) is not None

    @abc.abstractmethod
    def scan(
        self, engagement_id: str, repo_path: str, evidence: EvidenceStore
    ) -> Tuple[str, List[Finding]]:
        """Run the scan.

        Returns (evidence_ref, findings). Implementations must persist their raw
        output via `evidence.put(...)` and stamp the returned ref onto each
        finding's `evidence_ref`.
        """
        ...
