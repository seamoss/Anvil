"""Base class every DAST scanner adapter implements.

DAST adapters receive a `ScopeGuard` and MUST call `guard.check_url(...)`
immediately before every outbound request they make — scope is re-validated at
request time, never assumed from an up-front check.
"""

from __future__ import annotations

import abc
import shutil
from typing import List, Tuple

from anvil.controller.scope_guard import ScopeGuard
from anvil.evidence.store import EvidenceStore
from anvil.schemas.finding import Finding


class DastAdapter(abc.ABC):
    binary: str = ""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        ...

    def is_available(self) -> bool:
        return bool(self.binary) and shutil.which(self.binary) is not None

    @abc.abstractmethod
    def scan(
        self,
        engagement_id: str,
        target_url: str,
        guard: ScopeGuard,
        evidence: EvidenceStore,
    ) -> Tuple[str, List[Finding]]:
        """Run a NON-DESTRUCTIVE scan against target_url and return
        (evidence_ref, findings). Must re-validate every request URL through
        `guard.check_url(...)`."""
        ...
