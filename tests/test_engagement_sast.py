"""Multi-scanner SAST orchestration in the engagement.

Verifies the resilience contract: available scanners all contribute, an
unavailable scanner is skipped, a scanner that raises is logged but does not
abort the assessment, and zero available scanners is a hard error.
"""

from __future__ import annotations

from typing import List, Tuple

import pytest

from anvil.controller.engagement import Engagement
from anvil.evidence.store import EvidenceStore
from anvil.pipelines.sast.base import SastAdapter
from anvil.schemas.finding import Finding, Location, Pipeline, Severity


class FakeAdapter(SastAdapter):
    def __init__(self, name, available=True, raises=False, n=1):
        self._name = name
        self._available = available
        self._raises = raises
        self._n = n

    @property
    def name(self):
        return self._name

    def is_available(self):
        return self._available

    def scan(self, engagement_id, repo_path, evidence: EvidenceStore) -> Tuple[str, List[Finding]]:
        if self._raises:
            raise RuntimeError("boom")
        ref = evidence.put(f"raw-{self._name}", label=self._name)
        findings = [
            Finding(
                finding_id=Finding.make_id(engagement_id, self._name, f"r{i}", f"f{i}.py:1"),
                engagement_id=engagement_id,
                pipeline=Pipeline.SAST,
                source_tool=self._name,
                rule_id=f"r{i}",
                title=f"{self._name} finding {i}",
                severity=Severity.MEDIUM,
                location=Location(file_path=f"f{i}.py", start_line=1),
                evidence_ref=ref,
            )
            for i in range(self._n)
        ]
        return ref, findings


@pytest.fixture
def engagement(make_auth, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    auth = make_auth(repos=[str(repo)])
    eng = Engagement(auth, runs_dir=tmp_path / "runs")
    return eng, str(repo)


def test_all_scanners_contribute(engagement, monkeypatch):
    eng, repo = engagement
    monkeypatch.setattr(
        Engagement, "_sast_adapters",
        staticmethod(lambda: [FakeAdapter("a", n=2), FakeAdapter("b", n=1)]),
    )
    findings = eng.scan_repo(repo)
    sources = sorted(f.source_tool for f in findings)
    assert sources == ["a", "a", "b"]


def test_failing_scanner_does_not_abort(engagement, monkeypatch):
    eng, repo = engagement
    monkeypatch.setattr(
        Engagement, "_sast_adapters",
        staticmethod(lambda: [FakeAdapter("ok", n=1), FakeAdapter("bad", raises=True)]),
    )
    findings = eng.scan_repo(repo)
    assert [f.source_tool for f in findings] == ["ok"]
    # the failure is recorded, and the chain stays intact
    log = (eng.root / "audit.jsonl").read_text()
    assert "scanner_error" in log
    assert eng.audit.verify_chain() is True


def test_unavailable_scanner_is_skipped(engagement, monkeypatch):
    eng, repo = engagement
    monkeypatch.setattr(
        Engagement, "_sast_adapters",
        staticmethod(lambda: [FakeAdapter("up", n=1), FakeAdapter("down", available=False)]),
    )
    findings = eng.scan_repo(repo)
    assert [f.source_tool for f in findings] == ["up"]


def test_no_scanners_available_is_hard_error(engagement, monkeypatch):
    eng, repo = engagement
    monkeypatch.setattr(
        Engagement, "_sast_adapters",
        staticmethod(lambda: [FakeAdapter("x", available=False)]),
    )
    with pytest.raises(RuntimeError, match="No SAST scanners"):
        eng.scan_repo(repo)
