"""OSV-Scanner adapter parsing tests (real OSV 2.x JSON shape)."""

from __future__ import annotations

from anvil.pipelines.sast.osv import OsvScannerAdapter
from anvil.schemas.finding import Pipeline, Severity

A = OsvScannerAdapter()

OSV_DATA = {
    "results": [
        {
            "source": {"path": "requirements.txt", "type": "lockfile"},
            "packages": [{
                "package": {"name": "flask", "version": "0.12.2", "ecosystem": "PyPI"},
                "groups": [{
                    "ids": ["PYSEC-2018-66", "GHSA-562c-5r94-xh97"],
                    "aliases": ["CVE-2018-1000656", "GHSA-562c-5r94-xh97", "PYSEC-2018-66"],
                    "max_severity": "8.7",
                }],
                "vulnerabilities": [{
                    "id": "PYSEC-2018-66",
                    "summary": "Denial of service via crafted JSON",
                    "aliases": ["CVE-2018-1000656"],
                    "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "0.12.3"}]}]}],
                }],
            }],
        },
        {  # a vendored/installed copy — must be filtered out
            "source": {"path": "node_modules/dep/package-lock.json"},
            "packages": [{
                "package": {"name": "dep", "version": "1.0.0"},
                "groups": [{"ids": ["CVE-2020-1"], "max_severity": "5.0"}],
                "vulnerabilities": [],
            }],
        },
    ]
}


def test_parse_maps_and_filters_vendored():
    findings = A.parse("E", OSV_DATA, "ref")
    assert len(findings) == 1  # node_modules one filtered
    f = findings[0]
    assert f.source_tool == "osv"
    assert f.pipeline is Pipeline.SAST
    assert f.rule_id == "CVE-2018-1000656"  # canonical CVE preferred over PYSEC/GHSA
    assert f.severity is Severity.HIGH  # 8.7
    assert f.component == "flask@0.12.2"
    assert f.owasp_category == "A06:2021-Vulnerable and Outdated Components"
    assert f.is_dependency and not f.is_license
    assert "0.12.3" in f.remediation


def test_severity_from_max_severity():
    data = {"results": [{"source": {"path": "x"}, "packages": [{
        "package": {"name": "p", "version": "1"},
        "groups": [{"ids": ["CVE-1"], "max_severity": "9.8"}],
        "vulnerabilities": [],
    }]}]}
    assert A.parse("E", data, "r")[0].severity is Severity.CRITICAL


def test_missing_severity_is_info():
    data = {"results": [{"source": {"path": "x"}, "packages": [{
        "package": {"name": "p", "version": "1"},
        "groups": [{"ids": ["GHSA-abc"], "max_severity": ""}],
        "vulnerabilities": [],
    }]}]}
    f = A.parse("E", data, "r")[0]
    assert f.severity is Severity.INFO
    assert f.rule_id == "GHSA-abc"  # no CVE alias → falls back to the id
