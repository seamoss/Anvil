"""Dependency lane: cross-source dedup, license separation, rendering."""

from __future__ import annotations

from anvil.pipelines.sast.trivy import TrivyAdapter
from anvil.reporting.deps import aggregate, html_section, markdown_section
from anvil.schemas.finding import (
    Finding,
    FindingStatus,
    Location,
    Pipeline,
    Severity,
)


def dep(source, cve, component, cvss=8.7, severity=Severity.HIGH):
    return Finding(
        finding_id=f"{source}-{cve}-{component}",
        engagement_id="E", pipeline=Pipeline.SAST, source_tool=source,
        rule_id=cve, title=f"{component}: {cve}", severity=severity, cvss_score=cvss,
        remediation=f"Upgrade to 1.2.3 or later.", component=component,
        status=FindingStatus.TRIAGED, location=Location(file_path="package-lock.json"),
    )


def lic(name="GPL-3.0", pkg="somepkg", severity=Severity.HIGH):
    return TrivyAdapter()._license_finding(
        "E", "package-lock.json",
        {"Severity": severity.value.upper(), "Category": "restricted", "Name": name, "PkgName": pkg},
        "ref",
    )


# --- license finding -------------------------------------------------------
def test_trivy_license_filter_drops_permissive():
    # Only restricted/reciprocal (MEDIUM+) licenses are surfaced; MIT/ISC noise is dropped.
    data = {"Results": [{"Target": "package-lock.json", "Licenses": [
        {"Severity": "LOW", "Category": "notice", "Name": "MIT", "PkgName": "a"},
        {"Severity": "UNKNOWN", "Category": "unknown", "Name": "ISC", "PkgName": "b"},
        {"Severity": "MEDIUM", "Category": "reciprocal", "Name": "MPL-2.0", "PkgName": "c"},
        {"Severity": "HIGH", "Category": "restricted", "Name": "GPL-3.0", "PkgName": "d"},
    ]}]}
    findings = TrivyAdapter().parse("E", data, "ref")
    names = sorted(f.rule_id for f in findings)
    assert names == ["GPL-3.0", "MPL-2.0"]  # MIT / ISC dropped


def test_license_finding_is_distinct_source():
    f = lic()
    assert f.source_tool == "trivy-license"
    assert f.is_license and f.is_dependency
    assert f.severity is Severity.HIGH
    assert f.rule_id == "GPL-3.0"
    assert "GPL-3.0" in f.title


# --- aggregation -----------------------------------------------------------
def test_dedup_across_trivy_and_osv():
    vulns, licenses = aggregate([
        dep("trivy", "CVE-2020-1", "flask@0.12.2"),
        dep("osv", "CVE-2020-1", "flask@0.12.2"),
        dep("trivy", "CVE-2020-2", "requests@2.19.1"),
    ])
    assert len(vulns) == 2                       # the shared CVE collapses to one row
    shared = next(v for v in vulns if v["id"] == "CVE-2020-1")
    assert shared["sources"] == {"trivy", "osv"}  # both scanners credited
    assert licenses == []


def test_vulns_sorted_by_severity_then_cvss():
    vulns, _ = aggregate([
        dep("trivy", "CVE-A", "a@1", cvss=5.0, severity=Severity.MEDIUM),
        dep("trivy", "CVE-B", "b@1", cvss=9.8, severity=Severity.CRITICAL),
    ])
    assert vulns[0]["id"] == "CVE-B"  # critical first


def test_licenses_separated():
    vulns, licenses = aggregate([dep("trivy", "CVE-1", "a@1"), lic()])
    assert len(vulns) == 1 and len(licenses) == 1


# --- rendering -------------------------------------------------------------
def test_markdown_section_has_table_and_sources():
    md = markdown_section([dep("trivy", "CVE-1", "flask@0.12.2"), dep("osv", "CVE-1", "flask@0.12.2"), lic()])
    assert "## Dependencies" in md
    assert "osv, trivy" in md          # dual-source credit (sorted)
    assert "License concerns" in md
    assert "flask@0.12.2" in md


def test_empty_section_is_blank():
    assert markdown_section([]) == ""
    assert html_section([]) == ""


def test_html_section_escapes():
    html = html_section([dep("trivy", "CVE-1", "<pkg>@1")])
    assert "<pkg>" not in html and "&lt;pkg&gt;" in html
