"""SARIF and HTML report renderer tests."""

from __future__ import annotations

import json

import pytest

from anvil.reporting.html import HtmlReporter
from anvil.reporting.sarif import SarifReporter
from anvil.schemas.finding import (
    Confidence,
    Finding,
    FindingStatus,
    Location,
    Pipeline,
    Severity,
)


def _f(source, sev, status=FindingStatus.CONFIRMED, **kw):
    loc = kw.pop("location", Location())
    defaults = dict(
        finding_id=kw.pop("fid", Finding.make_id("E", source, kw.get("rule_id", "r"), loc.as_ref())),
        engagement_id="E",
        pipeline=kw.pop("pipeline", Pipeline.SAST),
        source_tool=source,
        title=kw.pop("title", f"{source} finding"),
        severity=sev,
        confidence=Confidence.MEDIUM,
        status=status,
        location=loc,
    )
    defaults.update(kw)
    return Finding(**defaults)


@pytest.fixture
def findings():
    return [
        _f("semgrep", Severity.HIGH, rule_id="python.sqli", cwe=["CWE-89"],
           owasp_category="A03:2021-Injection", cvss_score=8.8,
           cvss_vector="CVSS:3.1/AV:N", location=Location(file_path="app.py", start_line=10)),
        _f("trivy", Severity.MEDIUM, rule_id="CVE-2020-1", cwe=["CWE-20"],
           owasp_category="A06:2021-Vulnerable and Outdated Components",
           location=Location(file_path="requirements.txt")),  # no line
        _f("nuclei", Severity.LOW, rule_id="tls-check", pipeline=Pipeline.DAST,
           location=Location(url="https://x.example/health")),
        _f("semgrep", Severity.CRITICAL, rule_id="dropme", status=FindingStatus.FALSE_POSITIVE),
        _f("semgrep", Severity.HIGH, rule_id="xss", title="XSS",
           description="<script>alert(1)</script>", location=Location(file_path="v.py", start_line=3)),
    ]


# --- SARIF -----------------------------------------------------------------
def test_sarif_top_level(findings):
    doc = SarifReporter().render("E", findings)
    assert doc["version"] == "2.1.0"
    # one run per source tool among reportable findings: nuclei, semgrep, trivy
    tools = sorted(r["tool"]["driver"]["name"] for r in doc["runs"])
    assert tools == ["anvil-nuclei", "anvil-semgrep", "anvil-trivy"]


def test_sarif_excludes_false_positives(findings):
    doc = SarifReporter().render("E", findings)
    all_rule_ids = [res["ruleId"] for run in doc["runs"] for res in run["results"]]
    assert "dropme" not in all_rule_ids


def test_sarif_levels_and_security_severity(findings):
    doc = SarifReporter().render("E", findings)
    semgrep = next(r for r in doc["runs"] if r["tool"]["driver"]["name"] == "anvil-semgrep")
    by_rule = {res["ruleId"]: res for res in semgrep["results"]}
    assert by_rule["python.sqli"]["level"] == "error"  # high → error

    rules = {rule["id"]: rule for rule in semgrep["tool"]["driver"]["rules"]}
    assert rules["python.sqli"]["properties"]["security-severity"] == "8.8"  # from CVSS


def test_sarif_severity_fallback_when_no_cvss(findings):
    doc = SarifReporter().render("E", findings)
    trivy = next(r for r in doc["runs"] if r["tool"]["driver"]["name"] == "anvil-trivy")
    rule = trivy["tool"]["driver"]["rules"][0]
    assert rule["properties"]["security-severity"] == "5.0"  # medium fallback
    # no start line → no region, but the artifact uri is present
    loc = trivy["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "requirements.txt"
    assert "region" not in loc


def test_sarif_dast_url_location(findings):
    doc = SarifReporter().render("E", findings)
    nuclei = next(r for r in doc["runs"] if r["tool"]["driver"]["name"] == "anvil-nuclei")
    uri = nuclei["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "https://x.example/health"


def test_sarif_json_parses(findings):
    assert json.loads(SarifReporter().render_json("E", findings))["version"] == "2.1.0"


# --- HTML ------------------------------------------------------------------
def test_html_structure(findings):
    html = HtmlReporter().render("E", ["repos: /x"], findings)
    assert "<!doctype html>" in html.lower()
    assert "Security Assessment" in html
    assert "python.sqli" in html
    assert "Compliance Mapping" in html
    assert "A03:2021-Injection" in html


def test_html_escapes_user_content(findings):
    html = HtmlReporter().render("E", ["repos: /x"], findings)
    assert "<script>alert(1)</script>" not in html  # must be escaped
    assert "&lt;script&gt;" in html


def test_html_excludes_false_positives(findings):
    html = HtmlReporter().render("E", ["repos: /x"], findings)
    assert "dropme" not in html
