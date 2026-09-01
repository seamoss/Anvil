"""Mapping tests for the gitleaks (secrets) and trivy (SCA) adapters.

These exercise the native-JSON → Finding mapping directly, using the real output
shapes captured from gitleaks 8.x and trivy 0.74 — no subprocess, so they're
fast and hermetic.
"""

from __future__ import annotations

from anvil.pipelines.sast.gitleaks import GitleaksAdapter, _mask
from anvil.pipelines.sast.trivy import TrivyAdapter
from anvil.schemas.finding import Confidence, Pipeline, Severity


# --- gitleaks --------------------------------------------------------------
GITLEAKS_ITEM = {
    "RuleID": "stripe-access-token",
    "Description": "Stripe Access Token",
    "StartLine": 6,
    "File": "settings.py",
    "Secret": "EXAMPLE-REDACTED-TEST-TOKEN-not-a-real-secret",
    "Match": 'STRIPE_SECRET_KEY = "EXAMPLE-REDACTED-TEST-TOKEN-not-a-real-secret"',
}


def test_gitleaks_maps_to_secret_finding():
    f = GitleaksAdapter()._to_finding("E", GITLEAKS_ITEM, "ref1")
    assert f.source_tool == "gitleaks"
    assert f.pipeline is Pipeline.SAST
    assert f.rule_id == "stripe-access-token"
    assert f.cwe == ["CWE-798"]
    assert f.owasp_category == "A07:2021-Identification and Authentication Failures"
    assert f.severity is Severity.HIGH
    assert f.location.file_path == "settings.py"
    assert f.location.start_line == 6
    assert f.evidence_ref == "ref1"


def test_gitleaks_never_surfaces_the_raw_secret():
    secret = GITLEAKS_ITEM["Secret"]
    f = GitleaksAdapter()._to_finding("E", GITLEAKS_ITEM, "ref1")
    blob = " ".join([f.title, f.description, f.remediation, f.location.snippet or ""])
    assert secret not in blob  # the plaintext secret must never reach a Finding
    assert "[redacted" in f.location.snippet


def test_gitleaks_generic_rule_is_lower_confidence():
    generic = dict(GITLEAKS_ITEM, RuleID="generic-api-key")
    assert GitleaksAdapter()._to_finding("E", generic, "r").confidence is Confidence.MEDIUM
    assert GitleaksAdapter()._to_finding("E", GITLEAKS_ITEM, "r").confidence is Confidence.HIGH


def test_mask_redacts():
    assert "sk_live" not in _mask("TOKENsecretvalue0000")[4:]  # only a short head kept
    assert _mask("") == "[redacted]"


# --- trivy -----------------------------------------------------------------
TRIVY_VULN = {
    "VulnerabilityID": "CVE-2018-1000656",
    "PkgName": "Flask",
    "InstalledVersion": "0.12.2",
    "FixedVersion": "0.12.3",
    "Severity": "HIGH",
    "Title": "python-flask: denial of service via crafted JSON",
    "CweIDs": ["CWE-20"],
    "CVSS": {
        "nvd": {"V3Score": 7.5, "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
        "redhat": {"V3Score": 5.9},
    },
}


def test_trivy_maps_to_sca_finding():
    f = TrivyAdapter()._to_finding("E", "requirements.txt", TRIVY_VULN, "ref2")
    assert f.source_tool == "trivy"
    assert f.rule_id == "CVE-2018-1000656"
    assert f.owasp_category == "A06:2021-Vulnerable and Outdated Components"
    assert f.severity is Severity.HIGH
    assert f.cwe == ["CWE-20"]
    assert f.cvss_score == 7.5
    assert f.cvss_vector.startswith("CVSS:3.1/")
    assert f.location.file_path == "requirements.txt"
    assert "0.12.3" in f.remediation


def test_trivy_cvss_prefers_nvd_then_falls_back():
    adapter = TrivyAdapter()
    assert adapter._cvss(TRIVY_VULN) == (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")

    only_redhat = {"CVSS": {"redhat": {"V3Score": 5.9, "V3Vector": "CVSS:3.1/..."}}}
    assert only_redhat and adapter._cvss(only_redhat) == (5.9, "CVSS:3.1/...")

    assert adapter._cvss({"CVSS": {}}) == (None, None)


def test_trivy_no_fix_version_remediation():
    no_fix = dict(TRIVY_VULN)
    no_fix.pop("FixedVersion")
    f = TrivyAdapter()._to_finding("E", "requirements.txt", no_fix, "r")
    assert "No fixed version" in f.remediation
