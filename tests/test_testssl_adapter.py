"""testssl adapter parsing tests (using real testssl JSON record shapes)."""

from __future__ import annotations

from anvil.pipelines.dast.testssl import TestSslAdapter
from anvil.schemas.finding import Pipeline, Severity

A = TestSslAdapter()

# Shape captured from testssl.sh 3.x against a local TLS endpoint.
RECORDS = [
    {"id": "TLS1", "ip": "127.0.0.1", "port": "8443", "severity": "LOW", "finding": "offered (deprecated)"},
    {"id": "cert_chain_of_trust", "ip": "127.0.0.1", "port": "8443", "severity": "CRITICAL", "finding": "failed (self signed)."},
    {"id": "cert_subjectAltName", "ip": "127.0.0.1", "port": "8443", "severity": "HIGH", "finding": "No SAN"},
    {"id": "scanTime", "ip": "127.0.0.1", "port": "8443", "severity": "INFO", "finding": "42"},
    {"id": "somecheck", "ip": "127.0.0.1", "port": "8443", "severity": "OK", "finding": "not vulnerable"},
    {"id": "HSTS_time", "ip": "127.0.0.1", "port": "8443", "severity": "MEDIUM", "finding": "short", "cwe": "CWE-310"},
]


def test_parse_maps_and_filters():
    findings = A.parse("E", "127.0.0.1:8443", RECORDS, "ref")
    ids = {f.rule_id for f in findings}
    # OK / INFO records are dropped; actionable ones kept.
    assert "scanTime" not in ids and "somecheck" not in ids
    assert {"TLS1", "cert_chain_of_trust", "cert_subjectAltName", "HSTS_time"} == ids


def test_severity_and_owasp_mapping():
    by_id = {f.rule_id: f for f in A.parse("E", "127.0.0.1:8443", RECORDS, "ref")}
    assert by_id["cert_chain_of_trust"].severity is Severity.CRITICAL
    assert by_id["TLS1"].severity is Severity.LOW
    assert all(f.owasp_category == "A02:2021-Cryptographic Failures" for f in by_id.values())
    assert all(f.pipeline is Pipeline.DAST for f in by_id.values())


def test_cwe_passthrough_when_present():
    by_id = {f.rule_id: f for f in A.parse("E", "127.0.0.1:8443", RECORDS, "ref")}
    assert by_id["HSTS_time"].cwe == ["CWE-310"]
    assert by_id["TLS1"].cwe == []  # absent → empty


def test_remediation_is_contextual():
    by_id = {f.rule_id: f for f in A.parse("E", "127.0.0.1:8443", RECORDS, "ref")}
    assert "certificate" in by_id["cert_chain_of_trust"].remediation.lower()
    assert "tls 1.2" in by_id["TLS1"].remediation.lower()


def test_binary_name():
    assert A.binary == "testssl.sh"
