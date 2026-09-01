"""Unit tests for the built-in HTTP checks analyzers (no network)."""

from __future__ import annotations

from anvil.pipelines.dast.http_checks import (
    _CORS_PROBE_ORIGIN,
    HttpChecksAdapter,
    _Resp,
)
from anvil.schemas.finding import Pipeline, Severity

A = HttpChecksAdapter()


def _rules(findings):
    return {f.rule_id for f in findings}


# --- transport / headers ---------------------------------------------------
def test_cleartext_http_flagged():
    resp = _Resp(url="http://x.example/", status=200, headers={})
    out = A.analyze("E", "http://x.example/", resp, "ref")
    assert "cleartext-http" in _rules(out)
    sqli = next(f for f in out if f.rule_id == "cleartext-http")
    assert sqli.pipeline is Pipeline.DAST
    assert sqli.severity is Severity.HIGH
    assert sqli.cwe == ["CWE-319"]


def test_https_missing_hsts_and_headers():
    resp = _Resp(url="https://x.example/", status=200, headers={})
    out = A.analyze("E", "https://x.example/", resp, "ref")
    rules = _rules(out)
    assert "missing-hsts" in rules
    assert "missing-security-headers" in rules
    assert "cleartext-http" not in rules  # it's https


def test_fully_hardened_response_is_clean():
    resp = _Resp(
        url="https://x.example/",
        status=200,
        headers={
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "no-referrer",
        },
        cookies=["sid=abc; Secure; HttpOnly; SameSite=Strict"],
    )
    out = A.analyze("E", "https://x.example/", resp, "ref")
    assert out == []


def test_version_disclosure():
    resp = _Resp(url="https://x.example/", status=200,
                 headers={"server": "nginx/1.25.3", "strict-transport-security": "x",
                          "content-security-policy": "x", "x-content-type-options": "x",
                          "x-frame-options": "x", "referrer-policy": "x"})
    out = A.analyze("E", "https://x.example/", resp, "ref")
    assert "version-disclosure" in _rules(out)


def test_server_header_without_version_not_flagged():
    resp = _Resp(url="https://x.example/", status=200,
                 headers={"server": "nginx", "strict-transport-security": "x",
                          "content-security-policy": "x", "x-content-type-options": "x",
                          "x-frame-options": "x", "referrer-policy": "x"})
    assert "version-disclosure" not in _rules(A.analyze("E", "https://x.example/", resp, "ref"))


# --- cookies ---------------------------------------------------------------
def test_insecure_cookie_flags():
    resp = _Resp(url="https://x.example/", status=200,
                 headers={"strict-transport-security": "x", "content-security-policy": "x",
                          "x-content-type-options": "x", "x-frame-options": "x", "referrer-policy": "x"},
                 cookies=["session=abc123"])
    out = A.analyze("E", "https://x.example/", resp, "ref")
    cookie = next(f for f in out if f.rule_id == "insecure-cookie")
    assert cookie.severity is Severity.MEDIUM
    for flag in ("Secure", "HttpOnly", "SameSite"):
        assert flag in cookie.description


# --- CORS ------------------------------------------------------------------
def test_cors_reflected_origin_with_credentials_is_high():
    out = A._check_cors("E", "https://x.example/",
                        {"access-control-allow-origin": _CORS_PROBE_ORIGIN,
                         "access-control-allow-credentials": "true"}, "ref")
    assert out and out[0].severity is Severity.HIGH


def test_cors_reflected_origin_without_credentials_is_medium():
    out = A._check_cors("E", "https://x.example/",
                        {"access-control-allow-origin": _CORS_PROBE_ORIGIN}, "ref")
    assert out and out[0].severity is Severity.MEDIUM


def test_cors_wildcard_only_is_low():
    out = A._check_cors("E", "https://x.example/", {"access-control-allow-origin": "*"}, "ref")
    assert out and out[0].severity is Severity.LOW


def test_cors_specific_trusted_origin_not_flagged():
    out = A._check_cors("E", "https://x.example/",
                        {"access-control-allow-origin": "https://trusted.example"}, "ref")
    assert out == []


def test_no_cors_header_no_finding():
    assert A._check_cors("E", "https://x.example/", {}, "ref") == []
