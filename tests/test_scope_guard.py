from __future__ import annotations

import pytest

from anvil.controller.scope_guard import ScopeGuard, ScopeViolation


# --- construction gate -----------------------------------------------------
def test_rejects_unsigned_record(make_auth):
    with pytest.raises(ScopeViolation):
        ScopeGuard(make_auth(sign=False))


def test_rejects_tampered_record(make_auth):
    auth = make_auth(repos=["/repo/a"])
    auth.scope.repos.append("/repo/evil")  # post-signing tamper
    with pytest.raises(ScopeViolation):
        ScopeGuard(auth)


def test_rejects_expired_record(make_auth):
    with pytest.raises(ScopeViolation):
        ScopeGuard(make_auth(repos=["/repo/a"], expires_in_days=-1))


def test_rejects_when_no_signing_key(make_auth, monkeypatch):
    auth = make_auth(repos=["/repo/a"])
    monkeypatch.delenv("ANVIL_AUTH_SIGNING_KEY", raising=False)
    with pytest.raises(ScopeViolation):
        ScopeGuard(auth, signing_key="")


# --- repo scope ------------------------------------------------------------
def test_repo_exact_match_allowed(make_auth, tmp_path):
    repo = str(tmp_path)
    guard = ScopeGuard(make_auth(repos=[repo]))
    assert guard.check_repo(repo) == repo


def test_repo_out_of_scope_refused(make_auth, tmp_path):
    guard = ScopeGuard(make_auth(repos=[str(tmp_path)]))
    with pytest.raises(ScopeViolation):
        guard.check_repo("/some/other/path")


# --- url / domain scope ----------------------------------------------------
def test_domain_allowed(make_auth):
    guard = ScopeGuard(make_auth(domains=["example.com"]))
    assert guard.check_url("https://example.com/health")


def test_domain_denied(make_auth):
    guard = ScopeGuard(make_auth(domains=["example.com"]))
    with pytest.raises(ScopeViolation):
        guard.check_url("https://evil.example/")


def test_subdomain_requires_flag(make_auth):
    strict = ScopeGuard(make_auth(domains=["example.com"], include_subdomains=False))
    with pytest.raises(ScopeViolation):
        strict.check_url("https://api.example.com/")

    loose = ScopeGuard(make_auth(domains=["example.com"], include_subdomains=True))
    assert loose.check_url("https://api.example.com/")


def test_subdomain_flag_does_not_allow_suffix_lookalike(make_auth):
    # 'notexample.com' must NOT match 'example.com' even with subdomains on.
    guard = ScopeGuard(make_auth(domains=["example.com"], include_subdomains=True))
    with pytest.raises(ScopeViolation):
        guard.check_url("https://notexample.com/")


# --- ip range backstop (resolution mocked; no real DNS) --------------------
def test_ip_range_in_range_allowed(make_auth, monkeypatch):
    guard = ScopeGuard(make_auth(domains=["example.com"], ip_ranges=["10.0.0.0/8"]))
    monkeypatch.setattr(ScopeGuard, "_resolve", staticmethod(lambda host: "10.1.2.3"))
    assert guard.check_url("https://example.com/")


def test_ip_range_out_of_range_refused(make_auth, monkeypatch):
    guard = ScopeGuard(make_auth(domains=["example.com"], ip_ranges=["10.0.0.0/8"]))
    # Simulate DNS rebinding: host is in scope but resolves off-range.
    monkeypatch.setattr(ScopeGuard, "_resolve", staticmethod(lambda host: "192.168.1.5"))
    with pytest.raises(ScopeViolation):
        guard.check_url("https://example.com/")
