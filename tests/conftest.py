"""Shared fixtures.

The autouse `hermetic_env` fixture guarantees tests never read the developer's
real `.env.local` (which holds a live ANTHROPIC_API_KEY) and never make network
calls: it neutralizes env-file loading in the triage engine and unsets the key.
Tests that need an online engine inject a fake client explicitly.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from anvil.schemas.authorization import AuthorizationRecord, Scope

SIGNING_KEY = "test-signing-key-do-not-use-in-prod"


@pytest.fixture(autouse=True)
def hermetic_env(monkeypatch):
    # Don't let TriageEngine.__init__ pull the real key out of .env.local.
    monkeypatch.setattr("anvil.triage.engine.load_env", lambda *a, **k: None, raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("ANVIL_AUTH_SIGNING_KEY", SIGNING_KEY)


@pytest.fixture
def signing_key() -> str:
    return SIGNING_KEY


@pytest.fixture
def make_auth(signing_key):
    """Factory for a signed AuthorizationRecord."""

    def _make(
        engagement_id: str = "TEST",
        repos=None,
        domains=None,
        include_subdomains: bool = False,
        ip_ranges=None,
        expires_in_days: float = 7,
        sign: bool = True,
    ) -> AuthorizationRecord:
        rec = AuthorizationRecord(
            engagement_id=engagement_id,
            authorized_by="tester@example.com",
            reason="unit test",
            expires_at=datetime.now(timezone.utc) + timedelta(days=expires_in_days),
            scope=Scope(
                repos=repos or [],
                domains=domains or [],
                include_subdomains=include_subdomains,
                ip_ranges=ip_ranges or [],
            ),
        )
        return rec.sign(signing_key) if sign else rec

    return _make
