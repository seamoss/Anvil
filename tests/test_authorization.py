from __future__ import annotations

from datetime import datetime, timedelta, timezone


def test_signature_verifies(make_auth, signing_key):
    auth = make_auth(repos=["/repo/a"])
    assert auth.signature is not None
    assert auth.verify(signing_key) is True


def test_unsigned_record_does_not_verify(make_auth, signing_key):
    auth = make_auth(sign=False)
    assert auth.signature is None
    assert auth.verify(signing_key) is False


def test_wrong_key_does_not_verify(make_auth):
    auth = make_auth(repos=["/repo/a"])
    assert auth.verify("some-other-key") is False


def test_tampering_scope_breaks_signature(make_auth, signing_key):
    auth = make_auth(repos=["/repo/a"])
    # Widen the allowlist by hand after signing — must be detected.
    auth.scope.repos.append("/repo/evil")
    assert auth.verify(signing_key) is False


def test_expiry(make_auth):
    live = make_auth(expires_in_days=1)
    assert live.is_expired() is False
    expired = make_auth(expires_in_days=-1)
    assert expired.is_expired() is True


def test_signature_stable_across_reserialization(make_auth, signing_key):
    auth = make_auth(repos=["/repo/a"], domains=["x.example"])
    dumped = auth.model_dump(mode="json")
    from anvil.schemas.authorization import AuthorizationRecord

    reloaded = AuthorizationRecord(**dumped)
    assert reloaded.verify(signing_key) is True
