"""Authorization records — the legal/compliance backbone.

An engagement may only touch targets listed in a signed AuthorizationRecord.
The record is signed with an HMAC over its canonical form so a tampered scope
(e.g. someone widening the allowlist by hand) is detectable at load time.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, Field


class Scope(BaseModel):
    """The explicit allowlist. Anything not listed here is out of scope."""

    # SAST targets: local repo paths or git URLs that may be cloned & scanned.
    repos: List[str] = Field(default_factory=list)

    # DAST targets: hostnames/domains that may be probed. Subdomains of a listed
    # domain are in scope only if `include_subdomains` is true.
    domains: List[str] = Field(default_factory=list)
    include_subdomains: bool = False

    # Optional IP allowlist (CIDR strings). If non-empty, a resolved target IP
    # must fall inside one of these ranges — the anti-DNS-rebinding backstop.
    ip_ranges: List[str] = Field(default_factory=list)


class AuthorizationRecord(BaseModel):
    engagement_id: str
    authorized_by: str = Field(..., description="Email of the person who signed off.")
    reason: str = Field("", description="Ticket / compliance justification.")
    scope: Scope

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = Field(..., description="Hard expiry; scans refuse after this.")

    signature: Optional[str] = Field(
        None, description="HMAC-SHA256 over the canonical record. Set by sign()."
    )

    def _canonical_bytes(self) -> bytes:
        """Stable serialization excluding the signature itself."""
        payload = self.model_dump(mode="json", exclude={"signature"})
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def sign(self, signing_key: str) -> "AuthorizationRecord":
        self.signature = hmac.new(
            signing_key.encode(), self._canonical_bytes(), hashlib.sha256
        ).hexdigest()
        return self

    def verify(self, signing_key: str) -> bool:
        if not self.signature:
            return False
        expected = hmac.new(
            signing_key.encode(), self._canonical_bytes(), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, self.signature)

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return now >= self.expires_at
