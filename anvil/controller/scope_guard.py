"""The scope guard — a hard gate, not a check.

Every target (repo path, or a live URL about to be requested) must pass through
here. Off-scope targets raise `ScopeViolation`, which the engagement records to
the audit log and refuses to proceed on. The URL path additionally re-resolves
the host to an IP at request time to defend against scope creep via redirects
or DNS rebinding.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

from anvil.schemas.authorization import AuthorizationRecord


class ScopeViolation(Exception):
    """Raised when a target is not covered by the authorization record."""


class ScopeGuard:
    def __init__(self, auth: AuthorizationRecord, signing_key: Optional[str] = None):
        self.auth = auth
        signing_key = signing_key or os.environ.get("ANVIL_AUTH_SIGNING_KEY", "")

        if not signing_key:
            raise ScopeViolation(
                "No signing key available (set ANVIL_AUTH_SIGNING_KEY); refusing to "
                "trust an unverifiable authorization record."
            )
        if not auth.verify(signing_key):
            raise ScopeViolation(
                "Authorization record signature is invalid — the scope may have been "
                "tampered with. Refusing to run."
            )
        if auth.is_expired():
            raise ScopeViolation(
                f"Authorization for engagement '{auth.engagement_id}' expired at "
                f"{auth.expires_at.isoformat()}."
            )

    # --- SAST target check -------------------------------------------------
    def check_repo(self, target: str) -> str:
        """Return the target if authorized, else raise. Accepts a local path or
        a git URL; both must appear verbatim in the authorized repo list."""
        allowed = set(self.auth.scope.repos)

        if target in allowed:
            return target

        # Also accept a local path that resolves to an authorized path (handles
        # ./ vs absolute), without expanding scope beyond what was listed.
        try:
            resolved = str(Path(target).resolve())
            for repo in self.auth.scope.repos:
                if resolved == str(Path(repo).resolve()):
                    return target
        except (OSError, RuntimeError):
            pass

        raise ScopeViolation(
            f"Repo target '{target}' is not in the authorized scope for engagement "
            f"'{self.auth.engagement_id}'."
        )

    # --- DAST target check -------------------------------------------------
    def check_url(self, url: str) -> str:
        """Validate a URL's host against the domain allowlist AND (if an IP
        allowlist is configured) its live-resolved IP. Call this immediately
        before each request, not just once up front."""
        host = urlparse(url).hostname
        if not host:
            raise ScopeViolation(f"Could not parse a hostname from URL '{url}'.")

        if not self._host_allowed(host):
            raise ScopeViolation(
                f"Host '{host}' is not in the authorized domain scope for engagement "
                f"'{self.auth.engagement_id}'."
            )

        if self.auth.scope.ip_ranges:
            resolved_ip = self._resolve(host)
            if not self._ip_allowed(resolved_ip):
                raise ScopeViolation(
                    f"Host '{host}' resolved to {resolved_ip}, which is outside the "
                    f"authorized IP ranges (possible DNS rebinding / redirect)."
                )
        return url

    def _host_allowed(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        for domain in self.auth.scope.domains:
            domain = domain.lower().rstrip(".")
            if host == domain:
                return True
            if self.auth.scope.include_subdomains and host.endswith("." + domain):
                return True
        return False

    @staticmethod
    def _resolve(host: str) -> str:
        try:
            return socket.gethostbyname(host)
        except socket.gaierror as exc:  # pragma: no cover - network dependent
            raise ScopeViolation(f"Could not resolve host '{host}': {exc}") from exc

    def _ip_allowed(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        for cidr in self.auth.scope.ip_ranges:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        return False

    def scope_summary(self) -> List[str]:
        s = self.auth.scope
        lines = []
        if s.repos:
            lines.append(f"repos: {', '.join(s.repos)}")
        if s.domains:
            sub = " (+subdomains)" if s.include_subdomains else ""
            lines.append(f"domains: {', '.join(s.domains)}{sub}")
        if s.ip_ranges:
            lines.append(f"ip_ranges: {', '.join(s.ip_ranges)}")
        return lines
