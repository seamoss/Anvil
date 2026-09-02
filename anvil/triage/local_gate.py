"""Local-only classification gate.

Some findings pertain only to a local/development environment — local config
files, dev-only secrets, loopback URLs — not to shipped/production surfaces.
They are still worth reporting at full severity, but should NOT be pushed into
workflow integrations (tickets, alerts, PR comments), so developer-environment
noise doesn't page production owners.

This is a deterministic, path/URL-based classifier: predictable and auditable.
The pattern list is intentionally conservative — a bare `.env` (which may hold
production secrets) is NOT treated as local; only clear local indicators are.
"""

from __future__ import annotations

import re

from anvil.schemas.finding import Finding

# Each pattern marks a local/dev-only artifact. Case-insensitive.
_LOCAL_PATTERNS = [
    r"(^|/)[^/]*\.local(\.[^/]*)?$",              # .env.local, config.local, settings.local.js
    r"(^|/)local[^/]*\.log$",                     # local.log, local-debug.log
    r"(^|/)\.env\.(local|development|dev|test)$",  # .env.development, .env.test
    r"(^|/)local_settings\.py$",                  # Django local_settings.py
    r"(^|/)docker-compose\.override\.ya?ml$",     # local compose override
    r"\blocalhost\b",                              # loopback host in a URL
    r"//(127\.0\.0\.1|\[::1\])",                  # loopback IP in a URL
]
_LOCAL_RE = re.compile("|".join(_LOCAL_PATTERNS), re.IGNORECASE)


def is_local_only(finding: Finding) -> bool:
    """True if the finding's location looks like a local/dev-only artifact."""
    for candidate in (finding.location.file_path, finding.location.url):
        if candidate and _LOCAL_RE.search(candidate):
            return True
    return False


def classify(findings) -> None:
    """Set `local_only` on each finding in place (never clears an existing flag)."""
    for f in findings:
        if not f.local_only:
            f.local_only = is_local_only(f)
