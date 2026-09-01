"""Built-in HTTP checks adapter — first-party, dependency-free DAST.

Runs the standard passive/safe web-hygiene checks that organizations self-report
for compliance. Every request is a plain GET (or OPTIONS-like header probe); the
adapter never sends a payload intended to exploit, modify state, or exfiltrate —
it inspects what the server voluntarily returns.

Checks:
  - Transport: cleartext HTTP; missing HSTS on HTTPS (A02).
  - Missing security response headers: CSP, X-Content-Type-Options,
    X-Frame-Options, Referrer-Policy (A05).
  - Cookie flags: missing Secure / HttpOnly / SameSite (A05).
  - Version disclosure: Server / X-Powered-By banners (A05).
  - CORS: wildcard-with-credentials or reflected arbitrary origin (A05).
  - Sensitive file exposure: a small curated list (.env, .git, etc.), with a
    soft-404 baseline to suppress false positives (A05/A01).

Every request URL is re-validated through the ScopeGuard (including each redirect
hop), so the scan can never wander off the authorized target.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from anvil.controller.scope_guard import ScopeGuard
from anvil.evidence.store import EvidenceStore
from anvil.pipelines.dast.base import DastAdapter
from anvil.schemas.finding import (
    Confidence,
    Finding,
    Location,
    Pipeline,
    Severity,
)

_UA = "Anvil-Scanner/0.1 (authorized security assessment)"

# Headers whose absence is a hygiene finding.
_SECURITY_HEADERS = {
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
}

# Small, curated list of files that should never be web-reachable.
_SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/server-status",
    "/actuator/env",
    "/config.json",
    "/wp-config.php.bak",
]

_CORS_PROBE_ORIGIN = "https://anvil-cors-probe.example"


@dataclass
class _Resp:
    url: str
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)  # lower-cased keys
    cookies: List[str] = field(default_factory=list)
    body: str = ""
    error: Optional[str] = None


class _ScopeCheckedRedirect(urllib.request.HTTPRedirectHandler):
    """Re-validates every redirect target against the scope before following."""

    def __init__(self, guard: ScopeGuard):
        self.guard = guard

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.guard.check_url(newurl)  # raises ScopeViolation if off-scope
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class HttpChecksAdapter(DastAdapter):
    binary = ""  # first-party, no external tool

    def __init__(self, timeout: int = 10, probe_paths: bool = True):
        self.timeout = timeout
        self.probe_paths = probe_paths

    @property
    def name(self) -> str:
        return "http-checks"

    def is_available(self) -> bool:
        return True  # always available — pure stdlib

    # --- network ------------------------------------------------------------
    def _get(self, url: str, guard: ScopeGuard, extra_headers: Optional[dict] = None) -> _Resp:
        guard.check_url(url)  # re-validate at request time
        opener = urllib.request.build_opener(_ScopeCheckedRedirect(guard))
        headers = {"User-Agent": _UA}
        headers.update(extra_headers or {})
        req = urllib.request.Request(url, headers=headers)
        ctx = ssl.create_default_context()
        try:
            raw = opener.open(req, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            raw = exc  # HTTPError is response-like (.status/.code, .headers)
        except (urllib.error.URLError, ssl.SSLError, TimeoutError, ValueError) as exc:
            return _Resp(url=url, error=str(exc))

        hdrs = {k.lower(): v for k, v in raw.headers.items()}
        cookies = raw.headers.get_all("Set-Cookie") or []
        status = getattr(raw, "status", None) or getattr(raw, "code", 0)
        try:
            body = raw.read(4096).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001 - body is best-effort only
            body = ""
        return _Resp(url=url, status=status, headers=hdrs, cookies=cookies, body=body)

    # --- orchestration ------------------------------------------------------
    def scan(
        self,
        engagement_id: str,
        target_url: str,
        guard: ScopeGuard,
        evidence: EvidenceStore,
    ) -> Tuple[str, List[Finding]]:
        main = self._get(target_url, guard)
        findings: List[Finding] = []
        record: dict = {"target": target_url, "status": main.status, "headers": main.headers}

        if main.error:
            ref = evidence.put(json.dumps({"target": target_url, "error": main.error}), label=f"http_{engagement_id}")
            return ref, [self._unreachable(engagement_id, target_url, main.error, ref)]

        ref = evidence.put(json.dumps(record, default=str), label=f"http_{engagement_id}")
        findings += self.analyze(engagement_id, target_url, main, ref)

        # CORS probe: send an arbitrary Origin and see how the server responds.
        cors = self._get(target_url, guard, extra_headers={"Origin": _CORS_PROBE_ORIGIN})
        if not cors.error:
            findings += self._check_cors(engagement_id, target_url, cors.headers, ref)

        if self.probe_paths:
            findings += self._probe_sensitive_paths(engagement_id, target_url, guard, ref)

        return ref, findings

    # --- pure analyzers (unit-tested without network) -----------------------
    def analyze(self, engagement_id: str, url: str, resp: _Resp, ref: str) -> List[Finding]:
        out: List[Finding] = []
        scheme = urlparse(url).scheme
        h = resp.headers

        # Transport
        if scheme == "http":
            out.append(self._mk(
                engagement_id, url, "cleartext-http", "cleartext",
                "Endpoint served over cleartext HTTP; traffic and any credentials can be intercepted.",
                "Serve exclusively over HTTPS and redirect HTTP to HTTPS.",
                Severity.HIGH, ["CWE-319"], "A02:2021-Cryptographic Failures", ref, Confidence.HIGH,
            ))
        elif "strict-transport-security" not in h:
            out.append(self._mk(
                engagement_id, url, "missing-hsts", "hsts",
                "HTTPS endpoint does not send a Strict-Transport-Security (HSTS) header.",
                "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                Severity.LOW, ["CWE-319"], "A05:2021-Security Misconfiguration", ref,
            ))

        # Missing security headers
        missing = [label for key, label in _SECURITY_HEADERS.items() if key not in h]
        if missing:
            out.append(self._mk(
                engagement_id, url, "missing-security-headers", "secheaders",
                "Missing recommended security headers: " + ", ".join(missing) + ".",
                "Add the missing headers (e.g. a restrictive Content-Security-Policy, "
                "X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Referrer-Policy).",
                Severity.LOW, ["CWE-693"], "A05:2021-Security Misconfiguration", ref,
            ))

        # Version / tech disclosure
        disclosed = [
            f"{name}: {h[name]}"
            for name in ("server", "x-powered-by", "x-aspnet-version")
            if name in h and any(c.isdigit() for c in h[name])
        ]
        if disclosed:
            out.append(self._mk(
                engagement_id, url, "version-disclosure", "banner",
                "Server discloses software/version details: " + "; ".join(disclosed) + ".",
                "Suppress or genericize Server / X-Powered-By banners.",
                Severity.INFO, ["CWE-200"], "A05:2021-Security Misconfiguration", ref, Confidence.HIGH,
            ))

        # Cookie flags
        for cookie in resp.cookies:
            name = cookie.split("=", 1)[0].strip()
            low = cookie.lower()
            issues = []
            if scheme == "https" and "secure" not in low:
                issues.append("Secure")
            if "httponly" not in low:
                issues.append("HttpOnly")
            if "samesite" not in low:
                issues.append("SameSite")
            if issues:
                out.append(self._mk(
                    engagement_id, url, "insecure-cookie", f"cookie:{name}",
                    f"Cookie '{name}' is missing flags: {', '.join(issues)}.",
                    f"Set the {', '.join(issues)} attribute(s) on the '{name}' cookie.",
                    Severity.MEDIUM, ["CWE-614", "CWE-1004"],
                    "A05:2021-Security Misconfiguration", ref,
                ))
        return out

    def _check_cors(self, engagement_id: str, url: str, headers: Dict[str, str], ref: str) -> List[Finding]:
        aco = headers.get("access-control-allow-origin")
        creds = headers.get("access-control-allow-credentials", "").lower() == "true"
        if not aco:
            return []
        if aco == _CORS_PROBE_ORIGIN:
            sev = Severity.HIGH if creds else Severity.MEDIUM
            desc = ("Server reflects an arbitrary Origin in Access-Control-Allow-Origin"
                    + (" together with Allow-Credentials: true, exposing authenticated data to any site." if creds
                       else ", allowing any site to read responses."))
        elif aco == "*" and creds:
            sev, desc = Severity.HIGH, ("Access-Control-Allow-Origin: * combined with Allow-Credentials: true "
                                        "is an insecure CORS configuration.")
        elif aco == "*":
            sev, desc = Severity.LOW, "Access-Control-Allow-Origin: * exposes responses to any origin (no credentials)."
        else:
            return []
        return [self._mk(
            engagement_id, url, "permissive-cors", "cors", desc,
            "Restrict Access-Control-Allow-Origin to an explicit allowlist and avoid reflecting arbitrary origins.",
            sev, ["CWE-942"], "A05:2021-Security Misconfiguration", ref,
        )]

    def _probe_sensitive_paths(self, engagement_id: str, target_url: str, guard: ScopeGuard, ref: str) -> List[Finding]:
        p = urlparse(target_url)
        base = f"{p.scheme}://{p.netloc}"
        # Soft-404 baseline: a random path that should NOT exist.
        baseline = self._get(urljoin(base, f"/anvil-nonexistent-{uuid.uuid4().hex[:12]}"), guard)
        baseline_status = baseline.status if not baseline.error else None

        out: List[Finding] = []
        for path in _SENSITIVE_PATHS:
            resp = self._get(urljoin(base, path), guard)
            if resp.error:
                continue
            # Exposed only if it returns 200 AND the server distinguishes it from
            # a random missing path (suppresses soft-404s that 200 everything).
            if resp.status == 200 and baseline_status != 200:
                out.append(self._mk(
                    engagement_id, urljoin(base, path), "sensitive-file-exposure", f"path:{path}",
                    f"Sensitive path '{path}' is web-reachable (HTTP 200).",
                    f"Remove '{path}' from the web root or block access to it.",
                    Severity.HIGH, ["CWE-200", "CWE-538"],
                    "A05:2021-Security Misconfiguration", ref, Confidence.MEDIUM,
                ))
        return out

    # --- helper -------------------------------------------------------------
    def _mk(self, engagement_id, url, rule_id, disc, description, remediation,
            severity, cwe, owasp, ref, confidence=Confidence.MEDIUM) -> Finding:
        location = Location(url=url, http_method="GET")
        return Finding(
            finding_id=Finding.make_id(engagement_id, self.name, rule_id, f"{url}#{disc}"),
            engagement_id=engagement_id,
            pipeline=Pipeline.DAST,
            source_tool=self.name,
            rule_id=rule_id,
            title=description.split(".")[0][:120],
            description=description,
            remediation=remediation,
            severity=severity,
            confidence=confidence,
            cwe=cwe,
            owasp_category=owasp,
            location=location,
            evidence_ref=ref,
        )

    def _unreachable(self, engagement_id, url, error, ref) -> Finding:
        return self._mk(
            engagement_id, url, "endpoint-unreachable", "conn",
            f"Endpoint could not be reached: {error}",
            "Verify the target is running and reachable from the scanner.",
            Severity.INFO, [], None, ref, Confidence.HIGH,
        )
