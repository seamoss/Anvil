"""Triage layer — where the LLM earns its place.

Scanners produce breadth and false positives; this layer applies judgment:
  1. dedupe/correlate findings that are the same root issue,
  2. filter false positives,
  3. assign/normalize CVSS (3.1), CWE, and OWASP Top-10 mappings,
  4. (optional) a business-logic pass that reads source and reports authz/logic
     vulns the pattern scanners structurally cannot see — the "hybrid" value-add.

Detection stays in the scanners; the LLM only reasons over their output (and,
for the logic pass, over code you explicitly hand it). If no ANTHROPIC_API_KEY
is present, triage degrades to a deterministic heuristic so the pipeline still
runs end-to-end offline.
"""

from __future__ import annotations

import json
import os
from typing import Dict, List, Optional

from anvil.envfile import load_env
from anvil.schemas.finding import (
    Confidence,
    Finding,
    FindingStatus,
    Location,
    Pipeline,
    Severity,
)

MODEL = "claude-opus-5"

# The triage rubric. It is identical on every triage call, so it forms a stable
# cacheable prefix (see cache_control in _llm_triage). Keep volatile per-request
# content (the findings themselves) OUT of here — it goes in the user message.
_SYSTEM = """You are a senior application security engineer triaging automated \
scanner findings for a compliance report. Your output feeds an OWASP Top 10 \
(2021), SOC 2, and CWE/CVSS assessment. You are precise and conservative: you \
never invent vulnerabilities, and you mark a finding false_positive only when \
the evidence clearly shows it is not exploitable in its context.

## For each finding, decide

- status: "confirmed" | "false_positive"
- severity: critical | high | medium | low | info
- confidence: high | medium | low
- cwe: list of CWE ids, e.g. ["CWE-89"]
- owasp_category: the OWASP Top 10 2021 category (see list below)
- cvss_vector: a CVSS 3.1 base vector string
- cvss_score: the base score matching that vector (0.0-10.0)
- remediation: one concrete, actionable sentence
- triage_note: one sentence justifying the status decision
- duplicate_of: the finding_id this merges into if it is the same root cause as
  another finding, else null

## Severity guidance

- critical: unauthenticated remote code execution, auth bypass, or mass data
  exposure directly reachable in the scanned surface.
- high: injection (SQLi/command), stored XSS, SSRF, insecure deserialization,
  hardcoded production credentials.
- medium: reflected XSS, CSRF on state-changing actions, weak crypto, missing
  authorization checks with limited blast radius.
- low: missing security headers, verbose errors, outdated-but-unreachable deps.
- info: hardening suggestions with no direct exploit path.
Weight exploitability in context over the scanner's default rating; downgrade
findings that are not reachable or are already mitigated.

## CVSS 3.1

Produce a full base vector (AV/AC/PR/UI/S/C/I/A) and the matching base score.
Prefer the CWE already attached to the finding unless it is clearly wrong.

## OWASP Top 10 (2021) categories

A01:2021-Broken Access Control; A02:2021-Cryptographic Failures;
A03:2021-Injection; A04:2021-Insecure Design; A05:2021-Security
Misconfiguration; A06:2021-Vulnerable and Outdated Components;
A07:2021-Identification and Authentication Failures; A08:2021-Software and
Data Integrity Failures; A09:2021-Security Logging and Monitoring Failures;
A10:2021-Server-Side Request Forgery.

## False-positive criteria

Mark false_positive when: the sink is not reachable from untrusted input; the
"secret" is a test/example placeholder; the pattern is in test/fixture/vendored
code; or the input is provably validated/parameterized before the sink. When
unsure, keep it confirmed at lower confidence rather than dropping it.

## Deduplication

Group findings that share a single root cause (same vuln class at the same
sink, or the same dependency CVE across files). Keep one as canonical and point
the rest at it via duplicate_of.

## Output

Return ONLY a JSON object, no prose, no markdown fences:
{"decisions": [{"finding_id": "...", "status": "...", "severity": "...", \
"confidence": "...", "cwe": [...], "owasp_category": "...", "cvss_vector": "...", \
"cvss_score": 0.0, "remediation": "...", "triage_note": "...", "duplicate_of": null}]}"""

# One cache marker reused everywhere. Default TTL is ~5 min; bump to
# {"type": "ephemeral", "ttl": "1h"} for the rubric if engagements batch over a
# longer window (a 1h write costs more but survives longer between scans).
_EPHEMERAL = {"type": "ephemeral"}

# Stable instruction for the business-logic pass — kept separate from the (large,
# per-repo) source bundle so both can sit in a cached prefix and be reused across
# repeated or multi-angle passes over the same repo.
_LOGIC_SYSTEM = """You are a senior application security engineer. Review the \
provided source for BUSINESS-LOGIC and AUTHORIZATION vulnerabilities that \
pattern-based scanners miss: missing or inconsistent access checks, IDOR / \
insecure direct object references, broken authentication or session flows, \
unsafe state transitions, race conditions on security-relevant actions, and \
trust-boundary violations. Only report issues you can point to in the provided \
code — cite the file and line. Do not report generic pattern issues a linter \
would already catch. When unsure, prefer a lower-confidence finding over silence.

Return ONLY JSON, no prose or markdown fences:
{"findings": [{"title": "...", "description": "...", "file_path": "...", \
"start_line": 0, "severity": "critical|high|medium|low|info", \
"cwe": ["CWE-639"], "owasp_category": "A01:2021-Broken Access Control", \
"remediation": "..."}]}"""


class TriageEngine:
    def __init__(self, model: str = MODEL, api_key: Optional[str] = None):
        load_env()  # ensure .env(.local) is applied for library callers too
        self.model = model
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._client = None
        # Cumulative token usage across this engine's calls, for the audit trail.
        self.usage = {
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_creation_input_tokens": 0,
            "cache_read_input_tokens": 0,
        }
        if self._api_key:
            import anthropic  # imported lazily so offline mode needs no SDK

            self._client = anthropic.Anthropic(api_key=self._api_key)

    @property
    def online(self) -> bool:
        return self._client is not None

    def _record_usage(self, response) -> None:
        u = response.usage
        for key in self.usage:
            self.usage[key] += getattr(u, key, 0) or 0

    # --- main triage pass --------------------------------------------------
    def triage(self, findings: List[Finding]) -> List[Finding]:
        if not findings:
            return findings
        if not self.online:
            return [self._heuristic(f) for f in findings]
        return self._llm_triage(findings)

    def _llm_triage(self, findings: List[Finding]) -> List[Finding]:
        payload = [
            {
                "finding_id": f.finding_id,
                "source_tool": f.source_tool,
                "rule_id": f.rule_id,
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value,
                "cwe": f.cwe,
                "location": f.location.as_ref(),
                "snippet": f.location.snippet,
            }
            for f in findings
        ]

        response = self._client.messages.create(
            model=self.model,
            max_tokens=16000,
            thinking={"type": "adaptive"},
            output_config={"effort": "high"},
            # The rubric is a stable prefix — cache it so repeated triage calls
            # (across chunks, and across engagements within the cache TTL) only
            # pay for it once. Volatile content (the findings) stays in messages,
            # after the cached prefix, so it never invalidates the cache.
            system=[{"type": "text", "text": _SYSTEM, "cache_control": _EPHEMERAL}],
            messages=[{"role": "user", "content": json.dumps({"findings": payload})}],
        )
        self._record_usage(response)
        if response.stop_reason == "refusal":  # be explicit for the audit trail
            raise RuntimeError(
                f"Triage refused: {getattr(response.stop_details, 'explanation', '')}"
            )
        text = next((b.text for b in response.content if b.type == "text"), "")
        decisions = self._parse_decisions(text)

        by_id: Dict[str, Finding] = {f.finding_id: f for f in findings}
        for d in decisions:
            f = by_id.get(d.get("finding_id"))
            if not f:
                continue
            self._apply_decision(f, d)
        return list(by_id.values())

    @staticmethod
    def _parse_decisions(text: str) -> List[dict]:
        text = text.strip()
        # Tolerate accidental markdown fences around the JSON.
        if text.startswith("```"):
            text = text.split("```", 2)[1].lstrip("json").strip()
        return json.loads(text).get("decisions", [])

    @staticmethod
    def _apply_decision(f: Finding, d: dict) -> None:
        status = d.get("status")
        if status == "false_positive":
            f.status = FindingStatus.FALSE_POSITIVE
        elif d.get("duplicate_of") and d["duplicate_of"] != f.finding_id:
            f.status = FindingStatus.DUPLICATE
            f.duplicate_of = d["duplicate_of"]
        else:
            f.status = FindingStatus.CONFIRMED

        if d.get("severity"):
            f.severity = Severity(d["severity"])
        if d.get("confidence"):
            f.confidence = Confidence(d["confidence"])
        if d.get("cwe"):
            f.cwe = d["cwe"]
        f.owasp_category = d.get("owasp_category") or f.owasp_category
        f.cvss_vector = d.get("cvss_vector") or f.cvss_vector
        f.cvss_score = d.get("cvss_score") if d.get("cvss_score") is not None else f.cvss_score
        f.remediation = d.get("remediation") or f.remediation
        f.triage_note = d.get("triage_note")

    # --- offline heuristic -------------------------------------------------
    @staticmethod
    def _heuristic(f: Finding) -> Finding:
        f.status = FindingStatus.TRIAGED
        f.triage_note = "Offline heuristic triage (no ANTHROPIC_API_KEY set)."
        if not f.owasp_category and f.cwe:
            f.owasp_category = _CWE_TO_OWASP.get(f.cwe[0])
        return f

    # --- optional business-logic pass (the hybrid layer) -------------------
    def logic_review(
        self, engagement_id: str, files: Dict[str, str], evidence_ref: str
    ) -> List[Finding]:
        """Given {path: source_text}, ask Claude for authz/business-logic vulns
        the pattern scanners miss. Emits Findings with source_tool 'llm-logic'.
        Returns [] offline."""
        if not self.online or not files:
            return []

        bundle = "\n\n".join(
            f"=== {path} ===\n{text[:8000]}" for path, text in files.items()
        )
        response = self._client.messages.create(
            model=self.model,
            max_tokens=16000,
            thinking={"type": "adaptive"},
            output_config={"effort": "high"},
            # Two cached prefixes: the rubric (system) and the source bundle. The
            # bundle is the big per-repo payload — caching it means repeated or
            # multi-angle passes over the same checkout reuse it at ~0.1x cost.
            # Only the trailing ask is volatile, so it never breaks the cache.
            system=[{"type": "text", "text": _LOGIC_SYSTEM, "cache_control": _EPHEMERAL}],
            messages=[
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": bundle, "cache_control": _EPHEMERAL},
                        {"type": "text", "text": "Review the source above and return the JSON findings object."},
                    ],
                }
            ],
        )
        self._record_usage(response)
        if response.stop_reason == "refusal":
            return []
        text = next((b.text for b in response.content if b.type == "text"), "")
        try:
            items = self._parse_decisions_generic(text)
        except (json.JSONDecodeError, KeyError):
            return []

        out: List[Finding] = []
        for it in items:
            loc = Location(file_path=it.get("file_path"), start_line=it.get("start_line"))
            out.append(
                Finding(
                    finding_id=Finding.make_id(
                        engagement_id, "llm-logic", it.get("title", ""), loc.as_ref()
                    ),
                    engagement_id=engagement_id,
                    pipeline=Pipeline.SAST,
                    source_tool="llm-logic",
                    rule_id=None,
                    title=it.get("title", "Business-logic issue"),
                    description=it.get("description", ""),
                    remediation=it.get("remediation", ""),
                    severity=Severity(it.get("severity", "medium")),
                    confidence=Confidence.LOW,  # LLM-sourced → verify before reporting
                    cwe=it.get("cwe", []),
                    owasp_category=it.get("owasp_category"),
                    location=loc,
                    evidence_ref=evidence_ref,
                    status=FindingStatus.NEW,
                )
            )
        return out

    @staticmethod
    def _parse_decisions_generic(text: str) -> List[dict]:
        text = text.strip()
        if text.startswith("```"):
            text = text.split("```", 2)[1].lstrip("json").strip()
        return json.loads(text).get("findings", [])


# Minimal CWE→OWASP map for the offline heuristic. The online path lets Claude
# assign these properly; this just keeps offline reports non-empty.
_CWE_TO_OWASP = {
    "CWE-89": "A03:2021-Injection",
    "CWE-79": "A03:2021-Injection",
    "CWE-78": "A03:2021-Injection",
    "CWE-22": "A01:2021-Broken Access Control",
    "CWE-639": "A01:2021-Broken Access Control",
    "CWE-798": "A07:2021-Identification and Authentication Failures",
    "CWE-327": "A02:2021-Cryptographic Failures",
    "CWE-502": "A08:2021-Software and Data Integrity Failures",
}
