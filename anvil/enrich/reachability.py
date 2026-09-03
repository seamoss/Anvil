"""Tier-2 reachability — LLM judgment for pattern findings without a proven flow.

CodeQL/semgrep taint findings already carry a proven source→sink path (tier 0).
Pattern findings (semgrep-pattern, bandit) don't — they sit at `unknown`, which
the risk scorer penalizes. This layer gives Claude each such finding plus a
window of surrounding source and asks the one question that decides its real
priority: can untrusted input actually reach this sink?

It's scoped tightly (reportable, non-suppressed, non-local-only, first-party
pattern findings at MEDIUM+), reuses the cached-rubric + chunking pattern, and
degrades to a no-op offline or on any parse failure — findings simply stay
`unknown`, never worse.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List, Optional

from anvil.envfile import load_env
from anvil.schemas.finding import Finding, FindingStatus, Reachability, Severity

MODEL = "claude-opus-5"
_CHUNK = 8  # findings per request (each carries a code window)
_ELIGIBLE_TOOLS = {"semgrep", "bandit"}
_MIN_SEV = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}
_REPORTABLE = {FindingStatus.CONFIRMED, FindingStatus.TRIAGED}
_EPHEMERAL = {"type": "ephemeral"}

_SYSTEM = """You are a senior application security engineer assessing the \
REACHABILITY of a static-analysis finding: can untrusted or external input \
actually reach the flagged code?

You receive each finding's metadata and a window of surrounding source. Decide:
- reachability: "reachable" if there is a plausible path from an external entry \
point (an HTTP route/handler, CLI argument, queue/message consumer, file upload, \
webhook, or deserialization of external data) to this code; "unreachable" if it \
is dead code, test/fixture-only, a hardcoded internal constant, a build/dev \
script, or otherwise not exposed to external input; "unknown" if the provided \
context is insufficient to tell.
- entry_point: a short description of the entry point if reachable (e.g. \
"POST /api/loans handler"), else null.
- rationale: one sentence grounded in the provided code.

Be conservative — prefer "unknown" over guessing, and judge only from the code \
shown, not assumptions about the wider system.

Return ONLY JSON, no prose or fences:
{"decisions":[{"finding_id":"...","reachability":"reachable|unreachable|unknown",\
"entry_point":"... or null","rationale":"..."}]}"""


def _batches(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


class ReachabilityAnalyzer:
    def __init__(self, model: str = MODEL, api_key: Optional[str] = None):
        load_env()
        self.model = model
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._client = None
        self.usage = {
            "input_tokens": 0, "output_tokens": 0,
            "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
        }
        if self._api_key:
            import anthropic

            self._client = anthropic.Anthropic(api_key=self._api_key)

    @property
    def online(self) -> bool:
        return self._client is not None

    def analyze(self, findings: List[Finding], repo_path: str) -> List[Finding]:
        if not self.online:
            return findings
        candidates = [f for f in findings if self._eligible(f)]
        if not candidates:
            return findings
        by_id = {f.finding_id: f for f in candidates}
        for chunk in _batches(candidates, _CHUNK):
            try:
                decisions = self._analyze_chunk(chunk, repo_path)
            except (json.JSONDecodeError, KeyError, ValueError, RuntimeError):
                continue  # leave these 'unknown' — never worse than before
            for d in decisions:
                f = by_id.get(d.get("finding_id"))
                if f:
                    self._apply(f, d)
        return findings

    @staticmethod
    def _eligible(f: Finding) -> bool:
        return (
            f.status in _REPORTABLE
            and f.source_tool in _ELIGIBLE_TOOLS
            and f.reachability is Reachability.UNKNOWN
            and not f.local_only
            and not f.suppressed
            and f.severity in _MIN_SEV
        )

    def _analyze_chunk(self, chunk: List[Finding], repo_path: str) -> List[dict]:
        payload = [
            {
                "finding_id": f.finding_id,
                "tool": f.source_tool,
                "rule_id": f.rule_id,
                "title": f.title,
                "description": (f.description or "")[:300],
                "location": f.location.as_ref(),
                "code": self._code_window(repo_path, f.location.file_path, f.location.start_line),
            }
            for f in chunk
        ]
        response = self._client.messages.create(
            model=self.model,
            max_tokens=8000,
            thinking={"type": "adaptive"},
            output_config={"effort": "high"},
            system=[{"type": "text", "text": _SYSTEM, "cache_control": _EPHEMERAL}],
            messages=[{"role": "user", "content": json.dumps({"findings": payload})}],
        )
        self._record_usage(response)
        if response.stop_reason == "refusal":
            raise RuntimeError("reachability analysis refused")
        text = next((b.text for b in response.content if b.type == "text"), "")
        return self._parse(text)

    @staticmethod
    def _parse(text: str) -> List[dict]:
        text = text.strip()
        if text.startswith("```"):
            text = text.split("```", 2)[1].lstrip("json").strip()
        return json.loads(text).get("decisions", [])

    @staticmethod
    def _apply(f: Finding, d: dict) -> None:
        r = d.get("reachability")
        if r in ("reachable", "unreachable", "unknown"):
            f.reachability = Reachability(r)
            f.reachability_source = "llm"
            f.entry_point = d.get("entry_point") or None

    def _record_usage(self, response) -> None:
        u = response.usage
        for key in self.usage:
            self.usage[key] += getattr(u, key, 0) or 0

    @staticmethod
    def _code_window(repo_path: str, file_path: Optional[str], line: Optional[int], radius: int = 30) -> str:
        if not file_path:
            return ""
        p = Path(file_path)
        if not p.is_absolute() and repo_path:
            p = Path(repo_path) / file_path
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return ""
        line = line or 1
        lo = max(0, line - radius - 1)
        hi = min(len(lines), line + radius)
        return "\n".join(f"{i + 1}: {lines[i]}" for i in range(lo, hi))
