# Anvil

An **authorization-gated** pentesting agent for internal security & compliance
reporting. Anvil scans two kinds of target:

- **SAST (repo mode)** — point it at a source checkout; it runs static analyzers
  and reports code vulnerabilities.
- **DAST (live URL mode)** — point it at a running application; it runs
  **non-destructive** active checks (no exploitation, no data modification).

A hybrid **LLM triage layer** (Claude) sits over the scanners: it dedupes,
filters false positives, assigns CVSS/CWE/OWASP mappings, and (optionally)
reasons about business-logic/authz vulns the pattern scanners miss. Detection
stays in proven scanners so results are defensible in an audit.

> **Anvil only touches targets in a signed authorization record.** No valid,
> unexpired, in-scope authorization → no scan. This is a hard gate.

## Architecture

```
authorization (signed) → scope guard → SAST | DAST pipeline
   → evidence store (raw output) → LLM triage → compliance report
   ... every step recorded to a hash-chained audit log.
```

| Layer | Module | Role |
|---|---|---|
| Schemas | `anvil/schemas/` | `Finding` (the normalized spine) + `AuthorizationRecord` |
| Controller | `anvil/controller/` | scope guard, hash-chained audit log, engagement orchestrator |
| Evidence | `anvil/evidence/` | content-addressed raw scanner output |
| SAST | `anvil/pipelines/sast/` | Semgrep + Bandit + CodeQL (code), gitleaks (secrets), Trivy + OSV-Scanner (dependency CVEs, dual-source) + Trivy licenses |
| DAST | `anvil/pipelines/dast/` | http-checks (built-in: headers/cookies/CORS/methods/exposure/clickjacking), testssl (TLS/cert), nuclei (safe posture) |
| Triage | `anvil/triage/` | Claude triage (prompt-cached, chunked) + SCA fast-path + local-only gate + offline heuristic fallback |
| Enrich | `anvil/enrich/` | reachability (CodeQL/semgrep flows + LLM tier-2 for pattern findings) + contextual risk scoring → P1-P4 |
| State | `anvil/state/` | SQLite store: cross-run diffing (new/resolved), suppressions, history |
| Reporting | `anvil/reporting/` | OWASP Top 10 / SOC 2 / CWE + CVSS reports — Markdown, SARIF, HTML/PDF |

## Install

Uses [uv](https://docs.astral.sh/uv/). `uv sync` reads the pinned Python
(`.python-version`), creates `.venv`, and installs from `uv.lock`.

```bash
uv sync                             # env + deps (incl. the dev group)

# Scanners (install what you need — SAST runs every one that's present):
uv pip install semgrep bandit          # SAST: code patterns (bandit = Python)
brew install codeql gitleaks trivy osv-scanner  # SAST: dataflow + secrets + deps (dual-source)
brew install testssl nuclei         # DAST: TLS/cert + templates (http-checks is built-in, no install)

cp .env.example .env                # then fill in ANVIL_AUTH_SIGNING_KEY (+ ANTHROPIC_API_KEY)
```

Run commands with `uv run` (no manual venv activation needed), e.g. `uv run anvil ...`.

## Usage

```bash
export ANVIL_AUTH_SIGNING_KEY=<long-random-value>
export ANTHROPIC_API_KEY=<key>      # optional; without it triage runs an offline heuristic

# 1. Authorize an engagement (produces a signed YAML)
uv run anvil init-auth --engagement ACME-2026-Q3 --by you@org.com \
  --reason "SEC-1234" --days 14 \
  --repo /path/to/checkout --domain staging.acme.example --include-subdomains \
  --out config/authorizations/acme.yaml

# 2. SAST — scan a repo (choose any mix of output formats)
#    --logic: LLM business-logic pass · --reachability: LLM reachability for pattern findings
uv run anvil scan-repo --auth config/authorizations/acme.yaml --repo /path/to/checkout --logic --reachability --report --sarif --html

# 3. DAST — scan a live URL (safe posture)
uv run anvil scan-url --auth config/authorizations/acme.yaml --url https://staging.acme.example --report --sarif

# 4. Verify a run's audit trail
uv run anvil verify-audit --engagement ACME-2026-Q3

# 5. Track state across runs
uv run anvil history --engagement ACME-2026-Q3        # scan history
uv run anvil suppress --rule-id <id> --reason "..."   # accept-risk / mark FP
uv run anvil suppress --finding-id <id> --reason "..."
uv run anvil suppressions                             # list active suppressions
```

Anvil keeps state across runs in `runs/anvil.db` (SQLite, gitignored). Each
scan records a run and diffs against the engagement's previous one — reports and
the CLI show **N new / N resolved since last scan**, and new findings are tagged
🆕. Suppressed findings (accepted-risk / confirmed-FP) stay in the report tagged
`suppressed` but are excluded from workflow integrations.

Findings in local/dev-only artifacts (`.env.local`, `local.log`, loopback URLs,
`docker-compose.override.yml`, …) are tagged **local-only**: reported with full
severity, but flagged so workflow integrations (tickets, alerts, PR comments)
can exclude them — dev-environment noise shouldn't page production owners.

Each run writes to `runs/<engagement_id>/`: `audit.jsonl`, `evidence/`,
`findings.json` (always), plus whichever reports you requested — `report.md`
(`--report`), `results.sarif` (`--sarif`, for GitHub code scanning / CI),
`report.html` (`--html`, print-ready → Save as PDF), and `report.pdf` (`--pdf`,
requires WeasyPrint).

## Roadmap (next scanners are just new adapters)

The `Finding` schema is the spine — adding coverage is one adapter each.

Done: Semgrep + Bandit + CodeQL (code), gitleaks (secrets), Trivy (SCA) for
SAST; http-checks (first-party) + testssl (TLS) + nuclei for DAST; SARIF +
HTML/PDF reports; SCA fast-path (`--deep-deps` to include); local-only gate;
persistent state with cross-run diffing + suppressions; contextual risk scoring
(reachability harvested from CodeQL/semgrep flows × asset criticality × exposure
→ P1-P4).
Dependency findings render in their own lane (dual-source CVEs deduped across
Trivy + OSV, plus license concerns), separate from the risk-ranked first-party
findings.
Reachability is three-tier: harvested from CodeQL/semgrep flows (free), plus an
opt-in LLM pass (`--reachability`) that judges pattern findings and names the
entry point — feeding the P1-P4 score.
Next: entry-point mapping (tier 1, structural); workflow integrations
(Linear/Jira/GitHub issues, Slack — honoring local-only + suppressed);
authenticated DAST (deferred); OWASP ZAP (passive+safe); trend/burn-down
reporting.

## Tests

```bash
uv run pytest
```

The suite pins the compliance-critical guardrails so they can't silently
regress: authorization signing & tamper detection, the scope-guard gate (repo /
domain / subdomain / IP-range, plus rejection of unsigned/expired/tampered
records), the hash-chained audit log, evidence integrity, and the **prompt-cache
structure invariants** (cached-first / volatile-last, rubric + source bundle
carry breakpoints, ≤4 per request). Cache tests use a fake client — no network,
no API cost, and they never read your real `.env.local`.

## Safety & scope

- The built-in http-checks adapter is read-only: plain GET requests inspecting
  headers, cookies, CORS behavior, transport, and a small curated list of
  sensitive paths (with a soft-404 baseline). It never sends an exploit payload
  or modifies state.
- nuclei runs `info`/`low`/`medium` templates with a safe tag set only — no fuzz,
  intrusive, DoS, or exploitation templates.
- The scope guard re-validates each live URL (host + resolved IP) at request
  time to resist redirect/DNS-rebinding scope creep.
- This tool is for authorized testing of systems your organization owns or has
  written permission to assess.
