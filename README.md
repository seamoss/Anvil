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
| SAST | `anvil/pipelines/sast/` | Semgrep + Bandit + CodeQL (code), gitleaks (secrets), Trivy (SCA) adapters |
| DAST | `anvil/pipelines/dast/` | http-checks (built-in: headers/cookies/CORS/methods/exposure/clickjacking), testssl (TLS/cert), nuclei (safe posture) |
| Triage | `anvil/triage/` | Claude triage (prompt-cached, chunked) + SCA fast-path + offline heuristic fallback |
| Reporting | `anvil/reporting/` | OWASP Top 10 / SOC 2 / CWE + CVSS reports — Markdown, SARIF, HTML/PDF |

## Install

Uses [uv](https://docs.astral.sh/uv/). `uv sync` reads the pinned Python
(`.python-version`), creates `.venv`, and installs from `uv.lock`.

```bash
uv sync                             # env + deps (incl. the dev group)

# Scanners (install what you need — SAST runs every one that's present):
uv pip install semgrep bandit       # SAST: code patterns (bandit = Python)
brew install codeql gitleaks trivy  # SAST: deep dataflow + secrets + vulnerable deps
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
uv run anvil scan-repo --auth config/authorizations/acme.yaml --repo /path/to/checkout --logic --report --sarif --html

# 3. DAST — scan a live URL (safe posture)
uv run anvil scan-url --auth config/authorizations/acme.yaml --url https://staging.acme.example --report --sarif

# 4. Verify a run's audit trail
uv run anvil verify-audit --engagement ACME-2026-Q3
```

Each run writes to `runs/<engagement_id>/`: `audit.jsonl`, `evidence/`,
`findings.json` (always), plus whichever reports you requested — `report.md`
(`--report`), `results.sarif` (`--sarif`, for GitHub code scanning / CI),
`report.html` (`--html`, print-ready → Save as PDF), and `report.pdf` (`--pdf`,
requires WeasyPrint).

## Roadmap (next scanners are just new adapters)

The `Finding` schema is the spine — adding coverage is one adapter each.

Done: Semgrep + Bandit + CodeQL (code), gitleaks (secrets), Trivy (SCA) for
SAST; http-checks (first-party) + testssl (TLS) + nuclei for DAST; SARIF +
HTML/PDF reports. SCA findings fast-path around LLM triage by default
(`--deep-deps` to include them).
Next: authenticated DAST (deferred — session token/header, still read-only);
OWASP ZAP (passive+safe) for DAST; per-engagement scanner policy; and finding
diffing across runs.

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
