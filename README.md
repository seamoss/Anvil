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
| SAST | `anvil/pipelines/sast/` | Semgrep (code), gitleaks (secrets), Trivy (SCA) adapters |
| DAST | `anvil/pipelines/dast/` | nuclei adapter, safe posture (first scanner) |
| Triage | `anvil/triage/` | Claude triage + offline heuristic fallback |
| Reporting | `anvil/reporting/` | OWASP Top 10 / SOC 2 / CVSS Markdown report |

## Install

Uses [uv](https://docs.astral.sh/uv/). `uv sync` reads the pinned Python
(`.python-version`), creates `.venv`, and installs from `uv.lock`.

```bash
uv sync                             # env + deps (incl. the dev group)

# Scanners (install what you need — SAST runs every one that's present):
uv pip install semgrep              # SAST: code patterns
brew install gitleaks trivy         # SAST: secrets + vulnerable dependencies
brew install nuclei                 # DAST  (or see projectdiscovery/nuclei)

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

# 2. SAST — scan a repo
uv run anvil scan-repo --auth config/authorizations/acme.yaml --repo /path/to/checkout --logic --report

# 3. DAST — scan a live URL (safe posture)
uv run anvil scan-url --auth config/authorizations/acme.yaml --url https://staging.acme.example --report

# 4. Verify a run's audit trail
uv run anvil verify-audit --engagement ACME-2026-Q3
```

Each run writes to `runs/<engagement_id>/`: `audit.jsonl`, `evidence/`,
`findings.json`, `report.md`.

## Roadmap (next scanners are just new adapters)

The `Finding` schema is the spine — adding coverage is one adapter each.

Done: Semgrep, gitleaks (secrets), Trivy (SCA) for SAST; nuclei for DAST.
Next: CodeQL / Bandit for SAST; OWASP ZAP (passive+safe) and testssl.sh for
DAST; SARIF + HTML/PDF report renderers; per-engagement scanner policy; and
finding diffing across runs.

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

- DAST runs `info`/`low`/`medium` templates with a safe tag set only — no fuzz,
  intrusive, DoS, or exploitation templates.
- The scope guard re-validates each live URL (host + resolved IP) at request
  time to resist redirect/DNS-rebinding scope creep.
- This tool is for authorized testing of systems your organization owns or has
  written permission to assess.
