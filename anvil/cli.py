"""Anvil CLI.

    anvil init-auth ...      create & sign an authorization record (YAML)
    anvil scan-repo ...      run the SAST pipeline against an authorized repo
    anvil scan-url ...       run the DAST pipeline against an authorized URL
    anvil verify-audit ...   verify a run's hash-chained audit log

Authorization is a hard gate: scan-* refuse to run without a valid, signed,
unexpired authorization record covering the target.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml
from rich.console import Console

from anvil.controller.audit import AuditLog
from anvil.controller.engagement import Engagement
from anvil.controller.scope_guard import ScopeViolation
from anvil.envfile import load_env
from anvil.schemas.authorization import AuthorizationRecord, Scope
from anvil.state.store import StateStore

console = Console()
DEFAULT_DB = "runs/anvil.db"


def _signing_key() -> str:
    key = os.environ.get("ANVIL_AUTH_SIGNING_KEY")
    if not key:
        console.print(
            "[red]ANVIL_AUTH_SIGNING_KEY is not set.[/] Set it (see .env.example) "
            "before creating or using authorization records."
        )
        raise SystemExit(2)
    return key


def cmd_init_auth(args: argparse.Namespace) -> None:
    auth = AuthorizationRecord(
        engagement_id=args.engagement,
        authorized_by=args.by,
        reason=args.reason,
        expires_at=datetime.now(timezone.utc) + timedelta(days=args.days),
        scope=Scope(
            repos=args.repo or [],
            domains=args.domain or [],
            include_subdomains=args.include_subdomains,
            ip_ranges=args.ip_range or [],
        ),
    ).sign(_signing_key())

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(yaml.safe_dump(auth.model_dump(mode="json"), sort_keys=False), encoding="utf-8")
    console.print(f"[green]Wrote signed authorization[/] → {out}")
    console.print(f"  engagement: {auth.engagement_id}")
    console.print(f"  expires:    {auth.expires_at.isoformat()}")


def _run_scan(args: argparse.Namespace, kind: str) -> None:
    _signing_key()  # fail fast if missing
    try:
        eng = Engagement.from_auth_file(args.auth)
    except ScopeViolation as exc:
        console.print(f"[red]Authorization rejected:[/] {exc}")
        raise SystemExit(3)

    console.print(f"[bold]Engagement:[/] {eng.auth.engagement_id}")
    console.print(f"[bold]Scope:[/] {'; '.join(eng.guard.scope_summary())}")
    console.print(f"[bold]Triage:[/] {'online (Claude)' if eng.triage.online else 'offline heuristic'}")

    if kind == "repo" and getattr(args, "deep_deps", False):
        console.print(
            "[yellow]--deep-deps:[/] dependency (SCA) findings will be sent through "
            "LLM triage. On large dependency trees this is hundreds of extra findings "
            "and significantly higher token consumption."
        )

    try:
        if kind == "repo":
            findings = eng.scan_repo(args.repo, logic_review=args.logic, deep_deps=args.deep_deps)
        else:
            findings = eng.scan_url(args.url)
    except ScopeViolation as exc:
        console.print(f"[red]Scope violation:[/] {exc}")
        raise SystemExit(3)
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/]")
        raise SystemExit(1)

    reportable = [f for f in findings if f.status.value in ("confirmed", "triaged")]
    console.print(
        f"[green]Done.[/] {len(findings)} raw finding(s), {len(reportable)} to report."
    )
    if eng.last_diff is not None and not eng.last_diff.is_first_run:
        d = eng.last_diff
        console.print(f"[bold]Since last scan:[/] {len(d.new)} new, {len(d.resolved)} resolved")

    if eng.triage.online:
        u = eng.triage.usage
        console.print(
            f"[dim]Tokens — in {u['input_tokens']}, out {u['output_tokens']}, "
            f"cache write {u['cache_creation_input_tokens']}, "
            f"cache read {u['cache_read_input_tokens']}[/]"
        )

    outputs = []
    if args.report:
        outputs.append(("Markdown", eng.write_report(findings)))
    if getattr(args, "sarif", False):
        outputs.append(("SARIF", eng.write_sarif(findings)))
    if getattr(args, "html", False):
        outputs.append(("HTML", eng.write_html(findings)))
    if getattr(args, "pdf", False):
        try:
            outputs.append(("PDF", eng.write_pdf(findings)))
        except RuntimeError as exc:
            console.print(f"[yellow]PDF skipped:[/] {exc}")

    if outputs:
        for label, path in outputs:
            console.print(f"[green]{label}:[/] {path}")
        console.print(f"[green]Findings:[/] {eng.root / 'findings.json'}")
        console.print(f"[green]Audit log:[/] {eng.root / 'audit.jsonl'} (chain ok: {eng.audit.verify_chain()})")


def cmd_scan_repo(args: argparse.Namespace) -> None:
    _run_scan(args, "repo")


def cmd_scan_url(args: argparse.Namespace) -> None:
    _run_scan(args, "url")


def cmd_verify_audit(args: argparse.Namespace) -> None:
    audit_path = Path("runs") / args.engagement / "audit.jsonl"
    if not audit_path.exists() or audit_path.stat().st_size == 0:
        console.print(f"[red]No audit log found for engagement '{args.engagement}'.[/]")
        raise SystemExit(2)
    log = AuditLog(audit_path)
    ok = log.verify_chain()
    console.print(f"Audit chain for '{args.engagement}': {'[green]INTACT[/]' if ok else '[red]BROKEN[/]'}")
    raise SystemExit(0 if ok else 1)


def cmd_suppress(args: argparse.Namespace) -> None:
    store = StateStore(args.db)
    scope, value = ("finding_id", args.finding_id) if args.finding_id else ("rule_id", args.rule_id)
    store.add_suppression(scope, value, reason=args.reason, by=os.environ.get("USER"))
    console.print(f"[green]Suppressed[/] {scope}={value}"
                  + (f" — {args.reason}" if args.reason else ""))


def cmd_unsuppress(args: argparse.Namespace) -> None:
    store = StateStore(args.db)
    scope, value = ("finding_id", args.finding_id) if args.finding_id else ("rule_id", args.rule_id)
    store.remove_suppression(scope, value)
    console.print(f"[green]Removed suppression[/] {scope}={value}")


def cmd_suppressions(args: argparse.Namespace) -> None:
    rows = StateStore(args.db).list_suppressions()
    if not rows:
        console.print("No suppressions.")
        return
    for s in rows:
        console.print(f"{s['scope']}={s['value']}  "
                      f"[dim]{s.get('reason') or ''} ({s.get('created_by') or '?'} @ {s['ts']})[/]")


def cmd_history(args: argparse.Namespace) -> None:
    rows = StateStore(args.db).history(args.engagement)
    if not rows:
        console.print(f"No runs recorded for '{args.engagement}'.")
        return
    for r in rows:
        console.print(f"run {r['id']}: {r['ts']}  reported={r['reported']}  "
                      f"[dim]{r.get('target') or ''}[/]")


def _add_output_flags(parser: argparse.ArgumentParser) -> None:
    """Report-format flags shared by scan-repo and scan-url. Combine freely;
    findings.json is always written regardless."""
    parser.add_argument("--report", action="store_true", help="write report.md (Markdown)")
    parser.add_argument("--sarif", action="store_true", help="write results.sarif (SARIF 2.1.0)")
    parser.add_argument("--html", action="store_true", help="write report.html (print-ready)")
    parser.add_argument("--pdf", action="store_true", help="write report.pdf (needs WeasyPrint)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="anvil", description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    ia = sub.add_parser("init-auth", help="create & sign an authorization record")
    ia.add_argument("--engagement", required=True)
    ia.add_argument("--by", required=True, help="email of the authorizing person")
    ia.add_argument("--reason", default="", help="ticket / compliance justification")
    ia.add_argument("--days", type=int, default=14, help="days until expiry")
    ia.add_argument("--repo", action="append", help="authorized repo path/URL (repeatable)")
    ia.add_argument("--domain", action="append", help="authorized domain (repeatable)")
    ia.add_argument("--include-subdomains", action="store_true")
    ia.add_argument("--ip-range", action="append", help="authorized CIDR (repeatable)")
    ia.add_argument("--out", required=True, help="output YAML path")
    ia.set_defaults(func=cmd_init_auth)

    sr = sub.add_parser("scan-repo", help="run the SAST pipeline")
    sr.add_argument("--auth", required=True, help="path to signed authorization YAML")
    sr.add_argument("--repo", required=True, help="repo path (must be in scope)")
    sr.add_argument("--logic", action="store_true", help="add the LLM business-logic pass")
    sr.add_argument(
        "--deep-deps", action="store_true",
        help="also send dependency (SCA/Trivy) findings through LLM triage "
             "(default: fast-path them; --deep-deps costs many more tokens)",
    )
    _add_output_flags(sr)
    sr.set_defaults(func=cmd_scan_repo)

    su = sub.add_parser("scan-url", help="run the DAST pipeline (safe posture)")
    su.add_argument("--auth", required=True, help="path to signed authorization YAML")
    su.add_argument("--url", required=True, help="target URL (host must be in scope)")
    _add_output_flags(su)
    su.set_defaults(func=cmd_scan_url)

    va = sub.add_parser("verify-audit", help="verify a run's hash-chained audit log")
    va.add_argument("--engagement", required=True)
    va.set_defaults(func=cmd_verify_audit)

    sup = sub.add_parser("suppress", help="mark a finding_id or rule_id as accepted-risk / FP")
    g = sup.add_mutually_exclusive_group(required=True)
    g.add_argument("--finding-id")
    g.add_argument("--rule-id")
    sup.add_argument("--reason", default="")
    sup.add_argument("--db", default=DEFAULT_DB)
    sup.set_defaults(func=cmd_suppress)

    uns = sub.add_parser("unsuppress", help="remove a suppression")
    g2 = uns.add_mutually_exclusive_group(required=True)
    g2.add_argument("--finding-id")
    g2.add_argument("--rule-id")
    uns.add_argument("--db", default=DEFAULT_DB)
    uns.set_defaults(func=cmd_unsuppress)

    sps = sub.add_parser("suppressions", help="list active suppressions")
    sps.add_argument("--db", default=DEFAULT_DB)
    sps.set_defaults(func=cmd_suppressions)

    hist = sub.add_parser("history", help="show scan history for an engagement")
    hist.add_argument("--engagement", required=True)
    hist.add_argument("--db", default=DEFAULT_DB)
    hist.set_defaults(func=cmd_history)

    return p


def main(argv=None) -> None:
    load_env()  # pick up ANTHROPIC_API_KEY / ANVIL_AUTH_SIGNING_KEY from .env(.local)
    args = build_parser().parse_args(argv if argv is not None else sys.argv[1:])
    args.func(args)


if __name__ == "__main__":
    main()
