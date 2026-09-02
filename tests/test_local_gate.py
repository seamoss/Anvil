"""Local-only classification gate tests."""

from __future__ import annotations

import pytest

from anvil.reporting.html import HtmlReporter
from anvil.reporting.report import ReportGenerator
from anvil.reporting.sarif import SarifReporter
from anvil.schemas.finding import Finding, FindingStatus, Location, Pipeline, Severity
from anvil.triage.local_gate import classify, is_local_only


def mk(file_path=None, url=None):
    return Finding(
        finding_id="x",
        engagement_id="E",
        pipeline=Pipeline.DAST if url else Pipeline.SAST,
        source_tool="s",
        title="t",
        severity=Severity.HIGH,
        location=Location(file_path=file_path, url=url),
    )


@pytest.mark.parametrize("path", [
    "web/.env.local", ".env.local", "config.local.js", "app/settings.local.js",
    "local.log", "logs/local-debug.log", ".env.development", ".env.test",
    "app/local_settings.py", "docker-compose.override.yml",
])
def test_local_paths(path):
    assert is_local_only(mk(file_path=path)) is True


@pytest.mark.parametrize("path", [
    "web/.env", "config/index.js", "routes/loan_lenders.mjs", "lib/foo.mjs",
    "app/locale.js", "src/localization/en.json",
])
def test_non_local_paths(path):
    assert is_local_only(mk(file_path=path)) is False


@pytest.mark.parametrize("url,expect", [
    ("https://localhost:8443/", True),
    ("https://127.0.0.1:8099/", True),
    ("http://api.joinatmos.com/", False),
    ("https://staging.example.com/health", False),
])
def test_urls(url, expect):
    assert is_local_only(mk(url=url)) is expect


def test_classify_sets_flag_in_place():
    fs = [mk(file_path=".env.local"), mk(file_path="routes/x.mjs")]
    classify(fs)
    assert fs[0].local_only is True
    assert fs[1].local_only is False


def test_classify_never_clears_existing_flag():
    f = mk(file_path="routes/x.mjs")
    f.local_only = True  # e.g. set upstream
    classify([f])
    assert f.local_only is True


def test_reports_mark_local_only():
    f = mk(file_path=".env.local")
    f.status = FindingStatus.CONFIRMED
    f.local_only = True

    md = ReportGenerator().render_markdown("E", ["repos: x"], [f])
    assert "local-only" in md

    html = HtmlReporter().render("E", ["repos: x"], [f])
    assert "local-only" in html

    sarif = SarifReporter().render("E", [f])
    assert sarif["runs"][0]["results"][0]["properties"]["localOnly"] is True
