from __future__ import annotations

from anvil.schemas.finding import Finding, Location, Severity


def test_make_id_is_deterministic():
    a = Finding.make_id("E1", "semgrep", "rule.x", "app/db.py:42")
    b = Finding.make_id("E1", "semgrep", "rule.x", "app/db.py:42")
    assert a == b


def test_make_id_varies_with_inputs():
    base = Finding.make_id("E1", "semgrep", "rule.x", "app/db.py:42")
    assert base != Finding.make_id("E1", "semgrep", "rule.x", "app/db.py:43")
    assert base != Finding.make_id("E2", "semgrep", "rule.x", "app/db.py:42")
    assert base != Finding.make_id("E1", "nuclei", "rule.x", "app/db.py:42")


def test_location_ref_file_and_url():
    assert Location(file_path="a/b.py", start_line=7).as_ref() == "a/b.py:7"
    assert Location(file_path="a/b.py").as_ref() == "a/b.py"
    assert (
        Location(url="https://x.example/p", parameter="q").as_ref()
        == "https://x.example/p (param: q)"
    )
    assert Location().as_ref() == "unknown"


def test_severity_rank_orders_worst_first():
    ranks = [s.rank for s in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]]
    assert ranks == sorted(ranks)
    assert Severity.CRITICAL.rank < Severity.INFO.rank
