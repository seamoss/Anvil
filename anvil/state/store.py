"""Persistent state store — turns Anvil from a snapshot tool into a program.

A single SQLite database (default `runs/anvil.db`) tracks findings across runs,
keyed by the deterministic `finding_id`. It answers:
  - what's NEW since the engagement's last scan,
  - what's been RESOLVED (was open, gone now),
  - what's still open,
and it holds SUPPRESSIONS (accept-risk / confirmed-FP) so known findings stop
re-alerting without disappearing from the record.

Everything is keyed per engagement so different targets don't cross-contaminate.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from anvil.schemas.finding import Finding, FindingStatus

_REPORTABLE = {FindingStatus.CONFIRMED.value, FindingStatus.TRIAGED.value}


@dataclass
class RunDiff:
    """Result of recording a run: how it differs from the previous one."""

    run_id: int
    new: List[str] = field(default_factory=list)       # newly-seen (or reappeared)
    resolved: List[str] = field(default_factory=list)  # were open, gone this run
    existing: List[str] = field(default_factory=list)  # carried over from before

    @property
    def is_first_run(self) -> bool:
        return not self.resolved and not self.existing


class StateStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id TEXT NOT NULL,
                ts TEXT NOT NULL,
                target TEXT,
                reported INTEGER
            );
            CREATE TABLE IF NOT EXISTS findings (
                engagement_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                first_run_id INTEGER,
                last_run_id INTEGER,
                first_ts TEXT,
                last_ts TEXT,
                severity TEXT,
                status TEXT,
                source_tool TEXT,
                title TEXT,
                resolved INTEGER DEFAULT 0,
                resolved_ts TEXT,
                PRIMARY KEY (engagement_id, finding_id)
            );
            CREATE TABLE IF NOT EXISTS suppressions (
                scope TEXT NOT NULL,      -- 'finding_id' | 'rule_id'
                value TEXT NOT NULL,
                reason TEXT,
                created_by TEXT,
                ts TEXT,
                PRIMARY KEY (scope, value)
            );
            """
        )
        self._conn.commit()

    # --- run recording / diffing -------------------------------------------
    def record_run(self, engagement_id: str, findings: List[Finding], target: str = None) -> RunDiff:
        """Persist this run's reportable findings and return the diff vs the
        engagement's previous run."""
        now = datetime.now(timezone.utc).isoformat()
        reportable = [f for f in findings if f.status.value in _REPORTABLE]
        cur = self._conn.cursor()
        cur.execute(
            "INSERT INTO runs (engagement_id, ts, target, reported) VALUES (?,?,?,?)",
            (engagement_id, now, target, len(reportable)),
        )
        run_id = cur.lastrowid

        existing = {
            r["finding_id"]: r
            for r in cur.execute(
                "SELECT * FROM findings WHERE engagement_id=?", (engagement_id,)
            )
        }

        diff = RunDiff(run_id=run_id)
        current_ids = set()
        for f in reportable:
            fid = f.finding_id
            current_ids.add(fid)
            prev = existing.get(fid)
            if prev is None:
                diff.new.append(fid)
                cur.execute(
                    "INSERT INTO findings (engagement_id, finding_id, first_run_id, "
                    "last_run_id, first_ts, last_ts, severity, status, source_tool, "
                    "title, resolved) VALUES (?,?,?,?,?,?,?,?,?,?,0)",
                    (engagement_id, fid, run_id, run_id, now, now,
                     f.severity.value, f.status.value, f.source_tool, f.title),
                )
            else:
                if prev["resolved"]:
                    diff.new.append(fid)  # reappeared after being resolved
                else:
                    diff.existing.append(fid)
                cur.execute(
                    "UPDATE findings SET last_run_id=?, last_ts=?, severity=?, status=?, "
                    "resolved=0, resolved_ts=NULL WHERE engagement_id=? AND finding_id=?",
                    (run_id, now, f.severity.value, f.status.value, engagement_id, fid),
                )

        # Anything previously open but absent this run is now resolved.
        for fid, prev in existing.items():
            if not prev["resolved"] and fid not in current_ids:
                diff.resolved.append(fid)
                cur.execute(
                    "UPDATE findings SET resolved=1, resolved_ts=? WHERE engagement_id=? AND finding_id=?",
                    (now, engagement_id, fid),
                )

        self._conn.commit()
        return diff

    def previous_run_count(self, engagement_id: str) -> int:
        """Number of runs recorded for this engagement (before the current one)."""
        row = self._conn.execute(
            "SELECT COUNT(*) AS n FROM runs WHERE engagement_id=?", (engagement_id,)
        ).fetchone()
        return row["n"]

    def history(self, engagement_id: str) -> List[dict]:
        return [
            dict(r)
            for r in self._conn.execute(
                "SELECT id, ts, target, reported FROM runs WHERE engagement_id=? ORDER BY id",
                (engagement_id,),
            )
        ]

    # --- suppressions ------------------------------------------------------
    def add_suppression(self, scope: str, value: str, reason: str = None, by: str = None) -> None:
        if scope not in ("finding_id", "rule_id"):
            raise ValueError("scope must be 'finding_id' or 'rule_id'")
        self._conn.execute(
            "INSERT OR REPLACE INTO suppressions (scope, value, reason, created_by, ts) "
            "VALUES (?,?,?,?,?)",
            (scope, value, reason, by, datetime.now(timezone.utc).isoformat()),
        )
        self._conn.commit()

    def remove_suppression(self, scope: str, value: str) -> None:
        self._conn.execute("DELETE FROM suppressions WHERE scope=? AND value=?", (scope, value))
        self._conn.commit()

    def list_suppressions(self) -> List[dict]:
        return [dict(r) for r in self._conn.execute(
            "SELECT scope, value, reason, created_by, ts FROM suppressions ORDER BY ts"
        )]

    def apply_suppressions(self, findings: List[Finding]) -> int:
        """Mark suppressed findings in place; return how many were suppressed."""
        sup_fid, sup_rule = set(), set()
        for r in self._conn.execute("SELECT scope, value FROM suppressions"):
            (sup_fid if r["scope"] == "finding_id" else sup_rule).add(r["value"])
        n = 0
        for f in findings:
            if f.finding_id in sup_fid or (f.rule_id and f.rule_id in sup_rule):
                f.suppressed = True
                n += 1
        return n

    def close(self) -> None:
        self._conn.close()
