"""Append-only, hash-chained audit log.

Every meaningful event (scan started, scanner invoked, scope violation, triage
decision, report written) is appended as one JSON line. Each entry carries the
hash of the previous entry, so any deletion or edit of history breaks the chain
and is detectable with `verify_chain()`. This is what lets an auditor trust the
sequence of events that produced a report.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)

    def _last_hash(self) -> str:
        last = GENESIS
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = json.loads(line)["entry_hash"]
        return last

    @staticmethod
    def _hash_entry(entry: Dict[str, Any]) -> str:
        canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def record(self, event_type: str, data: Optional[Dict[str, Any]] = None) -> str:
        prev = self._last_hash()
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "data": data or {},
            "prev_hash": prev,
        }
        entry["entry_hash"] = self._hash_entry(entry)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, separators=(",", ":")) + "\n")
        return entry["entry_hash"]

    def verify_chain(self) -> bool:
        """Return True iff the hash chain is intact end-to-end."""
        prev = GENESIS
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                claimed = entry.pop("entry_hash")
                if entry["prev_hash"] != prev:
                    return False
                if self._hash_entry(entry) != claimed:
                    return False
                prev = claimed
        return True
