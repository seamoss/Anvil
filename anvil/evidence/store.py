"""Evidence store — content-addressed, append-only raw scanner output.

Each raw scanner run (its full JSON/text output) is written verbatim and keyed
by the SHA-256 of its content. A Finding references its evidence by that hash
(`evidence_ref`), so anyone reviewing finding #7 can pull the exact bytes the
scanner emitted and replay the derivation.
"""

from __future__ import annotations

import hashlib
from pathlib import Path


class EvidenceStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, content: str, label: str = "") -> str:
        """Store raw content; return its content hash (the evidence_ref).

        `label` is an optional human hint baked into the filename for browsing;
        it does not affect the hash, so identical output dedupes to one blob.
        """
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        safe_label = "".join(c if c.isalnum() or c in "-_." else "_" for c in label)
        name = f"{digest[:16]}_{safe_label}" if safe_label else digest[:16]
        path = self.root / f"{name}.raw"
        if not path.exists():
            path.write_text(content, encoding="utf-8")
        # A tiny index line mapping full hash -> file, so a ref always resolves.
        (self.root / "index.tsv").open("a", encoding="utf-8").write(
            f"{digest}\t{path.name}\n"
        )
        return digest

    def get(self, evidence_ref: str) -> str:
        for line in (self.root / "index.tsv").read_text(encoding="utf-8").splitlines():
            digest, filename = line.split("\t", 1)
            if digest == evidence_ref:
                return (self.root / filename).read_text(encoding="utf-8")
        raise KeyError(f"No evidence stored for ref {evidence_ref}")
