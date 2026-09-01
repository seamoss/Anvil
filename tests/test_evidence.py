from __future__ import annotations

import pytest

from anvil.evidence.store import EvidenceStore


def test_put_get_roundtrip(tmp_path):
    store = EvidenceStore(tmp_path)
    ref = store.put('{"results": []}', label="semgrep")
    assert store.get(ref) == '{"results": []}'


def test_content_addressing_dedupes(tmp_path):
    store = EvidenceStore(tmp_path)
    ref1 = store.put("same output", label="run1")
    ref2 = store.put("same output", label="run1")
    assert ref1 == ref2
    # Identical content collapses to a single stored blob.
    raw_files = list(tmp_path.glob("*.raw"))
    assert len(raw_files) == 1


def test_different_content_different_ref(tmp_path):
    store = EvidenceStore(tmp_path)
    assert store.put("a") != store.put("b")


def test_missing_ref_raises(tmp_path):
    store = EvidenceStore(tmp_path)
    store.put("something")
    with pytest.raises(KeyError):
        store.get("0" * 64)
