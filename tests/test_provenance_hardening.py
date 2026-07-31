import json

import pytest

from vheatm_control.provenance import (
    ProvenanceError,
    ProvenanceRegistry,
    build_claim_record,
    build_source_record,
    verify_source_content,
)


def source(content: str = "stable source") -> dict:
    return build_source_record(
        source_type="document",
        locator="docs/design.md#decision-1",
        content=content,
        trust_zone="artifact_content",
        captured_at="2026-07-31T00:00:00Z",
    )


def test_registry_recomputes_and_rejects_forged_ids() -> None:
    record = source()
    forged = dict(record, id="SRC-AAAAAAAAAAAAAAAA")
    with pytest.raises(ProvenanceError, match="id mismatch"):
        ProvenanceRegistry().add_source(forged)


def test_source_bytes_are_verified() -> None:
    record = source("original")
    verify_source_content(record, "original")
    with pytest.raises(ProvenanceError, match="digest mismatch"):
        verify_source_content(record, "changed")


def test_persistent_registry_is_atomic_append_only_and_concurrency_safe(tmp_path) -> None:
    path = tmp_path / "provenance.json"
    registry = ProvenanceRegistry()
    first_source = source("one")
    registry.add_source(first_source)
    first_root = registry.save(path)

    loaded = ProvenanceRegistry.load(path)
    second_source = build_source_record(
        source_type="test",
        locator="tests/test_x.py::test_y",
        content="two",
        trust_zone="artifact_content",
        captured_at="2026-07-31T00:00:00Z",
    )
    loaded.add_source(second_source)
    second_root = loaded.save(path, expected_root_hash=first_root)
    assert second_root != first_root
    assert json.loads(path.read_text())["root_hash"] == second_root

    stale = ProvenanceRegistry({"schema_version": "1.0.0", "root_hash": first_root, "sources": [first_source], "claims": []})
    with pytest.raises(ProvenanceError, match="changed concurrently"):
        stale.save(path, expected_root_hash=first_root)


def test_claim_id_is_recomputed_and_unknown_refs_rejected() -> None:
    registry = ProvenanceRegistry()
    record = source()
    registry.add_source(record)
    claim = build_claim_record(
        text="Rollback is absent.",
        epistemic_status="verified",
        confidence=0.9,
        source_refs=[record["id"]],
        evidence_kind="document",
    )
    registry.add_claim(claim)
    with pytest.raises(ProvenanceError, match="id mismatch"):
        registry.add_claim(dict(claim, id="CLM-BBBBBBBBBBBBBBBB"))
