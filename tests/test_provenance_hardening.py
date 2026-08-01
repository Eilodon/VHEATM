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
    assert len(record["id"].split("-", 1)[1]) == 64
    forged = dict(record, id="SRC-" + "A" * 64)
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
        registry.add_claim(dict(claim, id="CLM-" + "B" * 64))


def test_untrusted_source_cannot_self_declare_validated() -> None:
    with pytest.raises(ProvenanceError, match="tainted"):
        build_source_record(
            source_type="code",
            locator="src/app.py",
            content="pass",
            trust_zone="artifact_content",
            taint_state="validated",
            captured_at="2026-07-31T00:00:00Z",
        )


def test_registry_rejects_forged_validated_state_for_untrusted_source() -> None:
    record = source()
    forged = dict(record, taint_state="validated")
    with pytest.raises(ProvenanceError, match="untrusted source"):
        ProvenanceRegistry().add_source(forged)


def test_claim_lineage_is_content_bound_and_must_resolve() -> None:
    registry = ProvenanceRegistry()
    record = source()
    registry.add_source(record)
    parent = build_claim_record(
        text="The source is present.",
        epistemic_status="verified",
        confidence=1.0,
        source_refs=[record["id"]],
        evidence_kind="document",
    )
    registry.add_claim(parent)
    child = build_claim_record(
        text="The source supports the control.",
        epistemic_status="inferred",
        confidence=0.8,
        source_refs=[record["id"]],
        evidence_kind="document",
        lineage_refs=[parent["id"]],
    )
    registry.add_claim(child)
    assert registry.to_document()["claims"][1]["lineage_refs"] == [parent["id"]]
    with pytest.raises(ProvenanceError, match="unknown lineage"):
        registry.add_claim(
            build_claim_record(
                text="Unresolved lineage.",
                epistemic_status="inferred",
                confidence=0.2,
                source_refs=[],
                evidence_kind="human",
                lineage_refs=["CLM-" + "F" * 64],
            )
        )


def test_journal_hash_chain_is_emitted_and_tamper_evident(tmp_path) -> None:
    path = tmp_path / "provenance.json"
    registry = ProvenanceRegistry()
    registry.add_source(source(), actor="operator")
    registry.save(path)
    document = json.loads(path.read_text())
    assert document["journal"][0]["actor"] == "operator"
    assert document["journal"][0]["previous_hash"] == ""
    assert document["journal"][0]["event_hash"]

    document["journal"][0]["event_hash"] = "0" * 64
    with pytest.raises(ProvenanceError, match="journal"):
        ProvenanceRegistry(document)

    duplicate = json.loads(path.read_text())
    duplicate["journal"].append(dict(duplicate["journal"][0]))
    with pytest.raises(ProvenanceError, match="journal"):
        ProvenanceRegistry(duplicate)
