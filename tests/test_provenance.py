import pytest

from vheatm_control.provenance import (
    ProvenanceError,
    ProvenanceRegistry,
    build_claim_record,
    build_source_record,
    sha256_digest,
)


def test_source_and_claim_ids_are_deterministic() -> None:
    digest = sha256_digest("stable source")
    first = build_source_record(
        source_type="document",
        locator="docs/design.md#decision-1",
        digest=digest,
        trust_zone="artifact_content",
        captured_at="2026-07-31T00:00:00Z",
    )
    second = build_source_record(
        source_type="document",
        locator="docs/design.md#decision-1",
        digest=digest,
        trust_zone="artifact_content",
        captured_at="2026-08-01T00:00:00Z",
    )
    assert first["id"] == second["id"]

    claim_a = build_claim_record(
        text="The write path lacks rollback.",
        epistemic_status="verified",
        confidence=0.95,
        source_refs=[first["id"]],
        evidence_kind="document",
    )
    claim_b = build_claim_record(
        text="  The write path lacks rollback.  ",
        epistemic_status="verified",
        confidence=0.80,
        source_refs=[first["id"]],
        evidence_kind="document",
    )
    assert claim_a["id"] == claim_b["id"]


def test_registry_rejects_unknown_source_refs() -> None:
    registry = ProvenanceRegistry()
    claim = build_claim_record(
        text="Unanchored claim",
        epistemic_status="inferred",
        confidence=0.5,
        source_refs=["SRC-UNKNOWN"],
        evidence_kind="human",
    )
    with pytest.raises(ProvenanceError, match="unknown sources"):
        registry.add_claim(claim)


def test_unknown_claim_cannot_have_confidence() -> None:
    with pytest.raises(ProvenanceError, match="null confidence"):
        build_claim_record(
            text="Unknown claim",
            epistemic_status="unknown",
            confidence=0.2,
            source_refs=[],
            evidence_kind="human",
        )
