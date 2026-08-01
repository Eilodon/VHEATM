from __future__ import annotations

from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from vheatm_control.overlay_capabilities import (
    OverlayCapabilityError,
    build_ai_rmf_overlay,
    build_assurance_maturity_delta,
    build_cross_cutting_scan,
    build_temporal_scan,
)
from vheatm_control.serialization import load_json


ROOT = Path(__file__).resolve().parents[1]


def test_cross_cutting_enterprise_scan_requires_l7_11() -> None:
    record = build_cross_cutting_scan(
        {"context_mode": "enterprise", "audit_stage": "code"},
        active_subcategories=["L7.1", "L7.2", "L7.4"],
        root=ROOT,
    )

    assert record["status"] == "complete"
    compliance = next(item for item in record["obligations"] if item["id"] == "L7.11")
    assert compliance["required"] is True
    assert compliance["owner"] == "MOD-EVIDENCE-ANCHORS"
    Draft202012Validator(load_json((ROOT / "schemas" / "cross-cutting-scan.schema.json").read_text(encoding="utf-8"))).validate(record)


def test_cross_cutting_unknown_context_does_not_infer_compliance_scope() -> None:
    record = build_cross_cutting_scan({}, active_subcategories=["L7.1"], root=ROOT)

    assert record["status"] == "unknown"
    assert "context_mode" in record["missing_requirements"]


def test_temporal_scan_requires_strictly_ordered_immutable_snapshots() -> None:
    record = build_temporal_scan(
        [
            {"snapshot_id": "S-1", "captured_at": "2026-08-01T00:00:00Z", "digest": "a" * 64},
            {"snapshot_id": "S-2", "captured_at": "2026-08-01T00:00:01Z", "digest": "b" * 64},
        ],
        mode="full",
        root=ROOT,
    )

    assert record["status"] == "complete"
    assert [item["id"] for item in record["sublayers"]] == [f"L4.{index}" for index in range(1, 7)]
    Draft202012Validator(load_json((ROOT / "schemas" / "temporal-scan.schema.json").read_text(encoding="utf-8"))).validate(record)


def test_temporal_scan_blocks_clock_or_snapshot_mismatch() -> None:
    with pytest.raises(OverlayCapabilityError, match="strictly increasing"):
        build_temporal_scan(
            [
                {"snapshot_id": "S-1", "captured_at": "2026-08-01T00:00:01Z", "digest": "a" * 64},
                {"snapshot_id": "S-2", "captured_at": "2026-08-01T00:00:01Z", "digest": "b" * 64},
            ],
            mode="standard",
            root=ROOT,
        )


def test_ai_rmf_overlay_keeps_missing_governance_unknown() -> None:
    record = build_ai_rmf_overlay(
        {"declarations": {"ai_integrated": "yes"}},
        model={"provider_id": "provider:test", "model_id": "model:test", "config_digest": "c" * 64},
        ai_inputs=["user prompt"],
        ai_outputs=["candidate finding"],
        human_oversight_points=1,
        governance={"policy_exists": None, "accountability_documented": True, "human_review_for_high_stakes": True},
        monitoring_coverage=None,
        root=ROOT,
    )

    assert record["status"] == "unknown"
    assert "governance.policy_exists" in record["missing_requirements"]
    assert record["authority_eligible"] is False


def test_ai_rmf_overlay_binds_pinned_nist_baseline_and_monitoring_coverage() -> None:
    record = build_ai_rmf_overlay(
        {"declarations": {"ai_integrated": "yes"}},
        model={"provider_id": "provider:test", "model_id": "model:test", "config_digest": "c" * 64},
        ai_inputs=["user prompt"],
        ai_outputs=["candidate finding"],
        human_oversight_points=2,
        governance={"policy_exists": True, "accountability_documented": True, "human_review_for_high_stakes": True},
        monitoring_coverage=0.75,
        root=ROOT,
    )

    assert record["status"] == "complete"
    assert record["monitoring_coverage"] == 0.75
    assert record["standards_binding"]["id"] == "NIST-AI-RMF-1.0"
    assert record["standards_binding"]["status"] == "pinned"
    assert len(record["standards_binding"]["policy_digest"]) == 64


def test_ai_rmf_overlay_does_not_treat_a_string_as_an_input_sequence() -> None:
    record = build_ai_rmf_overlay(
        {"declarations": {"ai_integrated": "yes"}},
        model={"provider_id": "provider:test", "model_id": "model:test", "config_digest": "c" * 64},
        ai_inputs="not-an-array",
        ai_outputs=["candidate finding"],
        human_oversight_points=1,
        governance={"policy_exists": True, "accountability_documented": True, "human_review_for_high_stakes": True},
        monitoring_coverage=1.0,
        root=ROOT,
    )

    assert record["status"] == "unknown"
    assert "ai_inputs" in record["missing_requirements"]


def test_assurance_maturity_overlay_is_delta_only_without_score() -> None:
    record = build_assurance_maturity_delta(
        [
            {
                "finding_id": "F-1",
                "priority": "mandatory",
                "finding_type": "MISSING_CONTROL",
                "samm_function": "VERIFICATION",
                "samm_practice": "security testing",
                "ssdf_mapping": "RV.3",
                "bsimm_baseline": True,
                "improvement_recommendation": "add mutation coverage",
                "priority_action": "IMMEDIATE",
            }
        ],
        root=ROOT,
    )

    assert record["status"] == "complete"
    assert record["claim_type"] == "delta_only"
    assert "maturity_score" not in record
    assert record["maturity_deltas"][0]["finding_id"] == "F-1"
    Draft202012Validator(load_json((ROOT / "schemas" / "assurance-maturity-delta.schema.json").read_text(encoding="utf-8"))).validate(record)
