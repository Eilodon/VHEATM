from __future__ import annotations

from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from vheatm_control.migration_capabilities import (
    MigrationCapabilityError,
    build_stakeholder_record,
    evaluate_signal_noise,
    migrate_legacy_output,
)
from vheatm_control.serialization import load_json


ROOT = Path(__file__).resolve().parents[1]


def test_signal_noise_preserves_security_mandatory_priority() -> None:
    decision = evaluate_signal_noise(
        {
            "hypothesis_id": "H-SEC-001",
            "original_priority": "mandatory",
            "worst_case": {"description": "authentication bypass", "probability": "medium"},
            "security_implication": True,
            "monitorable": False,
            "time_to_detect_hours": None,
            "time_to_fix_hours": None,
        },
        mode="standard",
        root=ROOT,
    )

    assert decision["status"] == "complete"
    assert decision["verdict"] == "maintain"
    assert decision["effective_priority"] == "mandatory"
    assert decision["security_exception"] is True
    Draft202012Validator(load_json((ROOT / "schemas" / "signal-noise-decision.schema.json").read_text(encoding="utf-8"))).validate(decision)


def test_signal_noise_fast_mode_explicitly_skips_unprovided_questions() -> None:
    decision = evaluate_signal_noise(
        {
            "hypothesis_id": "H-FAST-001",
            "original_priority": "required",
            "worst_case": {"description": "minor friction", "probability": "low"},
            "security_implication": False,
            "monitorable": True,
            "time_to_detect_hours": 4,
            "time_to_fix_hours": 8,
        },
        mode="fast",
        root=ROOT,
    )

    assert decision["status"] == "complete"
    assert decision["skipped_questions"] == ["Q2", "Q4"]
    assert decision["verdict"] == "downgrade"
    assert decision["effective_priority"] == "recommended"


def test_signal_noise_unknown_input_cannot_mint_a_downgrade() -> None:
    decision = evaluate_signal_noise(
        {
            "hypothesis_id": "H-UNKNOWN-001",
            "original_priority": "required",
            "worst_case": {"description": "unbounded impact", "probability": "unknown"},
            "security_implication": None,
            "monitorable": None,
            "time_to_detect_hours": None,
            "time_to_fix_hours": None,
        },
        mode="standard",
        root=ROOT,
    )

    assert decision["status"] == "unknown"
    assert decision["verdict"] is None
    assert decision["effective_priority"] is None
    assert decision["diagnostics"]


def test_stakeholder_record_requires_enterprise_ownership_map() -> None:
    record = build_stakeholder_record(
        {
            "schema_version": "2.0.0",
            "context_mode": "enterprise",
            "goal": "approve the release boundary",
            "decision_owner": "platform-lead",
            "stakeholder": "security",
            "organization_scope": "enterprise",
        },
        primary_role="security",
        secondary_roles=["SRE", "legal"],
        org_context={"auditor_team": "assurance", "teams_in_scope": ["platform", "security"]},
        ownership_map=[
            {
                "component": "control-plane",
                "owning_team": "platform",
                "on_call": "platform-oncall",
                "escalation": "security-lead",
            }
        ],
        root=ROOT,
    )

    assert record["status"] == "complete"
    assert record["primary_role"] == "security"
    assert record["ownership_map"][0]["owning_team"] == "platform"
    Draft202012Validator(load_json((ROOT / "schemas" / "stakeholder-record.schema.json").read_text(encoding="utf-8"))).validate(record)


def test_stakeholder_record_missing_owner_stays_unknown() -> None:
    record = build_stakeholder_record(
        {"context_mode": "enterprise", "goal": "release", "stakeholder": "security"},
        primary_role="security",
        root=ROOT,
    )

    assert record["status"] == "unknown"
    assert "decision_owner" in record["missing_requirements"]
    assert "ownership_map" in record["missing_requirements"]


def test_legacy_output_migration_maps_complete_fast_profile_without_authority() -> None:
    migrated = migrate_legacy_output(
        {
            "context": {"mode": "DESIGN"},
            "summary": {"verdict": "revise", "confidence": "medium"},
            "top_findings": [{"id": "F1"}, {"id": "F2"}, {"id": "F3"}],
            "bias_probe": {},
            "automation_bias_guard": {},
            "signal_noise_filter": {},
            "adversarial_pass": {},
            "recommendation": {"decision": "Revise"},
            "next_cycle_trigger": "when evidence changes",
        },
        mode="FAST",
        root=ROOT,
    )

    assert migrated["status"] == "complete"
    assert migrated["authority_eligible"] is False
    assert migrated["taint_state"] == "tainted"
    assert migrated["missing_sections"] == []
    assert any(item["legacy_section"] == "top_findings" for item in migrated["section_mappings"])
    Draft202012Validator(load_json((ROOT / "schemas" / "legacy-output-migration.schema.json").read_text(encoding="utf-8"))).validate(migrated)


def test_legacy_output_migration_rejects_wrong_finding_cardinality() -> None:
    with pytest.raises(MigrationCapabilityError, match="exactly 3"):
        migrate_legacy_output(
            {
                "context": {"mode": "DESIGN"},
                "summary": {"verdict": "revise", "confidence": "medium"},
                "top_findings": [{"id": "F1"}],
            },
            mode="FAST",
            root=ROOT,
        )
