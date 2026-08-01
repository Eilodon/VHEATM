import hashlib
import json
from pathlib import Path

import yaml
import pytest

from vheatm_control.evaluator import (
    ContextValidationError,
    PlanIntegrityError,
    evaluate_manifest,
    normalize_context,
    revise_plan,
    validate_context,
)


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = yaml.safe_load((ROOT / "manifests" / "vheatm-v17.yaml").read_text())
CONTEXT_SCHEMA = __import__("json").loads((ROOT / "schemas" / "audit-context.schema.json").read_text())


def test_default_context_blocks_on_unknown_activation() -> None:
    plan = evaluate_manifest(MANIFEST)
    assert plan["summary"]["total"] == 22
    assert plan["summary"]["completion_blocked"] is True
    assert plan["summary"]["unknown"] > 0


def test_explicit_low_risk_context_is_deterministic() -> None:
    plan = evaluate_manifest(
        MANIFEST,
        {
            "mode": "standard",
            "target_tier": 2,
            "context_mode": "single",
            "mandatory_findings": 0,
            "blast_radius": 1,
            "write_chain_components": 1,
            "declarations": {
                "self_audit": "no",
                "ai_executor": "no",
                "async_worker": "no",
                "safety_critical": "no",
                "financial_path": "no",
            },
        },
    )
    assert plan["summary"] == {
        "active": 15,
        "inactive": 7,
        "unknown": 0,
        "total": 22,
        "completion_blocked": False,
    }


def test_full_enterprise_context_activates_all_gates() -> None:
    plan = evaluate_manifest(
        MANIFEST,
        {
            "mode": "full",
            "target_tier": 3,
            "context_mode": "enterprise",
            "mandatory_findings": 2,
            "blast_radius": 5,
            "write_chain_components": 4,
            "declarations": {
                "self_audit": "yes",
                "ai_executor": "yes",
                "async_worker": "yes",
                "safety_critical": "yes",
                "financial_path": "yes",
            },
        },
    )
    assert plan["summary"]["active"] == 22
    assert plan["summary"]["unknown"] == 0


def test_plan_is_content_bound_to_manifest_context_and_evaluator() -> None:
    context = {
        "mode": "standard",
        "target_tier": 2,
        "context_mode": "single",
        "mandatory_findings": 0,
        "blast_radius": 1,
        "write_chain_components": 1,
        "declarations": {
            "self_audit": "no",
            "ai_executor": "no",
            "async_worker": "no",
            "safety_critical": "no",
            "financial_path": "no",
        },
    }
    plan = evaluate_manifest(MANIFEST, context)

    assert plan["context_digest"]
    assert plan["manifest_digest"]
    assert plan["evaluator_digest"]
    assert plan["plan_id"].startswith("PLN-")
    digest_input = {key: value for key, value in plan.items() if key not in {"plan_digest", "plan_id"}}
    expected_digest = hashlib.sha256(
        json.dumps(digest_input, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    assert plan["plan_digest"] == expected_digest


def test_empty_context_is_invalid_at_the_boundary() -> None:
    with pytest.raises(ContextValidationError, match="at least one property"):
        validate_context({}, CONTEXT_SCHEMA)
    with pytest.raises(ContextValidationError, match="at least one property"):
        normalize_context(MANIFEST, {})


def test_v2_context_maps_new_dimensions_and_derives_findings_from_ledger() -> None:
    raw = {
        "schema_version": "2.0.0",
        "goal": "Assess the release boundary.",
        "decision_owner": "platform-owner",
        "stakeholder": "platform-team",
        "subject": {"kind": "repository", "locator": "workspace:/repo", "digest": "a" * 64, "tree_digest": "b" * 64},
        "scope": {"included_paths": ["src"], "excluded_paths": []},
        "audit_stage": "code",
        "legacy_state": "no",
        "organization_scope": "single-team",
        "execution_profile": "standard",
        "audit_intent": "assessment-only",
        "pii": "no",
        "compliance": [],
        "multi_tenant": "no",
        "post_incident": "no",
        "language": "en",
        "organization_size": "small",
        "test_availability": "adequate",
        "declarations": {"self_audit": "no", "ai_executor": "no"},
        "finding_ledger": [{"id": "F-1", "priority": "mandatory", "state": "open"}],
        "facts": {"blast_radius": 2, "write_chain_components": 1},
        "amendments": [],
    }
    validate_context(raw, CONTEXT_SCHEMA)
    normalized = normalize_context(MANIFEST, raw)
    assert normalized["mode"] == "standard"
    assert normalized["context_mode"] == "single"
    assert normalized["mandatory_findings"] == 1
    assert normalized["blast_radius"] == 2
    assert normalized["audit_intent"] == "assessment-only"


def test_revise_plan_binds_late_facts_to_parent_plan() -> None:
    first = evaluate_manifest(MANIFEST, {
        "mode": "standard",
        "target_tier": 2,
        "context_mode": "single",
        "mandatory_findings": 0,
        "blast_radius": 1,
        "write_chain_components": 1,
        "declarations": {"self_audit": "no", "ai_executor": "no", "async_worker": "no", "safety_critical": "no", "financial_path": "no"},
    })
    revised = revise_plan(MANIFEST, first, {"facts": {"blast_radius": 4}}, reason="structural probe discovered wider impact")
    assert revised["plan_revision"] == first["plan_revision"] + 1
    assert revised["parent_plan_id"] == first["plan_id"]
    assert revised["context"]["blast_radius"] == 4
    assert revised["plan_id"] != first["plan_id"]


def test_v2_replan_activates_hybrid_verification_from_late_finding() -> None:
    context = {
        "schema_version": "2.0.0",
        "goal": "Assess the release boundary.",
        "decision_owner": "platform-owner",
        "stakeholder": "platform-team",
        "subject": {"kind": "repository", "locator": "workspace:/repo", "digest": "a" * 64, "tree_digest": "b" * 64},
        "scope": {"included_paths": ["src"], "excluded_paths": []},
        "audit_stage": "code",
        "legacy_state": "no",
        "organization_scope": "single-team",
        "execution_profile": "standard",
        "audit_intent": "assessment-only",
        "pii": "no",
        "compliance": [],
        "multi_tenant": "no",
        "post_incident": "no",
        "language": "en",
        "organization_size": "small",
        "test_availability": "adequate",
        "declarations": {"self_audit": "no", "ai_executor": "no"},
        "finding_ledger": [],
        "facts": {"blast_radius": 1, "write_chain_components": 1},
        "amendments": [],
    }
    first = evaluate_manifest(MANIFEST, context)
    assert next(gate for gate in first["gates"] if gate["id"] == "HG-HV")["activation_state"] == "inactive"
    revised = revise_plan(
        MANIFEST,
        first,
        {"finding_ledger": [{"id": "F-1", "priority": "mandatory", "state": "open"}]},
        reason="generation discovered a mandatory finding",
    )
    assert revised["context"]["mandatory_findings"] == 1
    assert next(gate for gate in revised["gates"] if gate["id"] == "HG-HV")["activation_state"] == "active"


def test_plan_session_root_changes_when_subject_snapshot_changes() -> None:
    first_context = {
        "schema_version": "2.0.0",
        "goal": "Assess the release boundary.",
        "decision_owner": "platform-owner",
        "stakeholder": "platform-team",
        "subject": {"kind": "repository", "locator": "workspace:/repo", "digest": "a" * 64, "tree_digest": "b" * 64},
        "scope": {"included_paths": ["src"], "excluded_paths": []},
        "audit_stage": "code",
        "legacy_state": "no",
        "organization_scope": "single-team",
        "execution_profile": "standard",
        "audit_intent": "assessment-only",
        "pii": "no",
        "compliance": [],
        "multi_tenant": "no",
        "post_incident": "no",
        "language": "en",
        "organization_size": "small",
        "test_availability": "adequate",
        "declarations": {"self_audit": "no"},
        "finding_ledger": [],
        "facts": {"blast_radius": 1, "write_chain_components": 1},
        "amendments": [],
    }
    second_context = dict(first_context, subject={**first_context["subject"], "digest": "b" * 64})
    first = evaluate_manifest(MANIFEST, first_context)
    second = evaluate_manifest(MANIFEST, second_context)
    assert first["session_root"] != second["session_root"]
    assert first["plan_id"] != second["plan_id"]


def test_replan_cannot_silently_deactivate_an_active_gate() -> None:
    first = evaluate_manifest(MANIFEST, {
        "mode": "standard",
        "target_tier": 2,
        "context_mode": "single",
        "mandatory_findings": 0,
        "blast_radius": 1,
        "write_chain_components": 1,
        "declarations": {"self_audit": "no", "ai_executor": "no", "async_worker": "no", "safety_critical": "no", "financial_path": "no"},
    })
    with pytest.raises(PlanIntegrityError, match="deactivate"):
        revise_plan(MANIFEST, first, {"mode": "fast"}, reason="late profile change")


def test_replan_finding_ledger_is_append_only() -> None:
    context = {
        "schema_version": "2.0.0",
        "goal": "Assess the release boundary.",
        "decision_owner": "platform-owner",
        "stakeholder": "platform-team",
        "subject": {"kind": "repository", "locator": "workspace:/repo", "digest": "a" * 64, "tree_digest": "b" * 64},
        "scope": {"included_paths": ["src"], "excluded_paths": []},
        "audit_stage": "code",
        "legacy_state": "no",
        "organization_scope": "single-team",
        "execution_profile": "standard",
        "audit_intent": "assessment-only",
        "pii": "no",
        "compliance": [],
        "multi_tenant": "no",
        "post_incident": "no",
        "language": "en",
        "organization_size": "small",
        "test_availability": "adequate",
        "declarations": {"self_audit": "no"},
        "finding_ledger": [{"id": "F-1", "priority": "mandatory", "state": "open"}],
        "facts": {"blast_radius": 1, "write_chain_components": 1},
        "amendments": [],
    }
    first = evaluate_manifest(MANIFEST, context)
    revised = revise_plan(
        MANIFEST,
        first,
        {"finding_ledger": [{"id": "F-2", "priority": "mandatory", "state": "open"}]},
        reason="another mandatory finding was discovered",
    )
    assert [item["id"] for item in revised["context"]["finding_ledger"]] == ["F-1", "F-2"]
    assert revised["context"]["mandatory_findings"] == 2

    with pytest.raises(PlanIntegrityError, match="ledger"):
        revise_plan(
            MANIFEST,
            first,
            {"finding_ledger": [{"id": "F-1", "priority": "normal", "state": "open"}]},
            reason="attempt to rewrite finding priority",
        )
