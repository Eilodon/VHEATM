from datetime import UTC, datetime

from vheatm_control.lifecycle import AuditLifecycle
from vheatm_control.evaluator import evaluate_manifest
from vheatm_control.execution import build_artifact_envelope, expected_module_run_id, selection_digest
from vheatm_control.provenance import (
    ProvenanceRegistry,
    build_claim_record,
    build_source_record,
    build_validation_receipt,
    expected_claim_id,
)
from vheatm_control.report_validator import (
    canonical_digest,
    record_collection_digest,
    report_subject_digest,
    validate_report_semantics,
)

GATE_IDS = ["HG-A", "HG-B", "HG-C"]
MANIFEST = {
    "framework": {"version": "17.0.0-dev.1"},
    "gates": {
        "items": [
            {"id": "HG-A", "layer": "core", "phase": "P", "activation": "always"},
            {"id": "HG-B", "layer": "triggered", "phase": "G", "activation": "mode == full"},
            {"id": "HG-C", "layer": "meta", "phase": "M", "activation": "self_audit == yes"},
        ]
    },
}
POLICY = {"policy_id": "vheatm-runtime-boundaries", "tools": {"default": "deny"}}
NOW = datetime(2026, 7, 31, 15, 0, tzinfo=UTC)


def report() -> dict:
    source = build_source_record(
        source_type="code",
        locator="src/app.py:10-20",
        content="unsafe path",
        trust_zone="artifact_content",
        taint_state="tainted",
        captured_at="2026-07-31T00:00:00Z",
    )
    receipt = build_validation_receipt(
        source_refs=[source["id"]],
        validator="test-validator",
        method="direct-evidence-review",
        input_digest=source["digest"]["value"],
        validated_at="2026-07-31T00:00:00Z",
    )
    claim = build_claim_record(
        text="The unsafe path was removed.",
        epistemic_status="verified",
        confidence=0.99,
        source_refs=[source["id"]],
        evidence_kind="code",
        validation_receipt_refs=[receipt["id"]],
        gate_trace=["HG-A"],
    )
    registry = ProvenanceRegistry()
    registry.add_source(source)
    registry.add_validation_receipt(receipt)
    registry.add_claim(claim)
    run_id = "RUN-pending"
    module_id = "MOD-TEST"
    output_contract = {
        "id": "module_decision",
        "required": True,
        "description": "Decision-bearing module result with gate trace and evidence references.",
        "schema_ref": "https://vheatm.dev/schemas/module-decision.schema.json",
        "cardinality": "one",
        "required_when": "always",
    }
    decision = {
        "module_id": module_id,
        "module_run_id": run_id,
        "gate_trace": ["HG-A"],
        "state": "pass",
        "evidence_refs": [claim["id"]],
    }
    provisional_run = {
        "id": "",
        "module_id": module_id,
        "module_digest": "1" * 64,
        "instruction_digest": "2" * 64,
        "status": "completed",
        "started_at": "2026-07-31T13:00:00Z",
        "finished_at": "2026-07-31T13:00:01Z",
        "input_artifact_refs": [],
        "output_artifact_refs": [],
        "validation_receipt_refs": [receipt["id"]],
        "result": decision,
    }
    run_id = expected_module_run_id(provisional_run)
    decision["module_run_id"] = run_id
    artifact = build_artifact_envelope(
        producer_module_id=module_id,
        producer_run_id=run_id,
        output_id="module_decision",
        schema_ref=output_contract["schema_ref"],
        payload=decision,
        validation_receipt_refs=[receipt["id"]],
        taint_state="validated",
    )
    module_selection = {
        "schema_version": "1.0.0",
        "framework_version": "17.0.0-dev.1",
        "registry_root": "0" * 64,
        "summary": {
            "selected": 1,
            "unselected": 0,
            "unresolved": 0,
            "estimated_tokens": 1,
            "hard_token_budget": 4096,
            "budget_exceeded": False,
            "completion_blocked": False,
        },
        "selected_modules": [{
            "id": module_id,
            "module_sha256": "1" * 64,
            "instruction_sha256": "2" * 64,
            "gate_coverage": ["HG-A"],
            "phase_coverage": ["P"],
            "output_contracts": [output_contract],
        }],
        "unselected_modules": [],
        "unresolved_modules": [],
        "unknown_gates": [],
        "conflicts": [],
    }
    module_run = {
        "id": run_id,
        "module_id": module_id,
        "module_digest": "1" * 64,
        "instruction_digest": "2" * 64,
        "status": "completed",
        "started_at": "2026-07-31T13:00:00Z",
        "finished_at": "2026-07-31T13:00:01Z",
        "input_artifact_refs": [],
        "output_artifact_refs": [artifact["id"]],
        "validation_receipt_refs": [receipt["id"]],
        "result": decision,
    }
    context = {"mode": "standard", "target_tier": 2, "declarations": {"self_audit": "no"}}
    plan = evaluate_manifest(MANIFEST, context)
    lifecycle = AuditLifecycle("AUD-REPORT-1")
    for state in ["context_validated", "planned", "running", "complete", "attested"]:
        lifecycle.transition(state, actor="test", reason=f"advance to {state}", occurred_at="2026-07-31T13:00:00Z")
    value = {
        "framework_version": "17.0.0-dev.1",
        "mode": "standard",
        "target_tier": 2,
        "cycle_status": "complete",
        "lifecycle_state": "attested",
        "lifecycle": lifecycle.to_document(),
        "declarations": {"self_audit": "no"},
        "activation_plan": plan,
        "provenance": registry.to_document(),
        "execution": {
            "plan_id": plan["plan_id"],
            "selection_digest": selection_digest(module_selection),
            "module_selection": module_selection,
            "module_runs": [module_run],
            "module_runs_digest": record_collection_digest([module_run]),
            "artifacts": [artifact],
            "artifacts_digest": record_collection_digest([artifact]),
            "validation_receipts": [receipt],
            "validation_receipts_digest": record_collection_digest([receipt]),
        },
        "gate_results": [
            {"gate": "HG-A", "state": "pass", "reason": "evidence verified", "evidence_refs": [claim["id"]]},
            {"gate": "HG-B", "state": "not_applicable", "reason": "inactive"},
            {"gate": "HG-C", "state": "not_applicable", "reason": "inactive"},
        ],
        "findings": [
            {
                "id": "F-1",
                "priority": "mandatory",
                "epistemic_status": "verified",
                "disposition": {"state": "remediated", "reason": "fixed and verified"},
                "gate_trace": ["HG-A"],
                "evidence": [
                    {
                        "claim": "The unsafe path was removed.",
                        "verified": True,
                        "claim_id": claim["id"],
                        "source_refs": [source["id"]],
                    }
                ],
            }
        ],
        "attestation": {
            "executor": "test",
            "validated_at": "2026-07-31T14:00:00Z",
            "expires_at": "2026-08-01T14:00:00Z",
            "manifest_digest": canonical_digest(MANIFEST),
            "policy_digest": canonical_digest(POLICY),
            "subject_digest": "pending",
            "limitations": [],
        },
    }
    value["attestation"]["subject_digest"] = report_subject_digest(value)
    return value


def test_complete_attested_report_passes_semantic_validation() -> None:
    assert validate_report_semantics(manifest=MANIFEST, policy=POLICY, report=report(), now=NOW) == []


def test_verified_claim_must_be_bound_to_the_gate_it_supports() -> None:
    value = report()
    claim = dict(value["provenance"]["claims"][0])
    claim["gate_trace"] = ["HG-B"]
    claim["id"] = expected_claim_id(claim)
    registry = ProvenanceRegistry()
    registry.add_source(value["provenance"]["sources"][0])
    registry.add_validation_receipt(value["provenance"]["validation_receipts"][0])
    registry.add_claim(claim)
    value["provenance"] = registry.to_document()
    value["gate_results"][0]["evidence_refs"] = [claim["id"]]
    value["execution"]["module_runs"][0]["result"]["evidence_refs"] = [claim["id"]]
    value["execution"]["artifacts"][0]["payload"]["evidence_refs"] = [claim["id"]]
    value["findings"][0]["evidence"][0]["claim_id"] = claim["id"]
    value["attestation"]["subject_digest"] = report_subject_digest(value)

    issues = validate_report_semantics(manifest=MANIFEST, policy=POLICY, report=value, now=NOW)

    assert any("not bound to gate HG-A" in issue.message for issue in issues)


def test_verified_finding_claim_must_cover_every_traced_gate() -> None:
    value = report()
    value["findings"][0]["gate_trace"] = ["HG-A", "HG-B"]
    value["attestation"]["subject_digest"] = report_subject_digest(value)

    issues = validate_report_semantics(manifest=MANIFEST, policy=POLICY, report=value, now=NOW)

    assert any("not bound to gate HG-B" in issue.message for issue in issues)


def test_report_rejects_claim_trace_for_unknown_gate() -> None:
    value = report()
    source = value["provenance"]["sources"][0]
    receipt = value["provenance"]["validation_receipts"][0]
    unknown_claim = build_claim_record(
        text="Evidence for a gate outside this manifest.",
        epistemic_status="verified",
        confidence=0.9,
        source_refs=[source["id"]],
        evidence_kind="document",
        validation_receipt_refs=[receipt["id"]],
        gate_trace=["HG-UNKNOWN"],
    )
    registry = ProvenanceRegistry(value["provenance"])
    registry.add_claim(unknown_claim)
    value["provenance"] = registry.to_document()
    value["attestation"]["subject_digest"] = report_subject_digest(value)

    issues = validate_report_semantics(manifest=MANIFEST, policy=POLICY, report=value, now=NOW)

    assert any("unknown gates" in issue.message for issue in issues)


def test_passing_gate_cannot_use_direct_trusted_source_evidence() -> None:
    value = report()
    trusted_source = build_source_record(
        source_type="document",
        locator="policy://trusted-evidence",
        content="canonical policy evidence",
        trust_zone="system_policy",
        taint_state="validated",
        captured_at="2026-07-31T00:00:00Z",
    )
    registry = ProvenanceRegistry(value["provenance"])
    registry.add_source(trusted_source)
    value["provenance"] = registry.to_document()
    value["gate_results"][0]["evidence_refs"] = [trusted_source["id"]]
    value["execution"]["module_runs"][0]["result"]["evidence_refs"] = [trusted_source["id"]]
    value["execution"]["artifacts"][0]["payload"]["evidence_refs"] = [trusted_source["id"]]
    value["attestation"]["subject_digest"] = report_subject_digest(value)

    issues = validate_report_semantics(manifest=MANIFEST, policy=POLICY, report=value, now=NOW)

    assert any("direct source evidence" in issue.message for issue in issues)


def test_missing_gate_result_cannot_claim_complete() -> None:
    value = report()
    value["gate_results"].pop()
    issues = validate_report_semantics(manifest=MANIFEST, policy=POLICY, report=value, now=NOW)
    assert any(issue.source == "gate_results" for issue in issues)
    assert any(issue.source == "cycle_status" for issue in issues)


def test_inactive_gate_cannot_be_marked_pass() -> None:
    value = report()
    value["gate_results"][1]["state"] = "pass"
    issues = validate_report_semantics(manifest=MANIFEST, policy=POLICY, report=value, now=NOW)
    assert any("inactive gates" in issue.message for issue in issues)


def test_verified_evidence_cannot_bypass_registry() -> None:
    value = report()
    value["findings"][0]["evidence"][0]["claim_id"] = "CLM-" + "A" * 64
    issues = validate_report_semantics(manifest=MANIFEST, policy=POLICY, report=value, now=NOW)
    assert any("unknown claim_id" in issue.message for issue in issues)


def test_attestation_is_bound_to_manifest_and_policy() -> None:
    value = report()
    value["attestation"]["manifest_digest"] = "0" * 64
    value["attestation"]["policy_digest"] = "1" * 64
    issues = validate_report_semantics(manifest=MANIFEST, policy=POLICY, report=value, now=NOW)
    assert sum(issue.source == "attestation" for issue in issues) >= 2


def test_forged_lifecycle_event_is_rejected() -> None:
    value = report()
    value["lifecycle"]["events"][0]["reason"] = "silently changed"
    issues = validate_report_semantics(manifest=MANIFEST, policy=POLICY, report=value, now=NOW)
    assert any(issue.source == "lifecycle" and "id mismatch" in issue.message for issue in issues)


def test_passing_gate_requires_verified_evidence_reference() -> None:
    value = report()
    value["gate_results"][0].pop("evidence_refs")
    value["attestation"]["subject_digest"] = report_subject_digest(value)
    issues = validate_report_semantics(manifest=MANIFEST, policy=POLICY, report=value, now=NOW)
    assert any(issue.source == "gate_results.HG-A" and "evidence_refs" in issue.message for issue in issues)


def test_attestation_subject_detects_report_mutation() -> None:
    value = report()
    value["gate_results"][0]["reason"] = "mutated after attestation"
    issues = validate_report_semantics(manifest=MANIFEST, policy=POLICY, report=value, now=NOW)
    assert any(issue.source == "attestation" and "subject_digest" in issue.message for issue in issues)


def test_report_rejects_tampered_activation_state_after_recompute() -> None:
    value = report()
    value["activation_plan"]["gates"][0]["activation_state"] = "inactive"
    value["attestation"]["subject_digest"] = report_subject_digest(value)
    issues = validate_report_semantics(manifest=MANIFEST, policy=POLICY, report=value, now=NOW)
    assert any("recomputed" in issue.message for issue in issues)


def test_verified_evidence_requires_explicit_validation_receipt() -> None:
    value = report()
    source = value["provenance"]["sources"][0]
    unvalidated_claim = build_claim_record(
        text="The unsafe path was removed.",
        epistemic_status="verified",
        confidence=0.99,
        source_refs=[source["id"]],
        evidence_kind="code",
    )
    registry = ProvenanceRegistry()
    registry.add_source(source)
    registry.add_claim(unvalidated_claim)
    value["provenance"] = registry.to_document()
    value["gate_results"][0]["evidence_refs"] = [unvalidated_claim["id"]]
    value["findings"][0]["evidence"][0]["claim_id"] = unvalidated_claim["id"]
    value["attestation"]["subject_digest"] = report_subject_digest(value)

    issues = validate_report_semantics(manifest=MANIFEST, policy=POLICY, report=value, now=NOW)
    assert any("validation receipt" in issue.message for issue in issues)


def test_report_rejects_caller_supplied_pass_without_valid_module_run() -> None:
    value = report()
    value["execution"]["module_runs"][0]["output_artifact_refs"] = []
    value["attestation"]["subject_digest"] = report_subject_digest(value)
    issues = validate_report_semantics(manifest=MANIFEST, policy=POLICY, report=value, now=NOW)
    assert any(issue.source == "execution" or "derived execution state" in issue.message for issue in issues)


def test_report_execution_digests_bind_typed_records() -> None:
    value = report()
    value["execution"]["artifacts"][0]["payload"]["state"] = "fail"
    value["attestation"]["subject_digest"] = report_subject_digest(value)
    issues = validate_report_semantics(manifest=MANIFEST, policy=POLICY, report=value, now=NOW)
    assert any(issue.source == "execution.artifacts_digest" for issue in issues)
