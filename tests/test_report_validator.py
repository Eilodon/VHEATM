from datetime import UTC, datetime

from vheatm_control.lifecycle import AuditLifecycle
from vheatm_control.provenance import ProvenanceRegistry, build_claim_record, build_source_record
from vheatm_control.report_validator import canonical_digest, report_subject_digest, validate_report_semantics

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
        taint_state="validated",
        captured_at="2026-07-31T00:00:00Z",
    )
    claim = build_claim_record(
        text="The unsafe path was removed.",
        epistemic_status="verified",
        confidence=0.99,
        source_refs=[source["id"]],
        evidence_kind="code",
    )
    registry = ProvenanceRegistry()
    registry.add_source(source)
    registry.add_claim(claim)
    plan = {
        "schema_version": "1.0.0",
        "framework_version": "17.0.0-dev.1",
        "context": {"mode": "standard", "target_tier": 2, "declarations": {"self_audit": "no"}},
        "summary": {"active": 1, "inactive": 2, "unknown": 0, "total": 3, "completion_blocked": False},
        "gates": [
            {"id": "HG-A", "layer": "core", "phase": "P", "activation": "always", "activation_state": "active", "unknown_references": [], "reason": "true"},
            {"id": "HG-B", "layer": "triggered", "phase": "G", "activation": "mode == full", "activation_state": "inactive", "unknown_references": [], "reason": "false"},
            {"id": "HG-C", "layer": "meta", "phase": "M", "activation": "self_audit == yes", "activation_state": "inactive", "unknown_references": [], "reason": "false"},
        ],
    }
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
    value["findings"][0]["evidence"][0]["claim_id"] = "CLM-AAAAAAAAAAAAAAAA"
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
