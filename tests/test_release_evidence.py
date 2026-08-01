from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

from vheatm_control.evaluation import evaluate_release_gates
from vheatm_control.qualification import (
    build_private_time_slice_manifest,
    build_qualification_evidence,
    sign_manifest,
    sign_qualification_evidence,
    verify_manifest,
)
from vheatm_control.serialization import load_json
from vheatm_control.supply_chain import (
    build_supply_chain_attestation,
    build_vulnerability_scan,
    expected_provenance_statement_id,
    sign_provenance_statement,
    sign_supply_chain_attestation,
    sign_vulnerability_scan,
    verify_vulnerability_scan,
)


ROOT = Path(__file__).resolve().parents[1]


def test_release_gates_keep_missing_evidence_unknown_and_block_ga() -> None:
    report = evaluate_release_gates("17.0.0-dev.1", {"metrics": {}})
    assert report["summary"]["unknown"] == 16
    assert report["summary"]["ga_eligible"] is False
    Draft202012Validator(load_json((ROOT / "schemas" / "release-gate-report.schema.json").read_text())).validate(report)


def test_release_gates_ignore_unverified_metric_shortcuts() -> None:
    metrics = {
        "mutation_rejection_rate": 1, "route_equivalence_rate": 1, "determinism_runs": 1000, "plan_digest_stability_rate": 1, "selection_digest_stability_rate": 1,
        "false_inactive_count": 0, "unknown_diagnostic_rate": 1, "forgery_rejection_rate": 1, "unrelated_pass_claims": 0,
        "high_critical_lineage_rate": 1, "high_critical_proof_or_judge_rate": 1, "critical_recall_lower_ci": 0.95, "critical_miss_count": 0,
        "calibration_regression_margin": 0, "high_critical_autoclose_count": 0, "judge_kappa_lower_ci": 0.8, "order_consistency_rate": 0.98, "self_judge_final_authority_count": 0,
        "critical_unsafe_action_count": 0, "critical_family_asr_upper_ci": 0.009, "unauthorized_block_rate": 1, "hard_stop_p99_seconds": 2,
        "duplicate_effect_count": 0, "resume_digest_match_rate": 1, "planner_router_p95_ms": 499, "peak_disclosure_ratio": 0.75,
        "secret_pii_leakage_count": 0, "trace_completeness_rate": 0.999, "signed_release": True, "provenance_verified": True, "canonical_sbom": True,
        "dependencies_locked": True, "critical_exploitable_cve_count": 0, "experimental_selected_count": 0, "p0_p1_open_count": 0,
        "scope_limitations_present": True, "unknown_risks_present": True, "certification_claims_absent": True,
    }
    report = evaluate_release_gates("17.0.0-dev.1", {"metrics": metrics}, evaluated_at="2026-08-01T00:00:00Z")
    assert report["summary"]["ga_eligible"] is False
    assert report["summary"]["unknown"] == 16


def test_release_gates_require_cryptographically_verified_qualification_and_supply_chain() -> None:
    key = Ed25519PrivateKey.generate()
    manifest = build_private_time_slice_manifest(
        framework_version="17.0.0-dev.1",
        private_locator="vault://qualification/v17/release-test",
        time_slice_start="2026-07-01T00:00:00Z",
        time_slice_end="2026-08-01T00:00:00Z",
        case_digests=["a" * 64],
        generated_at="2026-08-01T00:00:00Z",
    )
    signed_manifest = sign_manifest(manifest, private_key=key, key_id="qualification-key")
    verified_manifest = verify_manifest(signed_manifest, public_key=key.public_key(), key_id="qualification-key")
    values = {
        "mutation_rejection_rate": 1, "route_equivalence_rate": 1, "determinism_runs": 1000,
        "plan_digest_stability_rate": 1, "selection_digest_stability_rate": 1, "false_inactive_count": 0,
        "unknown_diagnostic_rate": 1, "forgery_rejection_rate": 1, "unrelated_pass_claims": 0,
        "high_critical_lineage_rate": 1, "high_critical_proof_or_judge_rate": 1, "critical_recall_lower_ci": 0.96,
        "critical_miss_count": 0, "calibration_regression_margin": 0, "high_critical_autoclose_count": 0,
        "judge_kappa_lower_ci": 0.81, "order_consistency_rate": 0.99, "self_judge_final_authority_count": 0,
        "critical_unsafe_action_count": 0, "critical_family_asr_upper_ci": 0.009, "unauthorized_block_rate": 1,
        "hard_stop_p99_seconds": 1.5, "duplicate_effect_count": 0, "resume_digest_match_rate": 1,
        "planner_router_p95_ms": 400, "peak_disclosure_ratio": 0.70, "secret_pii_leakage_count": 0,
        "trace_completeness_rate": 0.999, "experimental_selected_count": 0, "p0_p1_open_count": 0,
        "scope_limitations_present": True, "unknown_risks_present": True, "certification_claims_absent": True,
    }
    measurements = [
        {"metric": name, "value": value, "sample_count": 1000, "confidence_lower": float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 1.0, "method_digest": "c" * 64, "evidence_refs": [f"EV-{name}"]}
        for name, value in values.items()
    ]
    qualification = build_qualification_evidence(
        manifest=verified_manifest,
        evaluator_id="eval:v17",
        evaluator_version="1.0.0",
        independent_judge_id="judge:v17",
        measurements=measurements,
        generated_at="2026-08-01T00:00:00Z",
    )

    base_attestation = build_supply_chain_attestation(ROOT, generated_at="2026-08-01T00:00:00Z")
    scan = build_vulnerability_scan(
        scanner_id="scanner:v17",
        scanner_version="1.0.0",
        target_bundle_root=base_attestation["bundle_root"],
        target_lock_digest=base_attestation["dependency_lock_digest"],
        findings=[],
        generated_at="2026-08-01T00:00:00Z",
    )
    verified_scan = verify_vulnerability_scan(
        sign_vulnerability_scan(scan, private_key=key, key_id="vulnerability-key"),
        public_key=key.public_key(),
        bundle_root=base_attestation["bundle_root"],
        lock_digest=base_attestation["dependency_lock_digest"],
        key_id="vulnerability-key",
    )
    attestation = sign_supply_chain_attestation(
        build_supply_chain_attestation(ROOT, generated_at="2026-08-01T00:00:00Z", vulnerability_scan=verified_scan),
        private_key=key,
        key_id="supply-chain-key",
    )
    provenance = {
        "schema_version": "1.0.0",
        "bundle_root": attestation["bundle_root"],
        "sbom_digest": attestation["sbom_digest"],
        "builder_id": "builder:test",
        "build_type": "test-build",
        "verified": True,
        "signature_algorithm": "ed25519",
        "signature_key_id": "provenance-key",
        "signature_value": None,
        "generated_at": "2026-08-01T00:00:00Z",
    }
    provenance["statement_id"] = expected_provenance_statement_id(provenance)
    evidence = {
        "qualification_manifest": signed_manifest,
        "qualification_evidence": sign_qualification_evidence(qualification, private_key=key, key_id="qualification-key"),
        "supply_chain_attestation": attestation,
        "vulnerability_scan": sign_vulnerability_scan(scan, private_key=key, key_id="vulnerability-key"),
        "provenance_statement": sign_provenance_statement(provenance, private_key=key, key_id="provenance-key"),
    }
    report = evaluate_release_gates(
        "17.0.0-dev.1",
        evidence,
        evaluated_at="2026-08-01T00:00:00Z",
        expected_bundle_root=base_attestation["bundle_root"],
        verification_keys={"qualification": key.public_key(), "supply_chain": key.public_key(), "vulnerability": key.public_key(), "provenance": key.public_key()},
        verification_key_ids={"qualification": "qualification-key", "supply_chain": "supply-chain-key", "vulnerability": "vulnerability-key", "provenance": "provenance-key"},
    )
    assert report["summary"] == {"pass": 16, "fail": 0, "unknown": 0, "ga_eligible": True}


def test_supply_chain_evidence_is_canonical_and_locked_but_not_signed_yet(tmp_path) -> None:
    attestation = build_supply_chain_attestation(ROOT, generated_at="2026-08-01T00:00:00Z")
    schema = load_json((ROOT / "schemas" / "supply-chain-attestation.schema.json").read_text())
    Draft202012Validator(schema).validate(attestation)
    assert attestation["signed_release"] is False
    assert attestation["dependency_lock_present"] is True
    assert attestation["dependency_lock_path"] == "uv.lock"
    assert attestation["sbom"]


def test_verified_typed_evidence_overrides_contradictory_metric_shortcuts() -> None:
    report = evaluate_release_gates(
        "17.0.0-dev.1",
        {
            "metrics": {"signed_release": True, "provenance_verified": True, "critical_exploitable_cve_count": 0},
            "supply_chain_attestation": {
                "verification_state": "partial",
                "signed_release": False,
                "provenance_verified": False,
            },
        },
    )
    rg13 = next(item for item in report["gates"] if item["gate_id"] == "RG-13")
    assert rg13["status"] == "fail"
