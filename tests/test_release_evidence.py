from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from vheatm_control.evaluation import evaluate_release_gates
from vheatm_control.serialization import load_json
from vheatm_control.supply_chain import build_supply_chain_attestation


ROOT = Path(__file__).resolve().parents[1]


def test_release_gates_keep_missing_evidence_unknown_and_block_ga() -> None:
    report = evaluate_release_gates("17.0.0-dev.1", {"metrics": {}})
    assert report["summary"]["unknown"] == 16
    assert report["summary"]["ga_eligible"] is False
    Draft202012Validator(load_json((ROOT / "schemas" / "release-gate-report.schema.json").read_text())).validate(report)


def test_release_gates_can_derive_eligibility_only_from_all_frozen_metrics() -> None:
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
    assert report["summary"] == {"pass": 16, "fail": 0, "unknown": 0, "ga_eligible": True}


def test_supply_chain_evidence_is_canonical_and_locked_but_not_signed_yet(tmp_path) -> None:
    attestation = build_supply_chain_attestation(ROOT, generated_at="2026-08-01T00:00:00Z")
    schema = load_json((ROOT / "schemas" / "supply-chain-attestation.schema.json").read_text())
    Draft202012Validator(schema).validate(attestation)
    assert attestation["signed_release"] is False
    assert attestation["dependency_lock_present"] is True
    assert attestation["dependency_lock_path"] == "uv.lock"
    assert attestation["sbom"]
