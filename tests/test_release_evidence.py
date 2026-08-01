from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator

from vheatm_control.bundle import build_bundle
from vheatm_control.evaluation import EvaluationError, evaluate_release_gates
from vheatm_control.host_attestation import build_host_attestation, sign_host_attestation
from vheatm_control.host_qualification import expected_host_qualification_run_id
from vheatm_control.judge import build_blind_packet, expected_verdict_id, sign_verdict
from vheatm_control.qualification import (
    build_private_time_slice_manifest,
    build_qualification_evidence,
    expected_qualification_evidence_id,
    sign_manifest,
    sign_qualification_evidence,
    verify_manifest,
)
from vheatm_control.serialization import load_json
from vheatm_control.qualification_private import expected_private_case_digest, expected_private_corpus_digest, expected_private_corpus_id, ingest_private_corpus
from vheatm_control.qualification_methods import expected_method_digest
from vheatm_control.supply_chain import (
    build_supply_chain_attestation,
    build_vulnerability_scan,
    expected_attestation_id,
    expected_provenance_statement_id,
    sign_provenance_statement,
    sign_supply_chain_attestation,
    sign_vulnerability_scan,
    verify_vulnerability_scan,
)
from vheatm_control.trust_registry import build_trust_registry, sign_trust_registry


ROOT = Path(__file__).resolve().parents[1]
BUNDLE_ROOT = build_bundle(ROOT)["bundle_root"]


def _method_digest(metric: str) -> str:
    return expected_method_digest(metric, root=ROOT)


def _trusted_registry_kwargs(
    verification_keys: dict[str, Ed25519PublicKey],
    verification_key_ids: dict[str, str],
    bundle_root: str,
) -> dict[str, object]:
    authority = Ed25519PrivateKey.generate()
    registry = build_trust_registry(
        framework_version="17.0.0-dev.1",
        bundle_root=bundle_root,
        authority_id="test-release-authority:v17",
        authority_public_key=authority.public_key(),
        authority_key_id="test-release-registry-key",
        role_keys={role: (key, verification_key_ids[role]) for role, key in verification_keys.items()},
        valid_from="2026-08-01T00:00:00Z",
        valid_until="2026-08-20T00:00:00Z",
        generated_at="2026-08-01T00:00:00Z",
    )
    return {
        "trusted_key_registry": sign_trust_registry(registry, private_key=authority, key_id="test-release-registry-key"),
        "trust_registry_authority_key": authority.public_key(),
        "trust_registry_authority_key_id": "test-release-registry-key",
    }


def test_release_evaluator_rejects_non_rfc3339_evaluated_at() -> None:
    with pytest.raises(EvaluationError, match="evaluated_at"):
        evaluate_release_gates("17.0.0-dev.1", {"metrics": {}}, evaluated_at="not-a-timestamp")


def test_release_report_id_binds_evaluation_timestamp() -> None:
    first = evaluate_release_gates("17.0.0-dev.1", {"metrics": {}}, evaluated_at="2026-08-01T00:00:00Z")
    second = evaluate_release_gates("17.0.0-dev.1", {"metrics": {}}, evaluated_at="2026-08-01T00:00:01Z")
    assert first["report_id"] != second["report_id"]


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


def _release_private_fixture(tmp_path: Path, key: Ed25519PrivateKey, *, count: int = 300) -> tuple[dict, dict]:
    cases = []
    for index in range(count):
        case = {"case_id": f"PQC-CASE-RELEASE-{index:03d}", "captured_at": "2026-07-15T00:00:00Z", "payload": {"family": "release", "label": "yes", "index": index}}
        case["case_digest"] = expected_private_case_digest(case)
        cases.append(case)
    corpus = {"schema_version": "1.0.0", "corpus_id": "PQC-" + "0" * 64, "framework_version": "17.0.0-dev.1", "visibility": "private", "time_slice": {"start": "2026-07-01T00:00:00Z", "end": "2026-08-01T00:00:00Z"}, "cases": cases}
    corpus["corpus_digest"] = expected_private_corpus_digest(corpus)
    corpus["corpus_id"] = expected_private_corpus_id(corpus)
    corpus_path = tmp_path / "private-release-corpus.json"
    corpus_path.write_text(json.dumps(corpus), encoding="utf-8")
    manifest = build_private_time_slice_manifest(framework_version="17.0.0-dev.1", private_locator=str(corpus_path), time_slice_start=corpus["time_slice"]["start"], time_slice_end=corpus["time_slice"]["end"], case_digests=[case["case_digest"] for case in cases], generated_at="2026-08-01T00:00:00Z")
    signed_manifest = sign_manifest(manifest, private_key=key, key_id="qualification-key")
    receipt = ingest_private_corpus(signed_manifest, corpus_path=corpus_path, public_key=key.public_key(), key_id="qualification-key", verified_at="2026-08-01T00:00:00Z")
    return signed_manifest, receipt


def _release_judge_fixture(receipt: dict, *, case_refs: list[str] | None = None, signing_key: Ed25519PrivateKey | None = None) -> tuple[dict, dict, Ed25519PrivateKey]:
    selected_case_refs = case_refs if case_refs is not None else list(receipt["case_refs"])
    packet = build_blind_packet(
        source_session_root="a" * 64,
        judge_context_root="b" * 64,
        origin_provider_id="origin.provider",
        origin_model_id="origin-model",
        judge_provider_id="judge.provider",
        judge_model_id="judge-model",
        config_digest="c" * 64,
        rubric_digest="d" * 64,
        order_seed="e" * 64,
        items=[{"item_id": case_ref, "text": "Evaluate the private qualification case."} for case_ref in selected_case_refs],
    )
    verdict = {
        "schema_version": "1.0.0",
        "packet_id": packet["packet_id"],
        "request_id": packet["request_id"],
        "judge_provider_id": packet["judge_provider_id"],
        "judge_model_id": packet["judge_model_id"],
        "config_digest": packet["config_digest"],
        "order_digest": packet["order_digest"],
        "status": "complete",
        "epistemic_status": "independent_candidate",
        "decisions": [{"item_id": item["item_id"], "label": "yes", "confidence": 0.9} for item in packet["items"]],
        "generated_at": "2026-08-01T00:00:00Z",
    }
    verdict["verdict_id"] = expected_verdict_id(verdict)
    judge_key = signing_key or Ed25519PrivateKey.generate()
    if signing_key is not None:
        verdict = sign_verdict(verdict, private_key=judge_key, key_id="judge-key")
    return packet, verdict, judge_key


def _release_host_fixture() -> tuple[dict, dict, Ed25519PrivateKey]:
    observation = {
        "observation_id": "HOB-" + "A" * 64,
        "sample_index": 1,
        "kind": "hard_stop_timeout",
        "status": "observed",
        "elapsed_seconds": 0.2,
        "sandbox_run_id": "SBR-" + "B" * 64,
        "controls": ["timeout:enforced"],
        "details": {
            "reason": "timeout enforcement observed",
            "sandbox_status": "blocked",
            "exit_code": None,
            "stderr_digest": "c" * 64,
            "timeout_budget_seconds": 0.1,
        },
    }
    run: dict[str, object] = {
        "schema_version": "1.0.0",
        "framework_version": "17.0.0-dev.1",
        "bundle_root": build_bundle(ROOT)["bundle_root"],
        "runner_id": "vheatm.host-qualification",
        "runner_version": "1.0.0",
        "backend": "bubblewrap",
        "backend_digest": "d" * 64,
        "host_identity_digest": "e" * 64,
        "reference_monitor_status": "observed",
        "status": "complete",
        "evidence_state": "unverified",
        "observations": [observation],
        "measurements": [{
            "metric": "hard_stop_p99_seconds",
            "value": 0.2,
            "sample_count": 1,
            "confidence_lower": 0,
            "method_digest": _method_digest("hard_stop_p99_seconds"),
            "evidence_refs": [observation["observation_id"]],
        }],
        "generated_at": "2026-08-01T00:00:00Z",
    }
    run["run_id"] = expected_host_qualification_run_id(run)
    key = Ed25519PrivateKey.generate()
    signed = sign_host_attestation(
        build_host_attestation(
            run,
            authority_id="host-authority:v17",
            deployment_id="sandbox-host-release-fixture",
            generated_at="2026-08-01T00:00:00Z",
            root=ROOT,
        ),
        private_key=key,
        key_id="host-key",
    )
    return run, signed, key


def test_release_gates_reject_unsigned_independent_verdict(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    signed_manifest, receipt = _release_private_fixture(tmp_path, key)
    verified_manifest = verify_manifest(signed_manifest, public_key=key.public_key(), key_id="qualification-key")
    judge_packet, verdict, _ = _release_judge_fixture(receipt)
    evidence = build_qualification_evidence(
        manifest=verified_manifest,
        bundle_root=BUNDLE_ROOT,
        private_corpus_receipt_id=receipt["receipt_id"],
        evaluator_id="eval:v17",
        evaluator_version="1.0.0",
        independent_judge_id="judge:v17",
        judge_verdict_refs=[verdict["verdict_id"]],
        measurements=[
            {"metric": "critical_recall_lower_ci", "value": 0.96, "sample_count": 300, "confidence_lower": 0.96, "method_digest": _method_digest("critical_recall_lower_ci"), "evidence_refs": [receipt["receipt_id"]]},
            {"metric": "critical_miss_count", "value": 0, "sample_count": 300, "confidence_lower": 0, "method_digest": _method_digest("critical_miss_count"), "evidence_refs": [receipt["receipt_id"]]},
        ],
        generated_at="2026-08-01T00:00:00Z",
    )
    report = evaluate_release_gates(
        "17.0.0-dev.1",
        {
            "qualification_manifest": signed_manifest,
            "private_corpus_receipt": receipt,
            "qualification_evidence": sign_qualification_evidence(evidence, private_key=key, key_id="qualification-key"),
            "independent_judge_packets": [judge_packet],
            "independent_judge_verdicts": [verdict],
        },
        evaluated_at="2026-08-01T00:00:00Z",
        expected_bundle_root=BUNDLE_ROOT,
        **_trusted_registry_kwargs({"qualification": key.public_key()}, {"qualification": "qualification-key"}, BUNDLE_ROOT),
        schema_root=ROOT,
    )
    rg05 = next(item for item in report["gates"] if item["gate_id"] == "RG-05")
    assert rg05["status"] == "unknown"
    assert "signed" in rg05["rationale"] or "judge" in rg05["rationale"]

    same_key_packet, same_key_verdict, _ = _release_judge_fixture(receipt, signing_key=key)
    same_key_report = evaluate_release_gates(
        "17.0.0-dev.1",
        {
            "qualification_manifest": signed_manifest,
            "private_corpus_receipt": receipt,
            "qualification_evidence": sign_qualification_evidence(evidence, private_key=key, key_id="qualification-key"),
            "independent_judge_packets": [same_key_packet],
            "independent_judge_verdicts": [same_key_verdict],
        },
        evaluated_at="2026-08-01T00:00:00Z",
        expected_bundle_root=BUNDLE_ROOT,
        **_trusted_registry_kwargs({"qualification": key.public_key(), "judge": key.public_key()}, {"qualification": "qualification-key", "judge": "judge-key"}, BUNDLE_ROOT),
        schema_root=ROOT,
    )
    same_key_rg05 = next(item for item in same_key_report["gates"] if item["gate_id"] == "RG-05")
    assert same_key_rg05["status"] == "unknown"
    assert "distinct" in same_key_rg05["rationale"]


def test_release_gates_reject_measurement_with_unknown_method_digest(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    signed_manifest, receipt = _release_private_fixture(tmp_path, key)
    verified_manifest = verify_manifest(signed_manifest, public_key=key.public_key(), key_id="qualification-key")
    judge_key = Ed25519PrivateKey.generate()
    judge_packet, verdict, _ = _release_judge_fixture(receipt, signing_key=judge_key)
    evidence = build_qualification_evidence(
        manifest=verified_manifest,
        bundle_root=BUNDLE_ROOT,
        private_corpus_receipt_id=receipt["receipt_id"],
        evaluator_id="eval:v17",
        evaluator_version="1.0.0",
        independent_judge_id="judge:v17",
        judge_verdict_refs=[verdict["verdict_id"]],
        measurements=[
            {"metric": "critical_recall_lower_ci", "value": 0.96, "sample_count": 300, "confidence_lower": 0.96, "method_digest": "c" * 64, "evidence_refs": [receipt["receipt_id"]]},
            {"metric": "critical_miss_count", "value": 0, "sample_count": 300, "confidence_lower": 0, "method_digest": "c" * 64, "evidence_refs": [receipt["receipt_id"]]},
        ],
        generated_at="2026-08-01T00:00:00Z",
    )
    report = evaluate_release_gates(
        "17.0.0-dev.1",
        {
            "qualification_manifest": signed_manifest,
            "private_corpus_receipt": receipt,
            "qualification_evidence": sign_qualification_evidence(evidence, private_key=key, key_id="qualification-key"),
            "independent_judge_packets": [judge_packet],
            "independent_judge_verdicts": [verdict],
        },
        evaluated_at="2026-08-01T00:00:00Z",
        expected_bundle_root=BUNDLE_ROOT,
        **_trusted_registry_kwargs({"qualification": key.public_key(), "judge": judge_key.public_key()}, {"qualification": "qualification-key", "judge": "judge-key"}, BUNDLE_ROOT),
        schema_root=ROOT,
    )
    rg05 = next(item for item in report["gates"] if item["gate_id"] == "RG-05")
    assert rg05["status"] == "unknown"
    assert "method" in rg05["rationale"]


def test_release_gates_reject_critical_trials_larger_than_private_corpus(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    signed_manifest, receipt = _release_private_fixture(tmp_path, key, count=1)
    verified_manifest = verify_manifest(signed_manifest, public_key=key.public_key(), key_id="qualification-key")
    judge_key = Ed25519PrivateKey.generate()
    judge_packet, verdict, _ = _release_judge_fixture(receipt, signing_key=judge_key)
    evidence = build_qualification_evidence(
        manifest=verified_manifest,
        bundle_root=BUNDLE_ROOT,
        private_corpus_receipt_id=receipt["receipt_id"],
        evaluator_id="eval:v17",
        evaluator_version="1.0.0",
        independent_judge_id="judge:v17",
        judge_verdict_refs=[verdict["verdict_id"]],
        measurements=[
            {"metric": "critical_recall_lower_ci", "value": 0.96, "sample_count": 300, "confidence_lower": 0.96, "method_digest": _method_digest("critical_recall_lower_ci"), "evidence_refs": [receipt["receipt_id"]]},
            {"metric": "critical_miss_count", "value": 0, "sample_count": 300, "confidence_lower": 0, "method_digest": _method_digest("critical_miss_count"), "evidence_refs": [receipt["receipt_id"]]},
        ],
        generated_at="2026-08-01T00:00:00Z",
    )
    report = evaluate_release_gates(
        "17.0.0-dev.1",
        {
            "qualification_manifest": signed_manifest,
            "private_corpus_receipt": receipt,
            "qualification_evidence": sign_qualification_evidence(evidence, private_key=key, key_id="qualification-key"),
            "independent_judge_packets": [judge_packet],
            "independent_judge_verdicts": [verdict],
        },
        evaluated_at="2026-08-01T00:00:00Z",
        expected_bundle_root=BUNDLE_ROOT,
        **_trusted_registry_kwargs({"qualification": key.public_key(), "judge": judge_key.public_key()}, {"qualification": "qualification-key", "judge": "judge-key"}, BUNDLE_ROOT),
        schema_root=ROOT,
    )
    rg05 = next(item for item in report["gates"] if item["gate_id"] == "RG-05")
    assert rg05["status"] == "unknown"
    assert "measurement population binding" in rg05["rationale"]


def test_release_gates_reject_out_of_domain_qualification_metrics(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    signed_manifest, receipt = _release_private_fixture(tmp_path, key)
    verified_manifest = verify_manifest(signed_manifest, public_key=key.public_key(), key_id="qualification-key")
    judge_key = Ed25519PrivateKey.generate()
    judge_packet, verdict, _ = _release_judge_fixture(receipt, signing_key=judge_key)
    evidence = build_qualification_evidence(
        manifest=verified_manifest,
        bundle_root=BUNDLE_ROOT,
        private_corpus_receipt_id=receipt["receipt_id"],
        evaluator_id="eval:v17",
        evaluator_version="1.0.0",
        independent_judge_id="judge:v17",
        judge_verdict_refs=[verdict["verdict_id"]],
        measurements=[
            {"metric": "critical_recall_lower_ci", "value": 0.96, "sample_count": 300, "confidence_lower": 0.96, "method_digest": _method_digest("critical_recall_lower_ci"), "evidence_refs": [receipt["receipt_id"]]},
            {"metric": "critical_miss_count", "value": 0, "sample_count": 300, "confidence_lower": 0, "method_digest": _method_digest("critical_miss_count"), "evidence_refs": [receipt["receipt_id"]]},
        ],
        generated_at="2026-08-01T00:00:00Z",
    )
    evidence["measurements"][0]["value"] = 2.0
    evidence["metrics"]["critical_recall_lower_ci"] = 2.0
    evidence["evidence_id"] = expected_qualification_evidence_id(evidence)
    report = evaluate_release_gates(
        "17.0.0-dev.1",
        {
            "qualification_manifest": signed_manifest,
            "private_corpus_receipt": receipt,
            "qualification_evidence": sign_qualification_evidence(evidence, private_key=key, key_id="qualification-key"),
            "independent_judge_packets": [judge_packet],
            "independent_judge_verdicts": [verdict],
        },
        evaluated_at="2026-08-01T00:00:00Z",
        expected_bundle_root=BUNDLE_ROOT,
        **_trusted_registry_kwargs({"qualification": key.public_key(), "judge": judge_key.public_key()}, {"qualification": "qualification-key", "judge": "judge-key"}, BUNDLE_ROOT),
        schema_root=ROOT,
    )
    rg05 = next(item for item in report["gates"] if item["gate_id"] == "RG-05")
    assert rg05["status"] == "unknown"
    assert "metric domain" in rg05["rationale"]


def test_release_gates_reject_critical_trials_without_independent_case_coverage(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    signed_manifest, receipt = _release_private_fixture(tmp_path, key)
    verified_manifest = verify_manifest(signed_manifest, public_key=key.public_key(), key_id="qualification-key")
    judge_key = Ed25519PrivateKey.generate()
    judge_packet, verdict, _ = _release_judge_fixture(receipt, case_refs=[receipt["case_refs"][0]], signing_key=judge_key)
    evidence = build_qualification_evidence(
        manifest=verified_manifest,
        bundle_root=BUNDLE_ROOT,
        private_corpus_receipt_id=receipt["receipt_id"],
        evaluator_id="eval:v17",
        evaluator_version="1.0.0",
        independent_judge_id="judge:v17",
        judge_verdict_refs=[verdict["verdict_id"]],
        measurements=[
            {"metric": "critical_recall_lower_ci", "value": 0.96, "sample_count": 300, "confidence_lower": 0.96, "method_digest": _method_digest("critical_recall_lower_ci"), "evidence_refs": [receipt["receipt_id"]]},
            {"metric": "critical_miss_count", "value": 0, "sample_count": 300, "confidence_lower": 0, "method_digest": _method_digest("critical_miss_count"), "evidence_refs": [receipt["receipt_id"]]},
        ],
        generated_at="2026-08-01T00:00:00Z",
    )
    report = evaluate_release_gates(
        "17.0.0-dev.1",
        {
            "qualification_manifest": signed_manifest,
            "private_corpus_receipt": receipt,
            "qualification_evidence": sign_qualification_evidence(evidence, private_key=key, key_id="qualification-key"),
            "independent_judge_packets": [judge_packet],
            "independent_judge_verdicts": [verdict],
        },
        evaluated_at="2026-08-01T00:00:00Z",
        expected_bundle_root=BUNDLE_ROOT,
        **_trusted_registry_kwargs({"qualification": key.public_key(), "judge": judge_key.public_key()}, {"qualification": "qualification-key", "judge": "judge-key"}, BUNDLE_ROOT),
        schema_root=ROOT,
    )
    rg05 = next(item for item in report["gates"] if item["gate_id"] == "RG-05")
    assert rg05["status"] == "unknown"
    assert "independently judged private cases" in rg05["rationale"]


def test_release_gates_require_cryptographically_verified_qualification_and_supply_chain(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    signed_manifest, private_receipt = _release_private_fixture(tmp_path, key)
    verified_manifest = verify_manifest(signed_manifest, public_key=key.public_key(), key_id="qualification-key")
    judge_key = Ed25519PrivateKey.generate()
    judge_packet, judge_verdict, _ = _release_judge_fixture(private_receipt, signing_key=judge_key)
    supply_chain_key = Ed25519PrivateKey.generate()
    vulnerability_key = Ed25519PrivateKey.generate()
    provenance_key = Ed25519PrivateKey.generate()
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
        {"metric": name, "value": value, "sample_count": 300 if name in {"critical_recall_lower_ci", "critical_miss_count", "critical_family_asr_upper_ci", "critical_unsafe_action_count"} else 1000, "confidence_lower": float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= 1 else 0.0, "method_digest": _method_digest(name), "evidence_refs": [private_receipt["receipt_id"], f"EV-{name}"]}
        for name, value in values.items()
    ]
    qualification = build_qualification_evidence(
        manifest=verified_manifest,
        bundle_root=BUNDLE_ROOT,
        private_corpus_receipt_id=private_receipt["receipt_id"],
        evaluator_id="eval:v17",
        evaluator_version="1.0.0",
        independent_judge_id="judge:v17",
        judge_verdict_refs=[judge_verdict["verdict_id"]],
        measurements=measurements,
        generated_at="2026-08-01T00:00:00Z",
    )
    host_run, host_attestation, host_key = _release_host_fixture()

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
        sign_vulnerability_scan(scan, private_key=vulnerability_key, key_id="vulnerability-key"),
        public_key=vulnerability_key.public_key(),
        bundle_root=base_attestation["bundle_root"],
        lock_digest=base_attestation["dependency_lock_digest"],
        key_id="vulnerability-key",
    )
    attestation = sign_supply_chain_attestation(
        build_supply_chain_attestation(ROOT, generated_at="2026-08-01T00:00:00Z", vulnerability_scan=verified_scan),
        private_key=supply_chain_key,
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
        "private_corpus_receipt": private_receipt,
        "qualification_evidence": sign_qualification_evidence(qualification, private_key=key, key_id="qualification-key"),
        "host_qualification_run": host_run,
        "host_qualification_attestation": host_attestation,
        "independent_judge_packets": [judge_packet],
        "independent_judge_verdicts": [judge_verdict],
        "supply_chain_attestation": attestation,
        "vulnerability_scan": sign_vulnerability_scan(scan, private_key=vulnerability_key, key_id="vulnerability-key"),
        "provenance_statement": sign_provenance_statement(provenance, private_key=provenance_key, key_id="provenance-key"),
    }
    report = evaluate_release_gates(
        "17.0.0-dev.1",
        evidence,
        evaluated_at="2026-08-01T00:00:00Z",
        expected_bundle_root=base_attestation["bundle_root"],
        **_trusted_registry_kwargs({"qualification": key.public_key(), "judge": judge_key.public_key(), "host": host_key.public_key(), "supply_chain": supply_chain_key.public_key(), "vulnerability": vulnerability_key.public_key(), "provenance": provenance_key.public_key()}, {"qualification": "qualification-key", "judge": "judge-key", "host": "host-key", "supply_chain": "supply-chain-key", "vulnerability": "vulnerability-key", "provenance": "provenance-key"}, base_attestation["bundle_root"]),
        schema_root=ROOT,
    )
    assert report["summary"] == {"pass": 16, "fail": 0, "unknown": 0, "ga_eligible": True}
    Draft202012Validator(load_json((ROOT / "schemas" / "release-gate-report.schema.json").read_text())).validate(report)

    stale_report = evaluate_release_gates(
        "17.0.0-dev.1",
        evidence,
        evaluated_at="2026-08-10T00:00:00Z",
        expected_bundle_root=base_attestation["bundle_root"],
        **_trusted_registry_kwargs({"qualification": key.public_key(), "judge": judge_key.public_key(), "host": host_key.public_key(), "supply_chain": supply_chain_key.public_key(), "vulnerability": vulnerability_key.public_key(), "provenance": provenance_key.public_key()}, {"qualification": "qualification-key", "judge": "judge-key", "host": "host-key", "supply_chain": "supply-chain-key", "vulnerability": "vulnerability-key", "provenance": "provenance-key"}, base_attestation["bundle_root"]),
        schema_root=ROOT,
    )
    stale_rg13 = next(item for item in stale_report["gates"] if item["gate_id"] == "RG-13")
    assert stale_rg13["status"] == "fail"
    assert "stale" in stale_rg13["rationale"]

    same_key_evidence = {
        **evidence,
        "supply_chain_attestation": sign_supply_chain_attestation(attestation, private_key=key, key_id="supply-chain-key"),
        "vulnerability_scan": sign_vulnerability_scan(scan, private_key=key, key_id="vulnerability-key"),
        "provenance_statement": sign_provenance_statement(provenance, private_key=key, key_id="provenance-key"),
    }
    same_key_report = evaluate_release_gates(
        "17.0.0-dev.1",
        same_key_evidence,
        evaluated_at="2026-08-01T00:00:00Z",
        expected_bundle_root=base_attestation["bundle_root"],
        **_trusted_registry_kwargs({"qualification": key.public_key(), "judge": judge_key.public_key(), "supply_chain": key.public_key(), "vulnerability": key.public_key(), "provenance": key.public_key()}, {"qualification": "qualification-key", "judge": "judge-key", "supply_chain": "supply-chain-key", "vulnerability": "vulnerability-key", "provenance": "provenance-key"}, base_attestation["bundle_root"]),
        schema_root=ROOT,
    )
    same_key_rg13 = next(item for item in same_key_report["gates"] if item["gate_id"] == "RG-13")
    assert same_key_rg13["status"] == "fail"
    assert "must be distinct" in same_key_rg13["rationale"]

    packet_missing = evaluate_release_gates(
        "17.0.0-dev.1",
        {**evidence, "independent_judge_packets": []},
        evaluated_at="2026-08-01T00:00:00Z",
        expected_bundle_root=base_attestation["bundle_root"],
        **_trusted_registry_kwargs({"qualification": key.public_key(), "judge": judge_key.public_key(), "supply_chain": key.public_key(), "vulnerability": vulnerability_key.public_key(), "provenance": provenance_key.public_key()}, {"qualification": "qualification-key", "judge": "judge-key", "supply_chain": "supply-chain-key", "vulnerability": "vulnerability-key", "provenance": "provenance-key"}, base_attestation["bundle_root"]),
        schema_root=ROOT,
    )
    assert next(item for item in packet_missing["gates"] if item["gate_id"] == "RG-05")["status"] == "unknown"

    duplicate_packet = evaluate_release_gates(
        "17.0.0-dev.1",
        {**evidence, "independent_judge_packets": [judge_packet, judge_packet]},
        evaluated_at="2026-08-01T00:00:00Z",
        expected_bundle_root=base_attestation["bundle_root"],
        **_trusted_registry_kwargs({"qualification": key.public_key(), "judge": judge_key.public_key(), "supply_chain": key.public_key(), "vulnerability": vulnerability_key.public_key(), "provenance": provenance_key.public_key()}, {"qualification": "qualification-key", "judge": "judge-key", "supply_chain": "supply-chain-key", "vulnerability": "vulnerability-key", "provenance": "provenance-key"}, base_attestation["bundle_root"]),
        schema_root=ROOT,
    )
    assert next(item for item in duplicate_packet["gates"] if item["gate_id"] == "RG-05")["status"] == "unknown"

    verdict_mismatch = {**judge_verdict, "config_digest": "f" * 64}
    verdict_mismatch["verdict_id"] = expected_verdict_id(verdict_mismatch)
    binding_mismatch = evaluate_release_gates(
        "17.0.0-dev.1",
        {**evidence, "independent_judge_verdicts": [verdict_mismatch]},
        evaluated_at="2026-08-01T00:00:00Z",
        expected_bundle_root=base_attestation["bundle_root"],
        **_trusted_registry_kwargs({"qualification": key.public_key(), "judge": judge_key.public_key(), "supply_chain": key.public_key(), "vulnerability": vulnerability_key.public_key(), "provenance": provenance_key.public_key()}, {"qualification": "qualification-key", "judge": "judge-key", "supply_chain": "supply-chain-key", "vulnerability": "vulnerability-key", "provenance": "provenance-key"}, base_attestation["bundle_root"]),
        schema_root=ROOT,
    )
    assert next(item for item in binding_mismatch["gates"] if item["gate_id"] == "RG-05")["status"] == "unknown"

    schema_invalid = dict(evidence["qualification_evidence"])
    schema_invalid["unexpected_runtime_field"] = "must be rejected by the evaluator boundary"
    schema_invalid["evidence_id"] = expected_qualification_evidence_id(schema_invalid)
    schema_invalid = sign_qualification_evidence(schema_invalid, private_key=key, key_id="qualification-key")
    schema_tampered_evidence = {**evidence, "qualification_evidence": schema_invalid}
    schema_blocked = evaluate_release_gates(
        "17.0.0-dev.1",
        schema_tampered_evidence,
        evaluated_at="2026-08-01T00:00:00Z",
        expected_bundle_root=base_attestation["bundle_root"],
        **_trusted_registry_kwargs({"qualification": key.public_key(), "supply_chain": supply_chain_key.public_key(), "vulnerability": vulnerability_key.public_key(), "provenance": provenance_key.public_key()}, {"qualification": "qualification-key", "supply_chain": "supply-chain-key", "vulnerability": "vulnerability-key", "provenance": "provenance-key"}, base_attestation["bundle_root"]),
        schema_root=ROOT,
    )
    assert schema_blocked["summary"]["ga_eligible"] is False
    assert schema_blocked["summary"]["unknown"] >= 1

    supply_schema_invalid = dict(evidence["supply_chain_attestation"])
    supply_schema_invalid["unexpected_runtime_field"] = "must be rejected by the evaluator boundary"
    supply_schema_invalid["attestation_id"] = expected_attestation_id(supply_schema_invalid)
    supply_schema_invalid = sign_supply_chain_attestation(supply_schema_invalid, private_key=key, key_id="supply-chain-key")
    supply_schema_blocked = evaluate_release_gates(
        "17.0.0-dev.1",
        {**evidence, "supply_chain_attestation": supply_schema_invalid},
        evaluated_at="2026-08-01T00:00:00Z",
        expected_bundle_root=base_attestation["bundle_root"],
        **_trusted_registry_kwargs({"qualification": key.public_key(), "supply_chain": supply_chain_key.public_key(), "vulnerability": vulnerability_key.public_key(), "provenance": provenance_key.public_key()}, {"qualification": "qualification-key", "supply_chain": "supply-chain-key", "vulnerability": "vulnerability-key", "provenance": "provenance-key"}, base_attestation["bundle_root"]),
        schema_root=ROOT,
    )
    assert next(item for item in supply_schema_blocked["gates"] if item["gate_id"] == "RG-13")["status"] == "fail"

    missing_receipt = dict(evidence)
    missing_receipt.pop("private_corpus_receipt")
    blocked_report = evaluate_release_gates(
        "17.0.0-dev.1",
        missing_receipt,
        evaluated_at="2026-08-01T00:00:00Z",
        expected_bundle_root=base_attestation["bundle_root"],
        **_trusted_registry_kwargs({"qualification": key.public_key(), "supply_chain": supply_chain_key.public_key(), "vulnerability": vulnerability_key.public_key(), "provenance": provenance_key.public_key()}, {"qualification": "qualification-key", "supply_chain": "supply-chain-key", "vulnerability": "vulnerability-key", "provenance": "provenance-key"}, base_attestation["bundle_root"]),
        schema_root=ROOT,
    )
    assert blocked_report["summary"]["ga_eligible"] is False
    assert next(item for item in blocked_report["gates"] if item["gate_id"] == "RG-00")["status"] == "unknown"


def test_supply_chain_evidence_is_canonical_and_locked_but_not_signed_yet(tmp_path) -> None:
    attestation = build_supply_chain_attestation(ROOT, generated_at="2026-08-01T00:00:00Z")
    schema = load_json((ROOT / "schemas" / "supply-chain-attestation.schema.json").read_text())
    Draft202012Validator(schema).validate(attestation)
    assert attestation["signed_release"] is False
    assert attestation["dependency_lock_present"] is True
    assert attestation["dependency_lock_path"] == "uv.lock"
    assert attestation["sbom"]


def test_release_gates_reject_signed_attestation_with_noncanonical_sbom() -> None:
    release_key = Ed25519PrivateKey.generate()
    vulnerability_key = Ed25519PrivateKey.generate()
    provenance_key = Ed25519PrivateKey.generate()
    base_attestation = build_supply_chain_attestation(ROOT, generated_at="2026-08-01T00:00:00Z")
    scan = build_vulnerability_scan(
        scanner_id="scanner:v17",
        scanner_version="1.0.0",
        target_bundle_root=base_attestation["bundle_root"],
        target_lock_digest=base_attestation["dependency_lock_digest"],
        findings=[],
        generated_at="2026-08-01T00:00:00Z",
    )
    signed_scan = sign_vulnerability_scan(scan, private_key=vulnerability_key, key_id="vulnerability-key")
    verified_scan = verify_vulnerability_scan(
        signed_scan,
        public_key=vulnerability_key.public_key(),
        bundle_root=base_attestation["bundle_root"],
        lock_digest=base_attestation["dependency_lock_digest"],
        key_id="vulnerability-key",
    )
    forged = build_supply_chain_attestation(
        ROOT,
        generated_at="2026-08-01T00:00:00Z",
        vulnerability_scan=verified_scan,
    )
    forged["sbom"] = [{"path": "forged/not-in-bundle", "sha256": "a" * 64}]
    forged["sbom_digest"] = hashlib.sha256(
        json.dumps(forged["sbom"], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    forged["attestation_id"] = expected_attestation_id(forged)
    signed_attestation = sign_supply_chain_attestation(forged, private_key=release_key, key_id="supply-chain-key")
    provenance = {
        "schema_version": "1.0.0",
        "bundle_root": signed_attestation["bundle_root"],
        "sbom_digest": signed_attestation["sbom_digest"],
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
        "supply_chain_attestation": signed_attestation,
        "vulnerability_scan": signed_scan,
        "provenance_statement": sign_provenance_statement(provenance, private_key=provenance_key, key_id="provenance-key"),
    }
    report = evaluate_release_gates(
        "17.0.0-dev.1",
        evidence,
        evaluated_at="2026-08-01T00:00:00Z",
        expected_bundle_root=base_attestation["bundle_root"],
        **_trusted_registry_kwargs(
            {
                "supply_chain": release_key.public_key(),
                "vulnerability": vulnerability_key.public_key(),
                "provenance": provenance_key.public_key(),
            },
            {
                "supply_chain": "supply-chain-key",
                "vulnerability": "vulnerability-key",
                "provenance": "provenance-key",
            },
            base_attestation["bundle_root"],
        ),
        schema_root=ROOT,
    )
    rg13 = next(item for item in report["gates"] if item["gate_id"] == "RG-13")
    assert rg13["status"] == "fail"
    assert "canonical" in rg13["rationale"] or "bundle" in rg13["rationale"]


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
