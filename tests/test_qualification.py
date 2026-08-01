from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

from vheatm_control.bundle import build_bundle
from vheatm_control.judge import expected_verdict_id
from vheatm_control.qualification import (
    QualificationError,
    build_private_time_slice_manifest,
    build_qualification_evidence,
    expected_qualification_evidence_id,
    sign_manifest,
    sign_qualification_evidence,
    verify_qualification_evidence,
    verify_manifest,
)
from vheatm_control.qualification_methods import QualificationMethodError, expected_method_digest, method_definition, validate_method_digest
from vheatm_control.serialization import load_json
from vheatm_control.qualification_private import expected_private_case_digest, expected_private_corpus_digest, expected_private_corpus_id, ingest_private_corpus


ROOT = Path(__file__).resolve().parents[1]


def _private_fixture(tmp_path: Path, key: Ed25519PrivateKey, *, count: int = 2) -> tuple[dict, dict, dict]:
    cases = []
    for index in range(count):
        case = {"case_id": f"PQC-CASE-{index:03d}", "captured_at": "2026-07-15T00:00:00Z", "payload": {"index": index, "label": "yes"}}
        case["case_digest"] = expected_private_case_digest(case)
        cases.append(case)
    corpus = {"schema_version": "1.0.0", "corpus_id": "PQC-" + "0" * 64, "framework_version": "17.0.0-dev.1", "visibility": "private", "time_slice": {"start": "2026-07-01T00:00:00Z", "end": "2026-08-01T00:00:00Z"}, "cases": cases}
    corpus["corpus_digest"] = expected_private_corpus_digest(corpus)
    corpus["corpus_id"] = expected_private_corpus_id(corpus)
    corpus_path = tmp_path / "private-corpus.json"
    corpus_path.write_text(json.dumps(corpus), encoding="utf-8")
    manifest = build_private_time_slice_manifest(framework_version="17.0.0-dev.1", private_locator=str(corpus_path), time_slice_start=corpus["time_slice"]["start"], time_slice_end=corpus["time_slice"]["end"], case_digests=[case["case_digest"] for case in cases], generated_at="2026-08-01T00:00:00Z")
    signed_manifest = sign_manifest(manifest, private_key=key, key_id="gold-key")
    receipt = ingest_private_corpus(signed_manifest, corpus_path=corpus_path, public_key=key.public_key(), key_id="gold-key", verified_at="2026-08-01T00:00:00Z")
    return signed_manifest, receipt, corpus


def test_private_time_sliced_manifest_and_measurements_are_signed_and_bound(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    signed_manifest, receipt, _ = _private_fixture(tmp_path, key)
    verified_manifest = verify_manifest(signed_manifest, public_key=key.public_key(), key_id="gold-key")
    judge_verdict = {
        "schema_version": "1.0.0", "packet_id": "JPK-" + "a" * 64, "request_id": "JDR-" + "b" * 64,
        "judge_provider_id": "judge.provider", "judge_model_id": "judge-model", "config_digest": "c" * 64,
        "order_digest": "d" * 64, "status": "complete", "epistemic_status": "independent_candidate",
        "decisions": [{"item_id": "case-1", "label": "yes", "confidence": 0.9}], "generated_at": "2026-08-01T00:00:00Z",
    }
    judge_verdict["verdict_id"] = expected_verdict_id(judge_verdict)
    measurements = [{"metric": "critical_recall_lower_ci", "value": 0.96, "sample_count": 100, "confidence_lower": 0.96, "method_digest": expected_method_digest("critical_recall_lower_ci"), "evidence_refs": [receipt["receipt_id"]]}]
    bundle_root = build_bundle(ROOT)["bundle_root"]
    evidence = build_qualification_evidence(manifest=verified_manifest, bundle_root=bundle_root, private_corpus_receipt_id=receipt["receipt_id"], evaluator_id="eval:v17", evaluator_version="1.0.0", independent_judge_id="judge:v17", judge_verdict_refs=[judge_verdict["verdict_id"]], measurements=measurements, generated_at="2026-08-01T00:00:00Z")
    signed = sign_qualification_evidence(evidence, private_key=key, key_id="evidence-key")
    verified = verify_qualification_evidence(signed, manifest=verified_manifest, expected_bundle_root=bundle_root, public_key=key.public_key(), key_id="evidence-key")
    assert verified["evidence_state"] == "verified"
    assert verified["metrics"]["critical_recall_lower_ci"] == 0.96
    Draft202012Validator(load_json((ROOT / "schemas" / "qualification-manifest.schema.json").read_text(encoding="utf-8"))).validate(verified_manifest)
    Draft202012Validator(load_json((ROOT / "schemas" / "qualification-evidence.schema.json").read_text(encoding="utf-8"))).validate(verified)

    tampered = {**signed, "bundle_root": "0" * 64}
    tampered["evidence_id"] = expected_qualification_evidence_id(tampered)
    tampered = sign_qualification_evidence(tampered, private_key=key, key_id="evidence-key")
    with pytest.raises(QualificationError, match="bundle root"):
        verify_qualification_evidence(tampered, manifest=verified_manifest, expected_bundle_root=bundle_root, public_key=key.public_key(), key_id="evidence-key")


def test_measurement_method_digest_is_bound_to_canonical_method_policy() -> None:
    definition = method_definition("critical_recall_lower_ci", root=ROOT)
    assert definition["framework_version"] == "17.0.0-dev.1"
    assert definition["policy_id"] == "vheatm-qualification-methods"
    digest = expected_method_digest("critical_recall_lower_ci", root=ROOT)
    assert len(digest) == 64
    validate_method_digest("critical_recall_lower_ci", digest, root=ROOT)
    with pytest.raises(QualificationMethodError, match="does not match canonical method"):
        validate_method_digest("critical_recall_lower_ci", "c" * 64, root=ROOT)


def test_qualification_requires_verified_manifest_and_rejects_tampering() -> None:
    key = Ed25519PrivateKey.generate()
    manifest = build_private_time_slice_manifest(framework_version="17.0.0-dev.1", private_locator="vault://gold", time_slice_start="2026-07-01T00:00:00Z", time_slice_end="2026-08-01T00:00:00Z", case_digests=["a" * 64], generated_at="2026-08-01T00:00:00Z")
    with pytest.raises(QualificationError, match="verified private manifest"):
        build_qualification_evidence(manifest=manifest, bundle_root=build_bundle(ROOT)["bundle_root"], private_corpus_receipt_id="PQR-" + "A" * 64, evaluator_id="eval", evaluator_version="1", independent_judge_id="judge", judge_verdict_refs=[], measurements=[], generated_at="2026-08-01T00:00:00Z")
    tampered = dict(sign_manifest(manifest, private_key=key, key_id="gold-key"))
    tampered["case_count"] = 2
    with pytest.raises(QualificationError):
        verify_manifest(tampered, public_key=key.public_key(), key_id="gold-key")
