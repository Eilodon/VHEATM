from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

from vheatm_control.qualification import (
    QualificationError,
    build_private_time_slice_manifest,
    build_qualification_evidence,
    sign_manifest,
    sign_qualification_evidence,
    verify_qualification_evidence,
    verify_manifest,
)
from vheatm_control.serialization import load_json


ROOT = Path(__file__).resolve().parents[1]


def test_private_time_sliced_manifest_and_measurements_are_signed_and_bound() -> None:
    key = Ed25519PrivateKey.generate()
    manifest = build_private_time_slice_manifest(
        framework_version="17.0.0-dev.1",
        private_locator="vault://qualification/v17/2026-07",
        time_slice_start="2026-07-01T00:00:00Z",
        time_slice_end="2026-08-01T00:00:00Z",
        case_digests=["a" * 64, "b" * 64],
        generated_at="2026-08-01T00:00:00Z",
    )
    verified_manifest = verify_manifest(sign_manifest(manifest, private_key=key, key_id="gold-key"), public_key=key.public_key(), key_id="gold-key")
    measurements = [{"metric": "critical_recall_lower_ci", "value": 0.96, "sample_count": 100, "confidence_lower": 0.96, "method_digest": "c" * 64, "evidence_refs": ["vault://evidence/1"]}]
    evidence = build_qualification_evidence(manifest=verified_manifest, evaluator_id="eval:v17", evaluator_version="1.0.0", independent_judge_id="judge:v17", measurements=measurements, generated_at="2026-08-01T00:00:00Z")
    signed = sign_qualification_evidence(evidence, private_key=key, key_id="evidence-key")
    verified = verify_qualification_evidence(signed, manifest=verified_manifest, public_key=key.public_key(), key_id="evidence-key")
    assert verified["evidence_state"] == "verified"
    assert verified["metrics"]["critical_recall_lower_ci"] == 0.96
    Draft202012Validator(load_json((ROOT / "schemas" / "qualification-manifest.schema.json").read_text(encoding="utf-8"))).validate(verified_manifest)
    Draft202012Validator(load_json((ROOT / "schemas" / "qualification-evidence.schema.json").read_text(encoding="utf-8"))).validate(verified)


def test_qualification_requires_verified_manifest_and_rejects_tampering() -> None:
    key = Ed25519PrivateKey.generate()
    manifest = build_private_time_slice_manifest(framework_version="17.0.0-dev.1", private_locator="vault://gold", time_slice_start="2026-07-01T00:00:00Z", time_slice_end="2026-08-01T00:00:00Z", case_digests=["a" * 64], generated_at="2026-08-01T00:00:00Z")
    with pytest.raises(QualificationError, match="verified private manifest"):
        build_qualification_evidence(manifest=manifest, evaluator_id="eval", evaluator_version="1", independent_judge_id="judge", measurements=[], generated_at="2026-08-01T00:00:00Z")
    tampered = dict(sign_manifest(manifest, private_key=key, key_id="gold-key"))
    tampered["case_count"] = 2
    with pytest.raises(QualificationError):
        verify_manifest(tampered, public_key=key.public_key(), key_id="gold-key")
