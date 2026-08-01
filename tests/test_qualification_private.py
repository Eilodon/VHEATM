from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

from vheatm_control.bundle import build_bundle
from vheatm_control.qualification import build_private_time_slice_manifest, build_qualification_evidence, sign_manifest, verify_manifest
from vheatm_control.qualification_private import (
    PrivateCorpusError,
    expected_private_case_digest,
    expected_private_corpus_digest,
    expected_private_corpus_id,
    ingest_private_corpus,
)
from vheatm_control.serialization import load_json


ROOT = Path(__file__).resolve().parents[1]


def _corpus(path: Path, *, captured_at: str = "2026-07-15T00:00:00Z") -> tuple[dict, dict]:
    case = {"case_id": "PQC-CASE-001", "captured_at": captured_at, "payload": {"family": "critical-recall", "label": "yes"}}
    case["case_digest"] = expected_private_case_digest(case)
    corpus = {
        "schema_version": "1.0.0",
        "corpus_id": "PQC-" + "0" * 64,
        "framework_version": "17.0.0-dev.1",
        "visibility": "private",
        "time_slice": {"start": "2026-07-01T00:00:00Z", "end": "2026-08-01T00:00:00Z"},
        "cases": [case],
    }
    corpus["corpus_digest"] = expected_private_corpus_digest(corpus)
    corpus["corpus_id"] = expected_private_corpus_id(corpus)
    path.write_text(json.dumps(corpus), encoding="utf-8")
    return corpus, case


def _manifest(path: Path, key: Ed25519PrivateKey, corpus: dict, case: dict) -> dict:
    manifest = build_private_time_slice_manifest(
        framework_version="17.0.0-dev.1",
        private_locator=str(path),
        time_slice_start=corpus["time_slice"]["start"],
        time_slice_end=corpus["time_slice"]["end"],
        case_digests=[case["case_digest"]],
        generated_at="2026-08-01T00:00:00Z",
    )
    return sign_manifest(manifest, private_key=key, key_id="gold-key")


def test_private_corpus_ingest_verifies_manifest_slice_and_hides_payload(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    corpus_path = tmp_path / "private-corpus.json"
    corpus, case = _corpus(corpus_path)
    manifest = _manifest(corpus_path, key, corpus, case)

    receipt = ingest_private_corpus(manifest, corpus_path=corpus_path, public_key=key.public_key(), key_id="gold-key", verified_at="2026-08-01T00:00:00Z")

    assert receipt["verification_state"] == "verified"
    assert receipt["case_count"] == 1
    assert receipt["payload_disclosed"] is False
    assert "payload" not in receipt
    Draft202012Validator(load_json((ROOT / "schemas" / "private-corpus-receipt.schema.json").read_text(encoding="utf-8"))).validate(receipt)


def test_private_corpus_ingest_rejects_case_tamper_and_out_of_slice(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    corpus_path = tmp_path / "private-corpus.json"
    corpus, case = _corpus(corpus_path)
    manifest = _manifest(corpus_path, key, corpus, case)

    tampered = json.loads(corpus_path.read_text(encoding="utf-8"))
    tampered["cases"][0]["payload"]["label"] = "no"
    corpus_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(PrivateCorpusError, match="case digest"):
        ingest_private_corpus(manifest, corpus_path=corpus_path, public_key=key.public_key(), key_id="gold-key", verified_at="2026-08-01T00:00:00Z")

    corpus, case = _corpus(corpus_path, captured_at="2026-08-01T00:00:00Z")
    manifest = _manifest(corpus_path, key, corpus, case)
    with pytest.raises(PrivateCorpusError, match="time slice"):
        ingest_private_corpus(manifest, corpus_path=corpus_path, public_key=key.public_key(), key_id="gold-key", verified_at="2026-08-01T00:00:00Z")


def test_private_corpus_ingest_fails_closed_for_unavailable_locator(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    corpus_path = tmp_path / "private-corpus.json"
    corpus, case = _corpus(corpus_path)
    manifest = build_private_time_slice_manifest(
        framework_version="17.0.0-dev.1",
        private_locator="vault://gold/v17",
        time_slice_start=corpus["time_slice"]["start"],
        time_slice_end=corpus["time_slice"]["end"],
        case_digests=[case["case_digest"]],
        generated_at="2026-08-01T00:00:00Z",
    )
    manifest = sign_manifest(manifest, private_key=key, key_id="gold-key")

    with pytest.raises(PrivateCorpusError, match="locator"):
        ingest_private_corpus(manifest, corpus_path=corpus_path, public_key=key.public_key(), key_id="gold-key", verified_at="2026-08-01T00:00:00Z")


def test_private_corpus_ingest_rejects_symlinked_locator(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    target = tmp_path / "private-corpus.json"
    corpus, case = _corpus(target)
    link = tmp_path / "private-corpus-link.json"
    link.symlink_to(target)
    manifest = build_private_time_slice_manifest(
        framework_version="17.0.0-dev.1",
        private_locator=str(link),
        time_slice_start=corpus["time_slice"]["start"],
        time_slice_end=corpus["time_slice"]["end"],
        case_digests=[case["case_digest"]],
        generated_at="2026-08-01T00:00:00Z",
    )
    manifest = sign_manifest(manifest, private_key=key, key_id="gold-key")

    with pytest.raises(PrivateCorpusError, match="unsafe"):
        ingest_private_corpus(manifest, corpus_path=link, public_key=key.public_key(), key_id="gold-key", verified_at="2026-08-01T00:00:00Z")


def test_qualification_evidence_binds_ingested_private_corpus_receipt(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    corpus_path = tmp_path / "private-corpus.json"
    corpus, case = _corpus(corpus_path)
    manifest = _manifest(corpus_path, key, corpus, case)
    receipt = ingest_private_corpus(manifest, corpus_path=corpus_path, public_key=key.public_key(), key_id="gold-key", verified_at="2026-08-01T00:00:00Z")
    evidence = build_qualification_evidence(
        manifest=verify_manifest(manifest, public_key=key.public_key(), key_id="gold-key"),
        bundle_root=build_bundle(ROOT)["bundle_root"],
        private_corpus_receipt_id=receipt["receipt_id"],
        evaluator_id="eval:v17",
        evaluator_version="1.0.0",
        independent_judge_id="judge:v17",
        judge_verdict_refs=["JVR-" + "A" * 64],
        measurements=[{"metric": "mutation_rejection_rate", "value": 1.0, "sample_count": 1, "confidence_lower": 0, "method_digest": "b" * 64, "evidence_refs": [receipt["receipt_id"]]}],
        generated_at="2026-08-01T00:00:00Z",
    )
    assert evidence["private_corpus_receipt_id"] == receipt["receipt_id"]
