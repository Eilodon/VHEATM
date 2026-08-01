from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class QualificationError(ValueError):
    """Raised when qualification evidence is malformed, unbound, or unverifiable."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise QualificationError("qualification timestamps must be RFC 3339") from exc
    if parsed.tzinfo is None:
        raise QualificationError("qualification timestamps must include a timezone")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _verify(document: Mapping[str, Any], public_key: Ed25519PublicKey, *, key_id: str | None = None) -> None:
    if document.get("signature_algorithm") != "ed25519" or not isinstance(document.get("signature_value"), str):
        raise QualificationError("qualification evidence requires an Ed25519 signature")
    if key_id is not None and document.get("signature_key_id") != key_id:
        raise QualificationError("qualification signing key does not match")
    excluded = {"evidence_id", "signature_algorithm", "signature_key_id", "signature_value", "verification_state", "evidence_state"}
    if "evidence_id" not in document:
        excluded.add("manifest_id")
    subject = {key: value for key, value in document.items() if key not in excluded}
    try:
        public_key.verify(base64.urlsafe_b64decode(str(document["signature_value"])), _canonical(subject))
    except (InvalidSignature, ValueError) as exc:
        raise QualificationError("qualification signature is invalid") from exc


def _sign(subject: Mapping[str, Any], private_key: Ed25519PrivateKey) -> str:
    return _b64(private_key.sign(_canonical(subject)))


def expected_manifest_id(manifest: Mapping[str, Any]) -> str:
    identity = {key: value for key, value in manifest.items() if key not in {"manifest_id", "signature_algorithm", "signature_key_id", "signature_value", "verification_state"}}
    return "QMF-" + _digest(identity).upper()


def build_private_time_slice_manifest(
    *,
    framework_version: str,
    private_locator: str,
    time_slice_start: str,
    time_slice_end: str,
    case_digests: Sequence[str],
    generated_at: str,
) -> dict[str, Any]:
    normalized = sorted(set(str(value) for value in case_digests))
    if not normalized or any(len(value) != 64 or any(char not in "0123456789abcdef" for char in value) for value in normalized):
        raise QualificationError("private corpus case digests must be lowercase SHA-256 values")
    start = _timestamp(time_slice_start)
    end = _timestamp(time_slice_end)
    if datetime.fromisoformat(end.replace("Z", "+00:00")) <= datetime.fromisoformat(start.replace("Z", "+00:00")):
        raise QualificationError("qualification time slice must have a positive duration")
    manifest: dict[str, Any] = {
        "schema_version": "1.0.0",
        "framework_version": framework_version,
        "visibility": "private",
        "private_locator": private_locator,
        "time_slice": {"start": start, "end": end},
        "case_count": len(normalized),
        "case_digests": normalized,
        "corpus_digest": _digest(normalized),
        "verification_state": "unverified",
        "signature_algorithm": None,
        "signature_key_id": None,
        "signature_value": None,
        "generated_at": _timestamp(generated_at),
    }
    manifest["manifest_id"] = expected_manifest_id(manifest)
    return manifest


def sign_manifest(manifest: Mapping[str, Any], *, private_key: Ed25519PrivateKey, key_id: str) -> dict[str, Any]:
    if manifest.get("manifest_id") != expected_manifest_id(manifest):
        raise QualificationError("manifest identity does not match content")
    signed = dict(manifest)
    signed.update({"signature_algorithm": "ed25519", "signature_key_id": key_id})
    subject = {key: value for key, value in signed.items() if key not in {"manifest_id", "signature_algorithm", "signature_key_id", "signature_value", "verification_state"}}
    signed["signature_value"] = _sign(subject, private_key)
    return signed


def verify_manifest(manifest: Mapping[str, Any], *, public_key: Ed25519PublicKey, key_id: str | None = None) -> dict[str, Any]:
    if manifest.get("manifest_id") != expected_manifest_id(manifest):
        raise QualificationError("manifest identity does not match content")
    if manifest.get("case_count") != len(manifest.get("case_digests", [])) or manifest.get("corpus_digest") != _digest(manifest.get("case_digests", [])):
        raise QualificationError("manifest corpus digest is not derived from case digests")
    _verify(manifest, public_key, key_id=key_id)
    verified = dict(manifest)
    verified["verification_state"] = "verified"
    return verified


def expected_qualification_evidence_id(evidence: Mapping[str, Any]) -> str:
    identity = {key: value for key, value in evidence.items() if key not in {"evidence_id", "signature_algorithm", "signature_key_id", "signature_value", "evidence_state"}}
    return "QEV-" + _digest(identity).upper()


def build_qualification_evidence(
    *,
    manifest: Mapping[str, Any],
    evaluator_id: str,
    evaluator_version: str,
    independent_judge_id: str,
    measurements: Sequence[Mapping[str, Any]],
    generated_at: str,
) -> dict[str, Any]:
    if manifest.get("verification_state") != "verified":
        raise QualificationError("qualification evidence requires a verified private manifest")
    if not evaluator_id or not evaluator_version or not independent_judge_id:
        raise QualificationError("qualification evaluator and independent judge identities are required")
    normalized = [dict(item) for item in measurements]
    if not normalized or any(int(item.get("sample_count", 0)) < 1 for item in normalized):
        raise QualificationError("qualification measurements require positive sample counts")
    metrics: dict[str, Any] = {}
    for item in normalized:
        metric = str(item.get("metric", ""))
        if not metric or metric in metrics:
            raise QualificationError("qualification metrics must be unique and named")
        metrics[metric] = item.get("value")
    evidence: dict[str, Any] = {
        "schema_version": "1.0.0",
        "manifest_id": manifest["manifest_id"],
        "manifest_digest": _digest({key: value for key, value in manifest.items() if key != "signature_value"}),
        "evaluator_id": evaluator_id,
        "evaluator_version": evaluator_version,
        "independent_judge_id": independent_judge_id,
        "measurements": normalized,
        "metrics": metrics,
        "evidence_state": "unverified",
        "signature_algorithm": None,
        "signature_key_id": None,
        "signature_value": None,
        "generated_at": _timestamp(generated_at),
    }
    evidence["evidence_id"] = expected_qualification_evidence_id(evidence)
    return evidence


def sign_qualification_evidence(evidence: Mapping[str, Any], *, private_key: Ed25519PrivateKey, key_id: str) -> dict[str, Any]:
    if evidence.get("evidence_id") != expected_qualification_evidence_id(evidence):
        raise QualificationError("qualification evidence identity does not match content")
    signed = dict(evidence)
    signed.update({"signature_algorithm": "ed25519", "signature_key_id": key_id})
    subject = {key: value for key, value in signed.items() if key not in {"evidence_id", "signature_algorithm", "signature_key_id", "signature_value", "evidence_state"}}
    signed["signature_value"] = _sign(subject, private_key)
    return signed


def verify_qualification_evidence(
    evidence: Mapping[str, Any], *, manifest: Mapping[str, Any], public_key: Ed25519PublicKey, key_id: str | None = None
) -> dict[str, Any]:
    if evidence.get("evidence_id") != expected_qualification_evidence_id(evidence):
        raise QualificationError("qualification evidence identity does not match content")
    if manifest.get("verification_state") != "verified" or evidence.get("manifest_id") != manifest.get("manifest_id"):
        raise QualificationError("qualification evidence is not bound to a verified manifest")
    _verify(evidence, public_key, key_id=key_id)
    verified = dict(evidence)
    verified["evidence_state"] = "verified"
    return verified
