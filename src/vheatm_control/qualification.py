from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .qualification_methods import QualificationMethodError, method_definition, validate_method_digest


class QualificationError(ValueError):
    """Raised when qualification evidence is malformed, unbound, or unverifiable."""


_SAMPLE_BASES = frozenset({"private_case_trials", "repeated_evaluation", "private_corpus_observation"})
_BOUNDED_METRICS = frozenset(
    {
        "mutation_rejection_rate", "route_equivalence_rate", "plan_digest_stability_rate", "selection_digest_stability_rate",
        "unknown_diagnostic_rate", "forgery_rejection_rate", "high_critical_lineage_rate", "high_critical_proof_or_judge_rate",
        "critical_recall_lower_ci", "judge_kappa_lower_ci", "order_consistency_rate", "critical_family_asr_upper_ci",
        "unauthorized_block_rate", "resume_digest_match_rate", "peak_disclosure_ratio", "trace_completeness_rate",
    }
)
_NON_NEGATIVE_METRICS = frozenset(
    {
        "determinism_runs", "false_inactive_count", "unrelated_pass_claims", "critical_miss_count", "high_critical_autoclose_count",
        "self_judge_final_authority_count", "critical_unsafe_action_count", "hard_stop_p99_seconds", "duplicate_effect_count",
        "planner_router_p95_ms", "secret_pii_leakage_count", "experimental_selected_count", "p0_p1_open_count",
    }
)
_INTEGER_METRICS = frozenset(
    {
        "determinism_runs", "false_inactive_count", "unrelated_pass_claims", "critical_miss_count", "high_critical_autoclose_count",
        "self_judge_final_authority_count", "critical_unsafe_action_count", "duplicate_effect_count", "secret_pii_leakage_count",
        "experimental_selected_count", "p0_p1_open_count",
    }
)


def measurement_sample_basis(metric: str) -> str:
    """Return the canonical population semantics for a release metric."""

    try:
        return str(method_definition(metric)["sample_basis"])
    except QualificationMethodError:
        return "private_corpus_observation"


def metric_domain_error(metric: str, value: Any) -> str | None:
    if metric in _BOUNDED_METRICS and (isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1):
        return f"{metric} must be a numeric value in [0, 1]"
    if metric in _NON_NEGATIVE_METRICS and (isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0):
        return f"{metric} must be non-negative"
    if metric in _INTEGER_METRICS and (isinstance(value, bool) or not isinstance(value, int)):
        return f"{metric} must be an integer count"
    return None


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


def _validate_measurements(measurements: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    metrics: dict[str, Any] = {}
    for raw in measurements:
        if not isinstance(raw, Mapping):
            raise QualificationError("qualification measurements must be objects")
        metric = str(raw.get("metric", ""))
        if not metric or metric in metrics:
            raise QualificationError("qualification metrics must be unique and named")
        if raw.get("sample_basis") not in _SAMPLE_BASES:
            raise QualificationError("qualification measurements require a supported sample basis")
        value = raw.get("value")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            if not isinstance(value, bool):
                raise QualificationError("qualification metric values must be numeric or boolean")
        if isinstance(value, (int, float)) and not isinstance(value, bool) and not math.isfinite(float(value)):
            raise QualificationError("qualification metric values must be finite")
        domain_error = metric_domain_error(metric, value)
        if domain_error:
            raise QualificationError(f"qualification metric domain invalid: {domain_error}")
        if not isinstance(raw.get("sample_count"), int) or raw["sample_count"] < 1:
            raise QualificationError("qualification measurements require positive sample counts")
        lower = raw.get("confidence_lower")
        if not isinstance(lower, (int, float)) or isinstance(lower, bool) or not 0 <= lower <= 1:
            raise QualificationError("qualification measurements require a confidence lower bound in [0, 1]")
        method_digest = raw.get("method_digest")
        if not isinstance(method_digest, str) or len(method_digest) != 64 or any(char not in "0123456789abcdef" for char in method_digest):
            raise QualificationError("qualification measurements require a lowercase SHA-256 method digest")
        refs = raw.get("evidence_refs")
        if not isinstance(refs, Sequence) or isinstance(refs, (str, bytes)) or not refs or any(not str(ref).strip() for ref in refs):
            raise QualificationError("qualification measurements require evidence references")
        metrics[metric] = value
    return metrics


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
    if manifest.get("schema_version") != "1.0.0" or manifest.get("visibility") != "private":
        raise QualificationError("qualification manifest schema or visibility is invalid")
    if not isinstance(manifest.get("private_locator"), str) or not manifest["private_locator"].strip():
        raise QualificationError("private qualification locator is required")
    time_slice = manifest.get("time_slice")
    if not isinstance(time_slice, Mapping):
        raise QualificationError("private qualification manifest requires a time slice")
    start = _timestamp(str(time_slice.get("start", "")))
    end = _timestamp(str(time_slice.get("end", "")))
    if datetime.fromisoformat(end.replace("Z", "+00:00")) <= datetime.fromisoformat(start.replace("Z", "+00:00")):
        raise QualificationError("qualification time slice must have a positive duration")
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
    bundle_root: str,
    private_corpus_receipt_id: str,
    evaluator_id: str,
    evaluator_version: str,
    independent_judge_id: str,
    judge_verdict_refs: Sequence[str],
    measurements: Sequence[Mapping[str, Any]],
    generated_at: str,
) -> dict[str, Any]:
    if manifest.get("verification_state") != "verified":
        raise QualificationError("qualification evidence requires a verified private manifest")
    if not isinstance(bundle_root, str) or not re.fullmatch(r"[a-f0-9]{64}", bundle_root):
        raise QualificationError("qualification evidence requires a lowercase SHA-256 bundle root")
    if not evaluator_id or not evaluator_version or not independent_judge_id:
        raise QualificationError("qualification evaluator and independent judge identities are required")
    if evaluator_id == independent_judge_id:
        raise QualificationError("qualification evaluator and independent judge must be independent identities")
    if not isinstance(private_corpus_receipt_id, str) or not re.fullmatch(r"PQR-[A-F0-9]{64}", private_corpus_receipt_id):
        raise QualificationError("qualification evidence requires a content-addressed private corpus receipt")
    normalized_judge_refs = sorted(set(str(ref) for ref in judge_verdict_refs))
    if not normalized_judge_refs or any(not re.fullmatch(r"JVR-[A-F0-9]{64}", ref) for ref in normalized_judge_refs):
        raise QualificationError("qualification evidence requires content-addressed independent judge verdict references")
    normalized = []
    for item in measurements:
        normalized_item = dict(item)
        normalized_item.setdefault("sample_basis", measurement_sample_basis(str(normalized_item.get("metric", ""))))
        normalized.append(normalized_item)
    if not normalized:
        raise QualificationError("qualification evidence requires at least one measurement")
    metrics = _validate_measurements(normalized)
    evidence: dict[str, Any] = {
        "schema_version": "1.0.0",
        "manifest_id": manifest["manifest_id"],
        "bundle_root": bundle_root,
        "private_corpus_receipt_id": private_corpus_receipt_id,
        "manifest_digest": _digest({key: value for key, value in manifest.items() if key != "signature_value"}),
        "evaluator_id": evaluator_id,
        "evaluator_version": evaluator_version,
        "independent_judge_id": independent_judge_id,
        "judge_verdict_refs": normalized_judge_refs,
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
    evidence: Mapping[str, Any], *, manifest: Mapping[str, Any], public_key: Ed25519PublicKey, key_id: str | None = None, expected_bundle_root: str | None = None, root: Path | None = None
) -> dict[str, Any]:
    if evidence.get("schema_version") != "1.0.0":
        raise QualificationError("qualification evidence schema version is invalid")
    if evidence.get("evidence_id") != expected_qualification_evidence_id(evidence):
        raise QualificationError("qualification evidence identity does not match content")
    if not isinstance(evidence.get("bundle_root"), str) or not re.fullmatch(r"[a-f0-9]{64}", evidence["bundle_root"]):
        raise QualificationError("qualification evidence bundle root is invalid")
    if expected_bundle_root is not None and evidence.get("bundle_root") != expected_bundle_root:
        raise QualificationError("qualification evidence is not bound to the current bundle root")
    if manifest.get("verification_state") != "verified" or evidence.get("manifest_id") != manifest.get("manifest_id"):
        raise QualificationError("qualification evidence is not bound to a verified manifest")
    if not isinstance(evidence.get("private_corpus_receipt_id"), str) or not re.fullmatch(r"PQR-[A-F0-9]{64}", evidence["private_corpus_receipt_id"]):
        raise QualificationError("qualification evidence is not bound to a private corpus receipt")
    expected_manifest_digest = _digest({key: value for key, value in manifest.items() if key != "signature_value"})
    if evidence.get("manifest_digest") != expected_manifest_digest:
        raise QualificationError("qualification evidence manifest digest does not match the verified manifest")
    if evidence.get("evaluator_id") == evidence.get("independent_judge_id"):
        raise QualificationError("qualification evaluator and independent judge are not independent")
    judge_refs = evidence.get("judge_verdict_refs")
    if not isinstance(judge_refs, list) or not judge_refs or any(not isinstance(ref, str) or not re.fullmatch(r"JVR-[A-F0-9]{64}", ref) for ref in judge_refs):
        raise QualificationError("qualification evidence requires content-addressed independent judge verdict references")
    measurements = evidence.get("measurements")
    if not isinstance(measurements, list) or not measurements:
        raise QualificationError("qualification evidence requires measurements")
    derived_metrics = _validate_measurements(measurements)
    if evidence.get("metrics") != derived_metrics:
        raise QualificationError("qualification metrics are not derived from the measurement records")
    try:
        for measurement in measurements:
            validate_method_digest(str(measurement.get("metric", "")), str(measurement.get("method_digest", "")), root=root)
    except QualificationMethodError as exc:
        raise QualificationError(f"qualification measurement method verification failed: {exc}") from exc
    _verify(evidence, public_key, key_id=key_id)
    verified = dict(evidence)
    verified["evidence_state"] = "verified"
    return verified
