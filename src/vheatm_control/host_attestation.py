from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker

from .bundle import resolve_control_root
from .host_qualification import validate_host_qualification_run
from .serialization import load_json


class HostAttestationError(ValueError):
    """Raised when independent host attestation is malformed or unbound."""


ATTESTATION_SCHEMA_VERSION = "1.0.0"
CAPABILITY_PROFILE = "vheatm-bwrap-host-v1"


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def host_run_digest(host_run: Mapping[str, Any]) -> str:
    return _digest(dict(host_run))


def _timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HostAttestationError("host attestation timestamps must be RFC 3339") from exc
    if parsed.tzinfo is None:
        raise HostAttestationError("host attestation timestamps must include a timezone")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _identity(attestation: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in attestation.items()
        if key not in {"attestation_id", "signature_algorithm", "signature_key_id", "signature_value", "verification_state"}
    }


def expected_host_attestation_id(attestation: Mapping[str, Any]) -> str:
    return "HAT-" + _digest(_identity(attestation)).upper()


def _signing_subject(attestation: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in attestation.items()
        if key not in {"attestation_id", "signature_value", "verification_state"}
    }


def _load_schema(root: Path) -> Mapping[str, Any]:
    try:
        schema = load_json((root / "schemas" / "host-attestation.schema.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise HostAttestationError(f"host attestation schema is unavailable: {exc}") from exc
    if not isinstance(schema, Mapping):
        raise HostAttestationError("host attestation schema must be an object")
    return schema


def _validate_schema(attestation: Mapping[str, Any], *, root: Path) -> None:
    errors = sorted(
        Draft202012Validator(dict(_load_schema(root)), format_checker=FormatChecker()).iter_errors(attestation),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        location = ".".join(str(part) for part in errors[0].absolute_path) or "<root>"
        raise HostAttestationError(f"host attestation is not schema-valid at {location}: {errors[0].message}")


def _validate_host_run(host_run: Mapping[str, Any], *, root: Path) -> None:
    if host_run.get("status") != "complete":
        raise HostAttestationError("host attestation requires a complete host run")
    try:
        schema = load_json((root / "schemas" / "host-qualification-run.schema.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise HostAttestationError(f"host qualification schema is unavailable: {exc}") from exc
    issues = validate_host_qualification_run(host_run, schema, root=root)
    if issues:
        raise HostAttestationError("host run is not valid: " + "; ".join(issues))
    measurements = host_run.get("measurements")
    if not isinstance(measurements, list) or len(measurements) != 1 or measurements[0].get("metric") != "hard_stop_p99_seconds":
        raise HostAttestationError("host attestation requires a hard_stop_p99_seconds measurement")


def build_host_attestation(
    host_run: Mapping[str, Any],
    *,
    authority_id: str,
    deployment_id: str,
    generated_at: str,
    root: Path,
) -> dict[str, Any]:
    schema_root = resolve_control_root(root)
    _validate_host_run(host_run, root=schema_root)
    if not isinstance(authority_id, str) or not authority_id.strip():
        raise HostAttestationError("host attestation authority_id is required")
    if not isinstance(deployment_id, str) or not deployment_id.strip():
        raise HostAttestationError("host attestation deployment_id is required")
    attestation: dict[str, Any] = {
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "framework_version": str(host_run["framework_version"]),
        "bundle_root": str(host_run["bundle_root"]),
        "host_run_id": str(host_run["run_id"]),
        "host_run_digest": host_run_digest(host_run),
        "host_identity_digest": str(host_run["host_identity_digest"]),
        "authority_id": authority_id,
        "deployment_id": deployment_id,
        "capability_profile": CAPABILITY_PROFILE,
        "attested_metrics": ["hard_stop_p99_seconds"],
        "verification_state": "unverified",
        "signature_algorithm": None,
        "signature_key_id": None,
        "signature_value": None,
        "generated_at": _timestamp(generated_at),
    }
    attestation["attestation_id"] = expected_host_attestation_id(attestation)
    _validate_schema(attestation, root=schema_root)
    return attestation


def sign_host_attestation(
    attestation: Mapping[str, Any], *, private_key: Ed25519PrivateKey, key_id: str
) -> dict[str, Any]:
    if attestation.get("attestation_id") != expected_host_attestation_id(attestation):
        raise HostAttestationError("host attestation identity does not match content")
    if not isinstance(key_id, str) or not key_id.strip():
        raise HostAttestationError("host attestation signing key ID is required")
    signed = dict(attestation)
    signed.update({"signature_algorithm": "ed25519", "signature_key_id": key_id})
    signed["signature_value"] = base64.urlsafe_b64encode(private_key.sign(_canonical(_signing_subject(signed)))).decode("ascii")
    return signed


def verify_host_attestation(
    attestation: Mapping[str, Any],
    *,
    host_run: Mapping[str, Any],
    public_key: Ed25519PublicKey,
    key_id: str | None = None,
    expected_bundle_root: str | None = None,
    root: Path,
) -> dict[str, Any]:
    schema_root = resolve_control_root(root)
    _validate_schema(attestation, root=schema_root)
    _validate_host_run(host_run, root=schema_root)
    if attestation.get("attestation_id") != expected_host_attestation_id(attestation):
        raise HostAttestationError("host attestation identity does not match content")
    if attestation.get("host_run_digest") != host_run_digest(host_run):
        raise HostAttestationError("host attestation host run digest does not match supplied host run")
    if attestation.get("host_run_id") != host_run.get("run_id"):
        raise HostAttestationError("host attestation is not bound to the supplied host run ID")
    if expected_bundle_root is not None and attestation.get("bundle_root") != expected_bundle_root:
        raise HostAttestationError("host attestation is not bound to the current control bundle")
    for field in ("framework_version", "bundle_root", "host_identity_digest"):
        if attestation.get(field) != host_run.get(field):
            raise HostAttestationError(f"host attestation {field} is not bound to the supplied host run")
    if attestation.get("signature_algorithm") != "ed25519" or not isinstance(attestation.get("signature_value"), str):
        raise HostAttestationError("host attestation signature is missing")
    if key_id is not None and attestation.get("signature_key_id") != key_id:
        raise HostAttestationError("host attestation signing key does not match")
    try:
        public_key.verify(base64.urlsafe_b64decode(str(attestation["signature_value"])), _canonical(_signing_subject(attestation)))
    except (InvalidSignature, ValueError) as exc:
        raise HostAttestationError("host attestation signature is invalid") from exc
    verified = dict(attestation)
    verified["verification_state"] = "verified"
    return verified
