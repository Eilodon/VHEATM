from __future__ import annotations

import base64
import binascii
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from jsonschema import Draft202012Validator, FormatChecker

from .bundle import resolve_control_root
from .serialization import load_json
from .signer_service import SignerClient, SignerServiceError


TRUSTED_ROLES = frozenset({"qualification", "judge", "host", "supply_chain", "vulnerability", "provenance"})
_SIGNATURE_FIELDS = frozenset({"signature_algorithm", "signature_key_id", "signature_value"})
_KEY_ID_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"


class TrustRegistryError(ValueError):
    """Raised when an external trust-key registry cannot authorize evidence."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise TrustRegistryError("trust registry contains non-canonical data") from exc


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _bytes_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _public_key_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _encode_public_key(key: Ed25519PublicKey) -> str:
    return base64.urlsafe_b64encode(_public_key_bytes(key)).decode("ascii")


def _decode_public_key(value: Any) -> Ed25519PublicKey:
    if not isinstance(value, str):
        raise TrustRegistryError("trust registry public key is invalid")
    try:
        decoded = base64.b64decode(value, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise TrustRegistryError("trust registry public key encoding is invalid") from exc
    if len(decoded) != 32:
        raise TrustRegistryError("trust registry public key must be an Ed25519 key")
    try:
        return Ed25519PublicKey.from_public_bytes(decoded)
    except ValueError as exc:
        raise TrustRegistryError("trust registry public key is invalid") from exc


def _decode_signature(value: Any) -> bytes:
    if not isinstance(value, str):
        raise TrustRegistryError("trust registry signature is missing")
    try:
        return base64.b64decode(value, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise TrustRegistryError("trust registry signature encoding is invalid") from exc


def _parse_timestamp(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str) or not FormatChecker().conforms(value, "date-time"):
        raise TrustRegistryError(f"trust registry {field} must be an RFC 3339 date-time")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TrustRegistryError(f"trust registry {field} must be an RFC 3339 date-time") from exc
    if parsed.tzinfo is None:
        raise TrustRegistryError(f"trust registry {field} must include a timezone")
    return parsed.astimezone(UTC)


def _schema(root: Path | None) -> Mapping[str, Any]:
    control_root = resolve_control_root(root)
    try:
        schema = load_json((control_root / "schemas" / "trust-key-registry.schema.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise TrustRegistryError("trust registry schema is unavailable") from exc
    if not isinstance(schema, Mapping):
        raise TrustRegistryError("trust registry schema must be an object")
    return schema


def _validate_schema(registry: Mapping[str, Any], *, root: Path | None) -> None:
    issues = sorted(Draft202012Validator(dict(_schema(root)), format_checker=FormatChecker()).iter_errors(registry), key=lambda error: list(error.absolute_path))
    if issues:
        location = ".".join(str(part) for part in issues[0].absolute_path) or "<root>"
        raise TrustRegistryError(f"trust registry schema validation failed at {location}: {issues[0].message}")


def _identity(registry: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in registry.items() if key not in {"registry_id", *_SIGNATURE_FIELDS}}


def _signed_subject(registry: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in registry.items() if key not in _SIGNATURE_FIELDS}


def expected_trust_registry_id(registry: Mapping[str, Any]) -> str:
    return "KRG-" + _digest(_identity(registry)).upper()


def _validate_common_identity(registry: Mapping[str, Any]) -> None:
    if not isinstance(registry, Mapping):
        raise TrustRegistryError("trust registry must be an object")
    if registry.get("schema_version") != "1.0.0":
        raise TrustRegistryError("trust registry schema version is invalid")
    if registry.get("registry_id") != expected_trust_registry_id(registry):
        raise TrustRegistryError("trust registry identity does not match content")
    if registry.get("signature_algorithm") != "ed25519":
        raise TrustRegistryError("trust registry requires an Ed25519 signature")
    if not isinstance(registry.get("signature_value"), str) or not registry["signature_value"]:
        raise TrustRegistryError("trust registry signature is missing")
    if registry.get("signature_key_id") != registry.get("authority_key_id"):
        raise TrustRegistryError("trust registry signature key does not match authority key")
    if not isinstance(registry.get("authority_id"), str) or not registry["authority_id"].strip():
        raise TrustRegistryError("trust registry authority ID is required")
    if not isinstance(registry.get("authority_key_id"), str) or not registry["authority_key_id"].strip():
        raise TrustRegistryError("trust registry authority key ID is required")


def _validate_windows(registry: Mapping[str, Any], *, evaluated_at: str) -> datetime:
    registry_from = _parse_timestamp(registry.get("valid_from"), field="valid_from")
    registry_until = _parse_timestamp(registry.get("valid_until"), field="valid_until")
    if registry_from >= registry_until:
        raise TrustRegistryError("trust registry validity window is invalid")
    evaluated = _parse_timestamp(evaluated_at, field="evaluation time")
    if evaluated < registry_from or evaluated > registry_until:
        raise TrustRegistryError("trust registry validity window does not cover evaluation time")
    return evaluated


def _validate_keys(registry: Mapping[str, Any], *, evaluated: datetime) -> list[dict[str, Any]]:
    raw_keys = registry.get("keys")
    if not isinstance(raw_keys, list):
        raise TrustRegistryError("trust registry keys must be an array")
    seen_ids: set[str] = set()
    seen_roles: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for item in raw_keys:
        if not isinstance(item, Mapping):
            raise TrustRegistryError("trust registry key entry must be an object")
        role = item.get("role")
        key_id = item.get("key_id")
        if role not in TRUSTED_ROLES:
            raise TrustRegistryError("trust registry key role is not supported")
        if not isinstance(key_id, str) or not key_id or any(char not in _KEY_ID_CHARS for char in key_id):
            raise TrustRegistryError("trust registry key ID is invalid")
        if key_id in seen_ids:
            raise TrustRegistryError("trust registry contains duplicate key IDs")
        seen_ids.add(key_id)
        key = _decode_public_key(item.get("public_key"))
        key_from = _parse_timestamp(item.get("valid_from"), field=f"key {key_id} valid_from")
        key_until = _parse_timestamp(item.get("valid_until"), field=f"key {key_id} valid_until")
        if key_from >= key_until:
            raise TrustRegistryError(f"trust registry key {key_id} validity window is invalid")
        if key_from < _parse_timestamp(registry.get("valid_from"), field="valid_from") or key_until > _parse_timestamp(registry.get("valid_until"), field="valid_until"):
            raise TrustRegistryError(f"trust registry key {key_id} escapes registry validity")
        status = item.get("status")
        if status == "active":
            if role in seen_roles:
                raise TrustRegistryError(f"trust registry has ambiguous active keys for role {role}")
            seen_roles.add(role)
            if evaluated < key_from or evaluated > key_until:
                raise TrustRegistryError(f"trust registry key {key_id} is outside its validity window")
        elif status == "revoked":
            revoked_at = _parse_timestamp(item.get("revoked_at"), field=f"key {key_id} revoked_at")
            if revoked_at > evaluated:
                raise TrustRegistryError(f"trust registry key {key_id} has a future revocation")
        else:
            raise TrustRegistryError(f"trust registry key {key_id} has an invalid status")
        normalized.append({**dict(item), "public_key_object": key})
    return normalized


def build_trust_registry(
    *,
    framework_version: str,
    bundle_root: str,
    authority_id: str,
    authority_public_key: Ed25519PublicKey,
    authority_key_id: str,
    role_keys: Mapping[str, tuple[Ed25519PublicKey, str]],
    valid_from: str,
    valid_until: str,
    generated_at: str,
) -> dict[str, Any]:
    if not isinstance(framework_version, str) or not framework_version.strip():
        raise TrustRegistryError("trust registry framework version is required")
    if not isinstance(bundle_root, str) or len(bundle_root) != 64 or any(char not in "0123456789abcdef" for char in bundle_root):
        raise TrustRegistryError("trust registry bundle root must be a lowercase SHA-256 digest")
    if not isinstance(authority_public_key, Ed25519PublicKey):
        raise TrustRegistryError("trust registry authority key must be Ed25519")
    if not isinstance(authority_id, str) or not authority_id.strip() or not isinstance(authority_key_id, str) or not authority_key_id.strip():
        raise TrustRegistryError("trust registry authority identity is required")
    if not isinstance(role_keys, Mapping) or not role_keys:
        raise TrustRegistryError("trust registry requires at least one role key")
    registry_from = _parse_timestamp(valid_from, field="valid_from")
    registry_until = _parse_timestamp(valid_until, field="valid_until")
    if registry_from >= registry_until:
        raise TrustRegistryError("trust registry validity window is invalid")
    _parse_timestamp(generated_at, field="generated_at")
    entries: list[dict[str, Any]] = []
    for role in sorted(role_keys):
        if role not in TRUSTED_ROLES:
            raise TrustRegistryError(f"trust registry role is not supported: {role}")
        value = role_keys[role]
        if not isinstance(value, tuple) or len(value) != 2 or not isinstance(value[0], Ed25519PublicKey) or not isinstance(value[1], str) or not value[1].strip():
            raise TrustRegistryError(f"trust registry key binding is invalid for role {role}")
        entries.append({"role": role, "key_id": value[1], "public_key": _encode_public_key(value[0]), "status": "active", "valid_from": valid_from, "valid_until": valid_until})
    registry: dict[str, Any] = {
        "schema_version": "1.0.0",
        "framework_version": framework_version,
        "bundle_root": bundle_root,
        "authority_id": authority_id,
        "authority_key_id": authority_key_id,
        "authority_key_digest": _bytes_digest(_public_key_bytes(authority_public_key)),
        "valid_from": valid_from,
        "valid_until": valid_until,
        "keys": entries,
        "signature_algorithm": None,
        "signature_key_id": None,
        "signature_value": None,
        "generated_at": generated_at,
    }
    registry["registry_id"] = expected_trust_registry_id(registry)
    return registry


def sign_trust_registry(
    registry: Mapping[str, Any], *, private_key: Ed25519PrivateKey | None = None, key_id: str,
    signer: SignerClient | None = None, framework_version: str | None = None,
    public_key: Ed25519PublicKey | None = None, created_at: str | None = None,
) -> dict[str, Any]:
    _validate_common_identity({**dict(registry), "signature_algorithm": "ed25519", "signature_key_id": key_id, "signature_value": "placeholder"})
    if key_id != registry.get("authority_key_id"):
        raise TrustRegistryError("trust registry signing key does not match authority key")
    if signer is not None:
        if private_key is not None:
            raise TrustRegistryError("external signer and local private key cannot be combined")
        if not isinstance(public_key, Ed25519PublicKey):
            raise TrustRegistryError("external signer requires the expected authority public key")
        if _bytes_digest(_public_key_bytes(public_key)) != registry.get("authority_key_digest"):
            raise TrustRegistryError("external signer public key does not match authority key digest")
        if not isinstance(framework_version, str) or not framework_version.strip():
            raise TrustRegistryError("external signer requires the canonical framework version")
        if framework_version != registry.get("framework_version"):
            raise TrustRegistryError("external signer framework version does not match trust registry")
    elif not isinstance(private_key, Ed25519PrivateKey):
        raise TrustRegistryError("trust registry signing key must be Ed25519")
    else:
        if _bytes_digest(_public_key_bytes(private_key.public_key())) != registry.get("authority_key_digest"):
            raise TrustRegistryError("trust registry signing key does not match authority key digest")
    signed = dict(registry)
    signed.update({"signature_algorithm": "ed25519", "signature_key_id": key_id})
    if signer is not None:
        try:
            receipt = signer.sign(
                _canonical(_signed_subject(signed)),
                framework_version=framework_version,
                bundle_root=str(signed.get("bundle_root", "")),
                purpose="authority",
                key_id=key_id,
                public_key=public_key,
                created_at=str(created_at or signed.get("generated_at", "")),
            )
        except SignerServiceError as exc:
            raise TrustRegistryError(str(exc)) from exc
        signed["signature_value"] = str(receipt["signature_value"])
    else:
        signed["signature_value"] = base64.urlsafe_b64encode(private_key.sign(_canonical(_signed_subject(signed)))).decode("ascii")
    _validate_schema(signed, root=None)
    return signed


def resolve_trusted_verification_keys(
    registry: Mapping[str, Any],
    *,
    authority_public_key: Ed25519PublicKey,
    authority_key_id: str,
    framework_version: str,
    expected_bundle_root: str,
    evaluated_at: str,
    root: Path | None = None,
) -> tuple[dict[str, Ed25519PublicKey], dict[str, str]]:
    _validate_schema(registry, root=root)
    _validate_common_identity(registry)
    if not isinstance(authority_public_key, Ed25519PublicKey):
        raise TrustRegistryError("trust registry authority public key is required")
    if registry.get("signature_key_id") != authority_key_id:
        raise TrustRegistryError("trust registry authority key ID does not match")
    if registry.get("framework_version") != framework_version:
        raise TrustRegistryError("trust registry framework version does not match release")
    if registry.get("bundle_root") != expected_bundle_root:
        raise TrustRegistryError("trust registry is not bound to the current bundle root")
    if registry.get("authority_key_digest") != _bytes_digest(_public_key_bytes(authority_public_key)):
        raise TrustRegistryError("trust registry authority key digest does not match supplied authority key")
    evaluated = _validate_windows(registry, evaluated_at=evaluated_at)
    entries = _validate_keys(registry, evaluated=evaluated)
    try:
        authority_public_key.verify(_decode_signature(registry.get("signature_value")), _canonical(_signed_subject(registry)))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise TrustRegistryError("trust registry authority signature is invalid") from exc
    keys: dict[str, Ed25519PublicKey] = {}
    key_ids: dict[str, str] = {}
    for entry in entries:
        if entry["status"] == "active":
            role = str(entry["role"])
            keys[role] = entry["public_key_object"]
            key_ids[role] = str(entry["key_id"])
    return keys, key_ids
