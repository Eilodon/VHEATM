from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vheatm_control.bundle import build_bundle
from vheatm_control.evaluation import evaluate_release_gates
from vheatm_control.trust_registry import (
    TrustRegistryError,
    build_trust_registry,
    expected_trust_registry_id,
    resolve_trusted_verification_keys,
    sign_trust_registry,
)
from vheatm_control.signer_service import SignerClient


ROOT = Path(__file__).resolve().parents[1]
BUNDLE_ROOT = build_bundle(ROOT)["bundle_root"]
EVALUATED_AT = "2026-08-02T12:00:00Z"


def _signer_client(key: Ed25519PrivateKey) -> SignerClient:
    def transport(request: dict[str, object]) -> dict[str, object]:
        payload = base64.urlsafe_b64decode(str(request["payload"]))
        return {
            "schema_version": "1.0.0",
            "request_id": request["request_id"],
            "framework_version": request["framework_version"],
            "bundle_root": request["bundle_root"],
            "purpose": request["purpose"],
            "key_id": request["key_id"],
            "signature_algorithm": "ed25519",
            "payload_digest": request["payload_digest"],
            "signature_value": base64.urlsafe_b64encode(key.sign(payload)).decode("ascii"),
            "signer_service_id": "test-kms",
            "signed_at": "2026-08-02T00:00:01Z",
        }

    return SignerClient(transport, root=ROOT)


def _signed_registry() -> tuple[dict, Ed25519PrivateKey, dict[str, Ed25519PrivateKey]]:
    authority = Ed25519PrivateKey.generate()
    role_keys = {
        role: Ed25519PrivateKey.generate()
        for role in ("qualification", "judge", "host", "supply_chain", "vulnerability", "provenance")
    }
    registry = build_trust_registry(
        framework_version="17.0.0-dev.1",
        bundle_root=BUNDLE_ROOT,
        authority_id="release-authority:v17",
        authority_public_key=authority.public_key(),
        authority_key_id="release-registry-key",
        role_keys={role: (key.public_key(), f"{role}-key") for role, key in role_keys.items()},
        valid_from="2026-08-01T00:00:00Z",
        valid_until="2026-08-03T00:00:00Z",
        generated_at="2026-08-02T00:00:00Z",
    )
    return sign_trust_registry(registry, private_key=authority, key_id="release-registry-key"), authority, role_keys


def test_trust_registry_verifies_authority_and_resolves_role_keys() -> None:
    signed, authority, role_keys = _signed_registry()

    keys, key_ids = resolve_trusted_verification_keys(
        signed,
        authority_public_key=authority.public_key(),
        authority_key_id="release-registry-key",
        framework_version="17.0.0-dev.1",
        expected_bundle_root=BUNDLE_ROOT,
        evaluated_at=EVALUATED_AT,
        root=ROOT,
    )

    assert set(keys) == set(role_keys)
    assert all(keys[role].public_bytes_raw() == role_keys[role].public_key().public_bytes_raw() for role in role_keys)
    assert key_ids["judge"] == "judge-key"
    assert signed["registry_id"] == expected_trust_registry_id(signed)


def test_trust_registry_can_delegate_authority_signature_to_external_signer() -> None:
    signed_fixture, authority, _ = _signed_registry()
    registry = dict(signed_fixture)
    registry["signature_algorithm"] = None
    registry["signature_key_id"] = None
    registry["signature_value"] = None
    registry["registry_id"] = expected_trust_registry_id(registry)

    signed = sign_trust_registry(
        registry,
        signer=_signer_client(authority),
        framework_version="17.0.0-dev.1",
        public_key=authority.public_key(),
        key_id="release-registry-key",
    )

    keys, _ = resolve_trusted_verification_keys(
        signed,
        authority_public_key=authority.public_key(),
        authority_key_id="release-registry-key",
        framework_version="17.0.0-dev.1",
        expected_bundle_root=BUNDLE_ROOT,
        evaluated_at=EVALUATED_AT,
        root=ROOT,
    )
    assert set(keys) == {"qualification", "judge", "host", "supply_chain", "vulnerability", "provenance"}


def test_trust_registry_external_signer_framework_binding_is_exact() -> None:
    signed_fixture, authority, _ = _signed_registry()
    registry = dict(signed_fixture)
    registry["signature_algorithm"] = None
    registry["signature_key_id"] = None
    registry["signature_value"] = None
    registry["registry_id"] = expected_trust_registry_id(registry)

    with pytest.raises(TrustRegistryError, match="framework version"):
        sign_trust_registry(
            registry,
            signer=_signer_client(authority),
            framework_version="17.0.0-wrong",
            public_key=authority.public_key(),
            key_id="release-registry-key",
        )


def test_trust_registry_rejects_bundle_replay() -> None:
    signed, authority, _ = _signed_registry()

    with pytest.raises(TrustRegistryError, match="bundle root"):
        resolve_trusted_verification_keys(
            signed,
            authority_public_key=authority.public_key(),
            authority_key_id="release-registry-key",
            framework_version="17.0.0-dev.1",
            expected_bundle_root="0" * 64,
            evaluated_at=EVALUATED_AT,
            root=ROOT,
        )


def test_trust_registry_rejects_revoked_and_expired_role_keys() -> None:
    signed, authority, _ = _signed_registry()
    revoked = dict(signed)
    revoked["keys"] = [dict(item, status="revoked", revoked_at="2026-08-02T00:00:00Z") if item["role"] == "host" else item for item in signed["keys"]]
    revoked["registry_id"] = expected_trust_registry_id(revoked)
    revoked = sign_trust_registry(revoked, private_key=authority, key_id="release-registry-key")

    revoked_keys, _ = resolve_trusted_verification_keys(
        revoked,
        authority_public_key=authority.public_key(),
        authority_key_id="release-registry-key",
        framework_version="17.0.0-dev.1",
        expected_bundle_root=BUNDLE_ROOT,
        evaluated_at=EVALUATED_AT,
        root=ROOT,
    )
    assert "host" not in revoked_keys

    expired = dict(signed)
    expired["valid_until"] = (datetime.now(UTC) - timedelta(days=1)).isoformat().replace("+00:00", "Z")
    expired["registry_id"] = expected_trust_registry_id(expired)
    expired = sign_trust_registry(expired, private_key=authority, key_id="release-registry-key")
    with pytest.raises(TrustRegistryError, match="registry validity"):
        resolve_trusted_verification_keys(
            expired,
            authority_public_key=authority.public_key(),
            authority_key_id="release-registry-key",
            framework_version="17.0.0-dev.1",
            expected_bundle_root=BUNDLE_ROOT,
            evaluated_at=EVALUATED_AT,
            root=ROOT,
        )


def test_release_evaluator_rejects_direct_role_keys_without_signed_registry() -> None:
    key = Ed25519PrivateKey.generate()
    report = evaluate_release_gates(
        "17.0.0-dev.1",
        {"host_qualification_attestation": {"signature_algorithm": "ed25519"}},
        expected_bundle_root=BUNDLE_ROOT,
        verification_keys={"host": key.public_key()},
        verification_key_ids={"host": "host-key"},
        evaluated_at=EVALUATED_AT,
        schema_root=ROOT,
    )

    assert any("trusted key registry" in item["rationale"] for item in report["gates"])
