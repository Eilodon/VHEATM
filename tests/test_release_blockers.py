from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

from vheatm_control.serialization import load_yaml
from vheatm_control.supply_chain import (
    SupplyChainError,
    build_supply_chain_attestation,
    build_vulnerability_scan,
    expected_provenance_statement_id,
    sign_supply_chain_attestation,
    sign_provenance_statement,
    sign_vulnerability_scan,
    verify_provenance_statement,
    verify_supply_chain_attestation,
    verify_vulnerability_scan,
    verify_vulnerability_scan_freshness,
)
from vheatm_control.supply_chain_policy import distinct_signing_key_roles, vulnerability_scan_max_age_seconds
from vheatm_control.signer_service import SignerClient


ROOT = Path(__file__).resolve().parents[1]


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
            "signed_at": "2026-08-01T00:00:01Z",
        }

    return SignerClient(transport, root=ROOT)


def test_standards_baseline_is_present_and_schema_valid() -> None:
    policy_path = ROOT / "policies" / "standards-baseline.yaml"
    schema_path = ROOT / "schemas" / "standards-baseline.schema.json"
    assert policy_path.is_file()
    assert schema_path.is_file()

    policy = load_yaml(policy_path.read_text(encoding="utf-8"))
    schema = __import__("json").loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(policy)
    assert policy["framework_version"] == "17.0.0-dev.1"
    assert any(item["namespace"] == "normative" for item in policy["standards"])
    assert all(item["namespace"] in {"normative", "community", "draft", "experimental"} for item in policy["standards"])


def test_supply_chain_evidence_policy_is_canonical_and_fail_closed() -> None:
    policy_path = ROOT / "policies" / "supply-chain-evidence.yaml"
    schema_path = ROOT / "schemas" / "supply-chain-evidence.schema.json"
    policy = load_yaml(policy_path.read_text(encoding="utf-8"))
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(policy)
    assert vulnerability_scan_max_age_seconds(ROOT) == 604800
    assert distinct_signing_key_roles(ROOT) == ("supply_chain", "vulnerability", "provenance")


def test_supply_chain_attestation_binds_verified_uv_lock() -> None:
    lock_path = ROOT / "uv.lock"
    assert lock_path.is_file()
    attestation = build_supply_chain_attestation(ROOT, generated_at="2026-08-01T00:00:00Z")
    assert attestation["dependency_lock_present"] is True
    assert attestation["dependency_lock_digest"] == hashlib.sha256(lock_path.read_bytes()).hexdigest()
    assert attestation["dependency_lock_path"] == "uv.lock"


def test_vulnerability_scan_cannot_be_future_dated_against_evaluation() -> None:
    scan = build_vulnerability_scan(
        scanner_id="test-scanner",
        scanner_version="1.0.0",
        target_bundle_root="a" * 64,
        target_lock_digest="b" * 64,
        findings=[],
        generated_at="2026-08-02T00:00:00Z",
    )
    with pytest.raises(SupplyChainError, match="after the release evaluation"):
        verify_vulnerability_scan_freshness(scan, evaluated_at="2026-08-01T00:00:00Z", root=ROOT)


def test_signed_attestation_and_vulnerability_scan_are_cryptographically_bound() -> None:
    key = Ed25519PrivateKey.generate()
    public_key = key.public_key()
    attestation = build_supply_chain_attestation(ROOT, generated_at="2026-08-01T00:00:00Z")
    scan = build_vulnerability_scan(
        scanner_id="test-scanner",
        scanner_version="1.0.0",
        target_bundle_root=attestation["bundle_root"],
        target_lock_digest=attestation["dependency_lock_digest"],
        findings=[
            {"vulnerability_id": "CVE-2026-1234", "package": "example", "severity": "critical", "exploitable": True},
            {"vulnerability_id": "CVE-2026-5678", "package": "example", "severity": "high", "exploitable": False},
        ],
        generated_at="2026-08-01T00:00:00Z",
    )
    signed_scan = sign_vulnerability_scan(scan, private_key=key, key_id="scanner-key")
    verified_scan = verify_vulnerability_scan(
        signed_scan,
        public_key=public_key,
        bundle_root=attestation["bundle_root"],
        lock_digest=attestation["dependency_lock_digest"],
        key_id="scanner-key",
    )
    assert verified_scan["verification_state"] == "verified"
    assert verified_scan["critical_exploitable_cve_count"] == 1

    bound = build_supply_chain_attestation(ROOT, generated_at="2026-08-01T00:00:00Z", vulnerability_scan=verified_scan)
    signed = sign_supply_chain_attestation(bound, private_key=key, key_id="release-key")
    verified = verify_supply_chain_attestation(signed, public_key=public_key, key_id="release-key")
    assert verified["signed_release"] is True
    assert verified["verification_state"] == "verified"
    assert verified["vulnerability_scan_id"] == verified_scan["scan_id"]
    schema = json.loads((ROOT / "schemas" / "supply-chain-attestation.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(verified)

    provenance = {
        "schema_version": "1.0.0",
        "bundle_root": verified["bundle_root"],
        "sbom_digest": verified["sbom_digest"],
        "builder_id": "builder:test",
        "build_type": "test-build",
        "verified": True,
        "signature_algorithm": "ed25519",
        "signature_key_id": "provenance-key",
        "signature_value": None,
        "generated_at": "2026-08-01T00:00:00Z",
    }
    provenance["statement_id"] = expected_provenance_statement_id(provenance)
    provenance = sign_provenance_statement(provenance, private_key=key, key_id="provenance-key")
    with_provenance = verify_provenance_statement(verified, provenance, public_key=public_key, key_id="provenance-key")
    assert with_provenance["provenance_verified"] is True

    tampered = dict(signed)
    tampered["bundle_root"] = "0" * 64
    with pytest.raises(SupplyChainError, match="attestation_id"):
        verify_supply_chain_attestation(tampered, public_key=public_key)


def test_supply_chain_artifacts_can_be_signed_only_through_external_signer_client() -> None:
    key = Ed25519PrivateKey.generate()
    signer = _signer_client(key)
    attestation = build_supply_chain_attestation(ROOT, generated_at="2026-08-01T00:00:00Z")
    signed_attestation = sign_supply_chain_attestation(
        attestation,
        signer=signer,
        framework_version="17.0.0-dev.1",
        public_key=key.public_key(),
        key_id="release-key",
    )
    assert verify_supply_chain_attestation(signed_attestation, public_key=key.public_key(), key_id="release-key")["signed_release"] is True

    scan = build_vulnerability_scan(
        scanner_id="test-scanner",
        scanner_version="1.0.0",
        target_bundle_root=attestation["bundle_root"],
        target_lock_digest=attestation["dependency_lock_digest"],
        findings=[],
        generated_at="2026-08-01T00:00:00Z",
    )
    signed_scan = sign_vulnerability_scan(
        scan,
        signer=signer,
        framework_version="17.0.0-dev.1",
        public_key=key.public_key(),
        key_id="scanner-key",
    )
    assert verify_vulnerability_scan(
        signed_scan,
        public_key=key.public_key(),
        bundle_root=attestation["bundle_root"],
        lock_digest=attestation["dependency_lock_digest"],
        key_id="scanner-key",
    )["verification_state"] == "verified"

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
    signed_provenance = sign_provenance_statement(
        provenance,
        signer=signer,
        framework_version="17.0.0-dev.1",
        public_key=key.public_key(),
        key_id="provenance-key",
    )
    assert verify_provenance_statement(
        signed_attestation,
        signed_provenance,
        public_key=key.public_key(),
        key_id="provenance-key",
    )["provenance_verified"] is True


def test_supply_chain_signer_service_failure_never_falls_back_to_private_signing() -> None:
    key = Ed25519PrivateKey.generate()
    signer = SignerClient(lambda _: (_ for _ in ()).throw(OSError("kms unavailable")), root=ROOT)
    attestation = build_supply_chain_attestation(ROOT, generated_at="2026-08-01T00:00:00Z")

    with pytest.raises(SupplyChainError, match="signer service unavailable"):
        sign_supply_chain_attestation(
            attestation,
            signer=signer,
            framework_version="17.0.0-dev.1",
            public_key=key.public_key(),
            key_id="release-key",
        )
