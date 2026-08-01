from __future__ import annotations

import base64
import hashlib
import json
import re
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .bundle import build_bundle
from .supply_chain_policy import SupplyChainPolicyError, vulnerability_scan_max_age_seconds


class SupplyChainError(ValueError):
    """Raised when signed supply-chain evidence is malformed or mismatched."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SupplyChainError("supply-chain timestamps must be RFC 3339") from exc
    if parsed.tzinfo is None:
        raise SupplyChainError("supply-chain timestamps must include a timezone")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value.encode("ascii"))
    except (ValueError, UnicodeError) as exc:
        raise SupplyChainError("signature is not valid base64url") from exc


def _attestation_identity(attestation: Mapping[str, Any]) -> dict[str, Any]:
    derived = {
        "attestation_id",
        "signed_release",
        "signature_algorithm",
        "signature_key_id",
        "signature_value",
        "provenance_verified",
        "verification_state",
        "generated_at",
    }
    return {key: value for key, value in attestation.items() if key not in derived}


def expected_attestation_id(attestation: Mapping[str, Any]) -> str:
    return "SCA-" + _digest(_attestation_identity(attestation)).upper()


def _signed_subject(document: Mapping[str, Any]) -> dict[str, Any]:
    subject = {
        key: value
        for key, value in document.items()
        if key not in {"attestation_id", "scan_id", "statement_id", "signature_algorithm", "signature_key_id", "signature_value", "verification_state"}
    }
    if "signed_release" in subject:
        subject["signed_release"] = True
    return subject


def _sign(subject: Mapping[str, Any], private_key: Ed25519PrivateKey) -> str:
    return _b64(private_key.sign(_canonical(subject)))


def _verify(document: Mapping[str, Any], public_key: Ed25519PublicKey, *, key_id: str | None = None) -> None:
    if document.get("signature_algorithm") != "ed25519":
        raise SupplyChainError("evidence must use an Ed25519 signature")
    if key_id is not None and document.get("signature_key_id") != key_id:
        raise SupplyChainError("evidence signature key does not match the expected key")
    value = document.get("signature_value")
    if not isinstance(value, str) or not value:
        raise SupplyChainError("evidence signature is missing")
    try:
        public_key.verify(_unb64(value), _canonical(_signed_subject(document)))
    except InvalidSignature as exc:
        raise SupplyChainError("evidence signature is invalid") from exc


def _dependencies(root: Path) -> list[dict[str, str]]:
    text = (root / "pyproject.toml").read_text(encoding="utf-8")
    dependencies: list[dict[str, str]] = []
    in_dependencies = False
    for line in text.splitlines():
        if line.strip() == "dependencies = [":
            in_dependencies = True
            continue
        if in_dependencies and line.strip() == "]":
            in_dependencies = False
            continue
        if in_dependencies:
            match = re.search(r'"([^">=<!~]+)([^" ]*)"', line)
            if match:
                dependencies.append({"name": match.group(1).strip(), "specifier": match.group(2).strip() or "*"})
    return dependencies


def _lock_binding(root: Path) -> tuple[bool, str | None, str | None]:
    lock_path = root / "uv.lock"
    if not lock_path.is_file() or lock_path.is_symlink():
        return False, None, None
    try:
        lock_document = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return False, None, None
    valid = lock_document.get("version") == 1 and isinstance(lock_document.get("package"), list) and bool(lock_document["package"])
    if not valid:
        return False, None, None
    return True, "uv.lock", hashlib.sha256(lock_path.read_bytes()).hexdigest()


def _scan_binding(scan: Mapping[str, Any] | None) -> tuple[str | None, str | None, int | None]:
    if not isinstance(scan, Mapping) or scan.get("verification_state") != "verified":
        return None, None, None
    scan_id = str(scan.get("scan_id", ""))
    if not re.fullmatch(r"VUL-[A-F0-9]{64}", scan_id):
        raise SupplyChainError("verified vulnerability scan has an invalid scan_id")
    count = scan.get("critical_exploitable_cve_count")
    if not isinstance(count, int) or count < 0:
        raise SupplyChainError("verified vulnerability scan has an invalid critical count")
    return scan_id, _digest({key: value for key, value in scan.items() if key != "signature_value"}), count


def build_supply_chain_attestation(
    root: Path,
    *,
    generated_at: str | None = None,
    vulnerability_scan: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    bundle = build_bundle(root)
    sbom = [{"path": entry["path"], "sha256": entry["sha256"]} for entry in bundle["entries"]]
    sbom_digest = hashlib.sha256(_canonical(sbom)).hexdigest()
    lock_present, lock_path, lock_digest = _lock_binding(root)
    scan_id, scan_digest, critical_count = _scan_binding(vulnerability_scan)
    identity: dict[str, Any] = {
        "schema_version": "1.0.0",
        "bundle_root": bundle["bundle_root"],
        "sbom": sbom,
        "sbom_digest": sbom_digest,
        "dependencies": _dependencies(root),
        "dependency_lock_present": lock_present,
        "dependency_lock_path": lock_path,
        "dependency_lock_digest": lock_digest,
        "signed_release": False,
        "signature_algorithm": None,
        "signature_key_id": None,
        "signature_value": None,
        "provenance_verified": False,
        "vulnerability_scan_id": scan_id,
        "vulnerability_scan_digest": scan_digest,
        "critical_exploitable_cve_count": critical_count,
        "verification_state": "partial",
    }
    timestamp = _timestamp(generated_at or datetime.now(UTC).isoformat().replace("+00:00", "Z"))
    return {"attestation_id": expected_attestation_id(identity), **identity, "generated_at": timestamp}


def sign_supply_chain_attestation(
    attestation: Mapping[str, Any], *, private_key: Ed25519PrivateKey, key_id: str
) -> dict[str, Any]:
    if not key_id.strip():
        raise SupplyChainError("supply-chain signing key_id is required")
    if attestation.get("attestation_id") != expected_attestation_id(attestation):
        raise SupplyChainError("attestation_id does not match immutable attestation content")
    signed = dict(attestation)
    signed.update({"signed_release": True, "signature_algorithm": "ed25519", "signature_key_id": key_id, "verification_state": "partial"})
    signed["signature_value"] = _sign(_signed_subject(signed), private_key)
    return signed


def verify_supply_chain_attestation(
    attestation: Mapping[str, Any], *, public_key: Ed25519PublicKey, key_id: str | None = None, root: Path | None = None
) -> dict[str, Any]:
    if attestation.get("schema_version") != "1.0.0":
        raise SupplyChainError("attestation schema version is invalid")
    if attestation.get("attestation_id") != expected_attestation_id(attestation):
        raise SupplyChainError("attestation_id does not match immutable attestation content")
    sbom = attestation.get("sbom")
    if not isinstance(sbom, list) or not sbom or attestation.get("sbom_digest") != hashlib.sha256(_canonical(sbom)).hexdigest():
        raise SupplyChainError("attestation SBOM digest is not derived from its canonical entries")
    if any(
        not isinstance(item, Mapping)
        or not isinstance(item.get("path"), str)
        or not item["path"]
        or not isinstance(item.get("sha256"), str)
        or len(item["sha256"]) != 64
        or any(char not in "0123456789abcdef" for char in item["sha256"])
        for item in sbom
    ):
        raise SupplyChainError("attestation SBOM entries are malformed")
    if attestation.get("dependency_lock_present") is True:
        if not isinstance(attestation.get("dependency_lock_path"), str) or not isinstance(attestation.get("dependency_lock_digest"), str):
            raise SupplyChainError("locked release attestation is missing its dependency-lock binding")
        if len(attestation["dependency_lock_digest"]) != 64 or any(char not in "0123456789abcdef" for char in attestation["dependency_lock_digest"]):
            raise SupplyChainError("dependency-lock digest is malformed")
    if root is not None:
        try:
            canonical = build_supply_chain_attestation(root, generated_at=str(attestation.get("generated_at")))
        except (OSError, ValueError) as exc:
            raise SupplyChainError(f"canonical bundle binding cannot be verified: {exc}") from exc
        for field in (
            "bundle_root",
            "sbom",
            "sbom_digest",
            "dependencies",
            "dependency_lock_present",
            "dependency_lock_path",
            "dependency_lock_digest",
        ):
            if attestation.get(field) != canonical.get(field):
                raise SupplyChainError(f"attestation {field} is not bound to the current canonical bundle")
    _verify(attestation, public_key, key_id=key_id)
    verified = dict(attestation)
    verified.update({"signed_release": True, "verification_state": "verified"})
    return verified


def expected_vulnerability_scan_id(scan: Mapping[str, Any]) -> str:
    identity = {key: value for key, value in scan.items() if key not in {"scan_id", "verification_state", "signature_algorithm", "signature_key_id", "signature_value"}}
    return "VUL-" + _digest(identity).upper()


def build_vulnerability_scan(
    *,
    scanner_id: str,
    scanner_version: str,
    target_bundle_root: str,
    target_lock_digest: str,
    findings: list[Mapping[str, Any]],
    generated_at: str,
) -> dict[str, Any]:
    normalized = [dict(item) for item in findings]
    if len({item.get("vulnerability_id") for item in normalized}) != len(normalized):
        raise SupplyChainError("vulnerability IDs must be unique")
    critical_count = sum(1 for item in normalized if item.get("severity") == "critical" and item.get("exploitable") is True)
    scan: dict[str, Any] = {
        "schema_version": "1.0.0",
        "scanner_id": scanner_id,
        "scanner_version": scanner_version,
        "target_bundle_root": target_bundle_root,
        "target_lock_digest": target_lock_digest,
        "findings": normalized,
        "critical_exploitable_cve_count": critical_count,
        "verification_state": "unverified",
        "signature_algorithm": None,
        "signature_key_id": None,
        "signature_value": None,
        "generated_at": _timestamp(generated_at),
    }
    scan["scan_id"] = expected_vulnerability_scan_id(scan)
    return scan


def sign_vulnerability_scan(scan: Mapping[str, Any], *, private_key: Ed25519PrivateKey, key_id: str) -> dict[str, Any]:
    if scan.get("scan_id") != expected_vulnerability_scan_id(scan):
        raise SupplyChainError("scan_id does not match immutable scan content")
    signed = dict(scan)
    signed.update({"signature_algorithm": "ed25519", "signature_key_id": key_id})
    signed["signature_value"] = _sign(_signed_subject(signed), private_key)
    return signed


def verify_vulnerability_scan(
    scan: Mapping[str, Any],
    *,
    public_key: Ed25519PublicKey,
    bundle_root: str,
    lock_digest: str,
    key_id: str | None = None,
) -> dict[str, Any]:
    if scan.get("schema_version") != "1.0.0" or not isinstance(scan.get("scanner_id"), str) or not scan["scanner_id"].strip() or not isinstance(scan.get("scanner_version"), str) or not scan["scanner_version"].strip():
        raise SupplyChainError("vulnerability scan identity is malformed")
    if scan.get("scan_id") != expected_vulnerability_scan_id(scan):
        raise SupplyChainError("scan_id does not match immutable scan content")
    if scan.get("target_bundle_root") != bundle_root or scan.get("target_lock_digest") != lock_digest:
        raise SupplyChainError("vulnerability scan target is not bound to this release")
    findings = scan.get("findings")
    if not isinstance(findings, list):
        raise SupplyChainError("vulnerability scan findings must be an array")
    vulnerability_ids: set[str] = set()
    for finding in findings:
        if not isinstance(finding, Mapping):
            raise SupplyChainError("vulnerability findings must be objects")
        vulnerability_id = finding.get("vulnerability_id")
        if not isinstance(vulnerability_id, str) or not re.fullmatch(r"(?:CVE-[0-9]{4}-[0-9]+|GHSA-[A-Za-z0-9-]+)", vulnerability_id):
            raise SupplyChainError("vulnerability finding ID is malformed")
        if vulnerability_id in vulnerability_ids or not isinstance(finding.get("package"), str) or not finding["package"].strip() or finding.get("severity") not in {"low", "medium", "high", "critical", "unknown"} or not isinstance(finding.get("exploitable"), bool):
            raise SupplyChainError("vulnerability finding is malformed or duplicated")
        vulnerability_ids.add(vulnerability_id)
    expected_count = sum(1 for item in findings if item.get("severity") == "critical" and item.get("exploitable") is True)
    if scan.get("critical_exploitable_cve_count") != expected_count:
        raise SupplyChainError("vulnerability critical count is not derived from findings")
    _verify(scan, public_key, key_id=key_id)
    verified = dict(scan)
    verified["verification_state"] = "verified"
    return verified


def verify_vulnerability_scan_freshness(
    scan: Mapping[str, Any], *, evaluated_at: str, root: Path | None = None
) -> None:
    """Enforce the canonical time-of-evaluation freshness boundary for a scan."""

    if not isinstance(evaluated_at, str) or not evaluated_at:
        raise SupplyChainError("vulnerability scan freshness requires an evaluation timestamp")
    try:
        generated = datetime.fromisoformat(str(scan.get("generated_at")).replace("Z", "+00:00"))
        evaluated = datetime.fromisoformat(evaluated_at.replace("Z", "+00:00"))
        max_age = vulnerability_scan_max_age_seconds(root)
    except (TypeError, ValueError, SupplyChainPolicyError) as exc:
        raise SupplyChainError(f"vulnerability scan freshness policy cannot be verified: {exc}") from exc
    if generated.tzinfo is None or evaluated.tzinfo is None:
        raise SupplyChainError("vulnerability scan freshness timestamps must include a timezone")
    generated = generated.astimezone(UTC)
    evaluated = evaluated.astimezone(UTC)
    age_seconds = (evaluated - generated).total_seconds()
    if age_seconds < 0:
        raise SupplyChainError("vulnerability scan was generated after the release evaluation")
    if age_seconds > max_age:
        raise SupplyChainError(f"vulnerability scan is stale: age exceeds canonical {max_age}-second window")


def expected_provenance_statement_id(statement: Mapping[str, Any]) -> str:
    identity = {key: value for key, value in statement.items() if key not in {"statement_id", "signature_algorithm", "signature_key_id", "signature_value"}}
    return "PROV-" + _digest(identity).upper()


def sign_provenance_statement(
    statement: Mapping[str, Any], *, private_key: Ed25519PrivateKey, key_id: str
) -> dict[str, Any]:
    if statement.get("schema_version") != "1.0.0" or not isinstance(statement.get("builder_id"), str) or not statement["builder_id"].strip() or not isinstance(statement.get("build_type"), str) or not statement["build_type"].strip():
        raise SupplyChainError("provenance statement identity is malformed")
    if statement.get("statement_id") != expected_provenance_statement_id(statement):
        raise SupplyChainError("provenance statement identity is invalid")
    signed = dict(statement)
    signed.update({"signature_algorithm": "ed25519", "signature_key_id": key_id})
    signed["signature_value"] = _sign(_signed_subject(signed), private_key)
    return signed


def verify_provenance_statement(
    attestation: Mapping[str, Any],
    statement: Mapping[str, Any],
    *,
    public_key: Ed25519PublicKey,
    key_id: str | None = None,
) -> dict[str, Any]:
    if statement.get("schema_version") != "1.0.0" or not isinstance(statement.get("builder_id"), str) or not statement["builder_id"].strip() or not isinstance(statement.get("build_type"), str) or not statement["build_type"].strip():
        raise SupplyChainError("provenance statement identity is malformed")
    if statement.get("statement_id") != expected_provenance_statement_id(statement):
        raise SupplyChainError("provenance statement identity is invalid")
    if statement.get("bundle_root") != attestation.get("bundle_root") or statement.get("sbom_digest") != attestation.get("sbom_digest"):
        raise SupplyChainError("provenance statement does not bind the attestation")
    if statement.get("verified") is not True:
        raise SupplyChainError("provenance statement is not marked verified")
    _verify(statement, public_key, key_id=key_id)
    updated = dict(attestation)
    updated["provenance_verified"] = True
    if updated.get("signed_release") is True and updated.get("verification_state") == "verified":
        updated["verification_state"] = "verified"
    return updated
