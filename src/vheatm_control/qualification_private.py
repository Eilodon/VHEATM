from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import unquote, urlparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker

from .qualification import QualificationError, verify_manifest
from .serialization import load_json


class PrivateCorpusError(ValueError):
    """Raised when private qualification corpus evidence is unavailable or invalid."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _timestamp(value: Any) -> str:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise PrivateCorpusError("private corpus timestamps must be RFC 3339") from exc
    if parsed.tzinfo is None:
        raise PrivateCorpusError("private corpus timestamps must include a timezone")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _schema_path(name: str, root: Path | None = None) -> Path:
    candidates: list[Path] = []
    if root is not None:
        candidates.append(root.resolve() / "schemas" / name)
    candidates.extend(
        (
            Path(__file__).resolve().parent / "assets" / "schemas" / name,
            Path(__file__).resolve().parents[2] / "schemas" / name,
        )
    )
    for candidate in candidates:
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    raise PrivateCorpusError(f"required private qualification schema is unavailable: {name}")


def _validate_document(document: Mapping[str, Any], schema_name: str, *, root: Path | None = None) -> None:
    try:
        schema = load_json(_schema_path(schema_name, root).read_text(encoding="utf-8"))
        errors = sorted(
            Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(document),
            key=lambda error: list(error.absolute_path),
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise PrivateCorpusError(f"private qualification schema could not be loaded: {exc}") from exc
    if errors:
        location = ".".join(str(part) for part in errors[0].absolute_path) or "<root>"
        raise PrivateCorpusError(f"private qualification document is not schema-valid at {location}: {errors[0].message}")


def _case_identity(case: Mapping[str, Any]) -> dict[str, Any]:
    case_id = str(case.get("case_id", ""))
    captured_at = _timestamp(case.get("captured_at"))
    payload = case.get("payload")
    if not case_id or not isinstance(payload, Mapping):
        raise PrivateCorpusError("private corpus cases require case_id, captured_at, and an object payload")
    return {"case_id": case_id, "captured_at": captured_at, "payload": dict(payload)}


def expected_private_case_digest(case: Mapping[str, Any]) -> str:
    return _digest(_case_identity(case))


def expected_private_corpus_digest(corpus: Mapping[str, Any]) -> str:
    cases = corpus.get("cases")
    if not isinstance(cases, list):
        raise PrivateCorpusError("private corpus cases must be an array")
    digests = sorted(str(case.get("case_digest", "")) for case in cases if isinstance(case, Mapping))
    if not digests or any(len(value) != 64 or any(char not in "0123456789abcdef" for char in value) for value in digests):
        raise PrivateCorpusError("private corpus case digests must be lowercase SHA-256 values")
    return _digest(digests)


def _corpus_identity(corpus: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: (sorted(corpus[key], key=lambda item: str(item.get("case_id", ""))) if key == "cases" else corpus[key])
        for key in corpus
        if key != "corpus_id"
    }


def expected_private_corpus_id(corpus: Mapping[str, Any]) -> str:
    return "PQC-" + _digest(_corpus_identity(corpus)).upper()


def expected_private_corpus_receipt_id(receipt: Mapping[str, Any]) -> str:
    identity = {key: value for key, value in receipt.items() if key != "receipt_id"}
    return "PQR-" + _digest(identity).upper()


def verify_private_corpus_receipt(
    receipt: Mapping[str, Any],
    *,
    manifest: Mapping[str, Any],
    expected_framework_version: str | None = None,
    root: Path | None = None,
) -> dict[str, Any]:
    """Verify the non-disclosing receipt before it can bind qualification evidence."""

    _validate_document(receipt, "private-corpus-receipt.schema.json", root=root)
    if manifest.get("verification_state") != "verified":
        raise PrivateCorpusError("private corpus receipt requires a verified manifest")
    if receipt.get("receipt_id") != expected_private_corpus_receipt_id(receipt):
        raise PrivateCorpusError("private corpus receipt ID does not match its content")
    if receipt.get("manifest_id") != manifest.get("manifest_id") or receipt.get("manifest_digest") != _manifest_digest(manifest):
        raise PrivateCorpusError("private corpus receipt is not bound to the verified manifest")
    if expected_framework_version is not None and receipt.get("framework_version") != expected_framework_version:
        raise PrivateCorpusError("private corpus receipt framework version does not match the release")
    if receipt.get("framework_version") != manifest.get("framework_version") or receipt.get("corpus_digest") != manifest.get("corpus_digest"):
        raise PrivateCorpusError("private corpus receipt corpus binding does not match the manifest")
    if receipt.get("time_slice") != manifest.get("time_slice") or receipt.get("case_count") != manifest.get("case_count"):
        raise PrivateCorpusError("private corpus receipt time slice or case count does not match the manifest")
    return dict(receipt)


def _manifest_digest(manifest: Mapping[str, Any]) -> str:
    return _digest({key: value for key, value in manifest.items() if key != "signature_value"})


def _locator_path(locator: str) -> Path | None:
    parsed = urlparse(locator)
    if parsed.scheme and parsed.scheme != "file":
        return None
    if parsed.scheme == "file":
        if parsed.netloc not in {"", "localhost"}:
            return None
        value = unquote(parsed.path)
    else:
        value = locator
    if not value:
        return None
    path = Path(value)
    if not path.is_absolute():
        return None
    return Path(os.path.normpath(str(path)))


def _contains_symlink(path: Path) -> bool:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            if current.is_symlink():
                return True
        except OSError:
            return True
    return False


def _assert_locator(manifest: Mapping[str, Any], corpus_path: Path) -> Path:
    locator = manifest.get("private_locator")
    if not isinstance(locator, str) or not locator.strip():
        raise PrivateCorpusError("private qualification locator is missing")
    expected = _locator_path(locator)
    actual = Path(os.path.normpath(str(corpus_path))) if corpus_path.is_absolute() else None
    if expected is None or actual is None or expected != actual:
        raise PrivateCorpusError("private corpus path does not match the signed manifest locator")
    if _contains_symlink(actual) or not actual.is_file():
        raise PrivateCorpusError("private corpus locator is unavailable or unsafe")
    return actual


def ingest_private_corpus(
    manifest: Mapping[str, Any],
    *,
    corpus_path: Path,
    public_key: Ed25519PublicKey,
    key_id: str | None = None,
    verified_at: str,
    root: Path | None = None,
) -> dict[str, Any]:
    if not isinstance(manifest, Mapping):
        raise PrivateCorpusError("private qualification manifest must be an object")
    _validate_document(manifest, "qualification-manifest.schema.json", root=root)
    try:
        verified_manifest = verify_manifest(manifest, public_key=public_key, key_id=key_id)
    except QualificationError as exc:
        raise PrivateCorpusError(f"private qualification manifest verification failed: {exc}") from exc
    actual_path = _assert_locator(verified_manifest, corpus_path)
    try:
        document = load_json(actual_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise PrivateCorpusError(f"private corpus is unavailable or not valid JSON: {exc}") from exc
    if not isinstance(document, Mapping):
        raise PrivateCorpusError("private corpus must contain an object")
    _validate_document(document, "private-qualification-corpus.schema.json", root=root)
    if document.get("framework_version") != verified_manifest.get("framework_version") or document.get("visibility") != "private":
        raise PrivateCorpusError("private corpus framework or visibility does not match the verified manifest")
    manifest_slice = verified_manifest.get("time_slice")
    if document.get("time_slice") != manifest_slice:
        raise PrivateCorpusError("private corpus time slice does not match the signed manifest")
    cases = document.get("cases")
    if not isinstance(cases, list):
        raise PrivateCorpusError("private corpus cases must be an array")
    seen_ids: set[str] = set()
    observed_digests: list[str] = []
    start = datetime.fromisoformat(_timestamp(manifest_slice["start"]).replace("Z", "+00:00"))
    end = datetime.fromisoformat(_timestamp(manifest_slice["end"]).replace("Z", "+00:00"))
    for case in cases:
        if not isinstance(case, Mapping):
            raise PrivateCorpusError("private corpus cases must be objects")
        case_id = str(case["case_id"])
        if case_id in seen_ids:
            raise PrivateCorpusError("private corpus case IDs must be unique")
        seen_ids.add(case_id)
        captured = datetime.fromisoformat(_timestamp(case["captured_at"]).replace("Z", "+00:00"))
        if captured < start or captured >= end:
            raise PrivateCorpusError("private corpus case falls outside the signed time slice")
        expected_digest = expected_private_case_digest(case)
        if case["case_digest"] != expected_digest:
            raise PrivateCorpusError(f"private corpus case digest does not match payload: {case_id}")
        observed_digests.append(expected_digest)
    if len(cases) != verified_manifest.get("case_count") or sorted(observed_digests) != sorted(verified_manifest.get("case_digests", [])):
        raise PrivateCorpusError("private corpus cases do not match the signed manifest")
    if document.get("corpus_digest") != expected_private_corpus_digest(document):
        raise PrivateCorpusError("private corpus digest is not derived from its cases")
    if document.get("corpus_id") != expected_private_corpus_id(document):
        raise PrivateCorpusError("private corpus ID does not match its content")
    verified_timestamp = _timestamp(verified_at)
    receipt: dict[str, Any] = {
        "schema_version": "1.0.0",
        "manifest_id": str(verified_manifest["manifest_id"]),
        "manifest_digest": _manifest_digest(verified_manifest),
        "corpus_id": str(document["corpus_id"]),
        "corpus_digest": str(document["corpus_digest"]),
        "framework_version": str(document["framework_version"]),
        "visibility": "private",
        "time_slice": dict(document["time_slice"]),
        "case_count": len(cases),
        "case_refs": sorted(seen_ids),
        "payload_disclosed": False,
        "verification_state": "verified",
        "verified_at": verified_timestamp,
    }
    receipt["receipt_id"] = expected_private_corpus_receipt_id(receipt)
    _validate_document(receipt, "private-corpus-receipt.schema.json", root=root)
    return receipt
