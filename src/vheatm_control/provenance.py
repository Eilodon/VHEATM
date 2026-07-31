from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any, Iterable, Mapping


class ProvenanceError(ValueError):
    """Raised when provenance invariants are violated."""


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _content_id(prefix: str, value: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(_canonical_bytes(value)).hexdigest()[:16].upper()
    return f"{prefix}-{digest}"


def sha256_digest(content: str | bytes) -> str:
    payload = content.encode("utf-8") if isinstance(content, str) else content
    return hashlib.sha256(payload).hexdigest()


def build_source_record(
    *,
    source_type: str,
    locator: str,
    digest: str,
    trust_zone: str,
    taint_state: str = "tainted",
    captured_at: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not locator.strip():
        raise ProvenanceError("source locator cannot be empty")
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest.lower()):
        raise ProvenanceError("digest must be a SHA-256 hex string")
    identity = {
        "source_type": source_type,
        "locator": locator,
        "digest": {"algorithm": "sha256", "value": digest.lower()},
    }
    return {
        "id": _content_id("SRC", identity),
        **identity,
        "trust_zone": trust_zone,
        "taint_state": taint_state,
        "captured_at": captured_at or datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "metadata": dict(metadata or {}),
    }


def build_claim_record(
    *,
    text: str,
    epistemic_status: str,
    confidence: float | None,
    source_refs: Iterable[str],
    evidence_kind: str,
) -> dict[str, Any]:
    normalized_text = " ".join(text.split())
    refs = sorted(set(source_refs))
    if not normalized_text:
        raise ProvenanceError("claim text cannot be empty")
    if epistemic_status == "unknown" and confidence is not None:
        raise ProvenanceError("unknown claims must have null confidence")
    if confidence is not None and not 0 <= confidence <= 1:
        raise ProvenanceError("confidence must be between 0 and 1")
    if epistemic_status == "verified" and not refs:
        raise ProvenanceError("verified claims require at least one source reference")
    identity = {
        "text": normalized_text,
        "epistemic_status": epistemic_status,
        "source_refs": refs,
        "evidence_kind": evidence_kind,
    }
    return {
        "id": _content_id("CLM", identity),
        **identity,
        "confidence": confidence,
    }


class ProvenanceRegistry:
    def __init__(self) -> None:
        self._sources: dict[str, dict[str, Any]] = {}
        self._claims: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _insert(target: dict[str, dict[str, Any]], record: Mapping[str, Any]) -> dict[str, Any]:
        record_id = str(record["id"])
        candidate = deepcopy(dict(record))
        previous = target.get(record_id)
        if previous is not None and previous != candidate:
            raise ProvenanceError(f"content-addressed id collision or mutation: {record_id}")
        target[record_id] = candidate
        return deepcopy(candidate)

    def add_source(self, record: Mapping[str, Any]) -> dict[str, Any]:
        return self._insert(self._sources, record)

    def add_claim(self, record: Mapping[str, Any]) -> dict[str, Any]:
        missing = sorted(set(record.get("source_refs", [])) - self._sources.keys())
        if missing:
            raise ProvenanceError(f"claim references unknown sources: {missing}")
        return self._insert(self._claims, record)

    def to_document(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0.0",
            "sources": [deepcopy(self._sources[key]) for key in sorted(self._sources)],
            "claims": [deepcopy(self._claims[key]) for key in sorted(self._claims)],
        }
