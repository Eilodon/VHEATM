from __future__ import annotations

import hashlib
import json
import os
import tempfile
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Any, Iterable, Iterator, Mapping

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None


class ProvenanceError(ValueError):
    """Raised when provenance invariants are violated."""


_PERSISTENCE_LOCK = Lock()


@contextmanager
def _exclusive_file_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with _PERSISTENCE_LOCK:
        with path.open("a+", encoding="utf-8") as handle:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _content_id(prefix: str, value: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(_canonical_bytes(value)).hexdigest()[:16].upper()
    return f"{prefix}-{digest}"


def sha256_digest(content: str | bytes) -> str:
    payload = content.encode("utf-8") if isinstance(content, str) else content
    return hashlib.sha256(payload).hexdigest()


def _validate_digest(digest: str) -> str:
    normalized = digest.lower()
    if len(normalized) != 64 or any(char not in "0123456789abcdef" for char in normalized):
        raise ProvenanceError("digest must be a SHA-256 hex string")
    return normalized


def _source_identity(record: Mapping[str, Any]) -> dict[str, Any]:
    digest = record.get("digest")
    if not isinstance(digest, Mapping):
        raise ProvenanceError("source digest must be an object")
    if digest.get("algorithm") != "sha256":
        raise ProvenanceError("source digest algorithm must be sha256")
    return {
        "source_type": str(record.get("source_type", "")),
        "locator": str(record.get("locator", "")),
        "digest": {"algorithm": "sha256", "value": _validate_digest(str(digest.get("value", "")))},
    }


def expected_source_id(record: Mapping[str, Any]) -> str:
    identity = _source_identity(record)
    if not identity["locator"].strip():
        raise ProvenanceError("source locator cannot be empty")
    return _content_id("SRC", identity)


def _claim_identity(record: Mapping[str, Any]) -> dict[str, Any]:
    text = " ".join(str(record.get("text", "")).split())
    refs = sorted(set(str(value) for value in record.get("source_refs", [])))
    return {
        "text": text,
        "epistemic_status": str(record.get("epistemic_status", "")),
        "source_refs": refs,
        "evidence_kind": str(record.get("evidence_kind", "")),
    }


def expected_claim_id(record: Mapping[str, Any]) -> str:
    identity = _claim_identity(record)
    if not identity["text"]:
        raise ProvenanceError("claim text cannot be empty")
    return _content_id("CLM", identity)


def build_source_record(
    *,
    source_type: str,
    locator: str,
    digest: str | None = None,
    content: str | bytes | None = None,
    trust_zone: str,
    taint_state: str = "tainted",
    captured_at: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if digest is None and content is None:
        raise ProvenanceError("source requires digest or content")
    computed = sha256_digest(content) if content is not None else None
    if digest is not None:
        digest = _validate_digest(digest)
    if digest is not None and computed is not None and digest != computed:
        raise ProvenanceError("provided digest does not match source content")
    final_digest = digest or computed
    assert final_digest is not None
    identity = {
        "source_type": source_type,
        "locator": locator,
        "digest": {"algorithm": "sha256", "value": final_digest},
    }
    record: dict[str, Any] = {
        "id": _content_id("SRC", identity),
        **identity,
        "trust_zone": trust_zone,
        "taint_state": taint_state,
        "captured_at": captured_at or datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "metadata": dict(metadata or {}),
    }
    if content is not None:
        payload = content.encode("utf-8") if isinstance(content, str) else content
        record["content_length"] = len(payload)
    return record


def verify_source_content(record: Mapping[str, Any], content: str | bytes) -> None:
    digest = _source_identity(record)["digest"]["value"]
    if sha256_digest(content) != digest:
        raise ProvenanceError(f"source content digest mismatch: {record.get('id', '<unknown>')}")
    length = record.get("content_length")
    if length is not None:
        payload = content.encode("utf-8") if isinstance(content, str) else content
        if len(payload) != length:
            raise ProvenanceError(f"source content length mismatch: {record.get('id', '<unknown>')}")


def build_claim_record(
    *,
    text: str,
    epistemic_status: str,
    confidence: float | None,
    source_refs: Iterable[str],
    evidence_kind: str,
    supersedes: str | None = None,
) -> dict[str, Any]:
    identity = {
        "text": " ".join(text.split()),
        "epistemic_status": epistemic_status,
        "source_refs": sorted(set(source_refs)),
        "evidence_kind": evidence_kind,
    }
    if not identity["text"]:
        raise ProvenanceError("claim text cannot be empty")
    if epistemic_status == "unknown" and confidence is not None:
        raise ProvenanceError("unknown claims must have null confidence")
    if confidence is not None and not 0 <= confidence <= 1:
        raise ProvenanceError("confidence must be between 0 and 1")
    if epistemic_status == "verified" and not identity["source_refs"]:
        raise ProvenanceError("verified claims require at least one source reference")
    record: dict[str, Any] = {
        "id": _content_id("CLM", identity),
        **identity,
        "confidence": confidence,
    }
    if supersedes is not None:
        record["supersedes"] = supersedes
    return record


class ProvenanceRegistry:
    def __init__(self, document: Mapping[str, Any] | None = None) -> None:
        self._sources: dict[str, dict[str, Any]] = {}
        self._claims: dict[str, dict[str, Any]] = {}
        if document is not None:
            self._load_document(document)

    def _load_document(self, document: Mapping[str, Any]) -> None:
        if document.get("schema_version") != "1.0.0":
            raise ProvenanceError("unsupported provenance schema_version")
        for source in document.get("sources", []):
            self.add_source(source)
        for claim in document.get("claims", []):
            self.add_claim(claim)
        declared_root = document.get("root_hash")
        if declared_root is not None and declared_root != self.root_hash:
            raise ProvenanceError("provenance root_hash mismatch")

    @staticmethod
    def _insert(target: dict[str, dict[str, Any]], record: Mapping[str, Any], expected_id: str) -> dict[str, Any]:
        candidate = deepcopy(dict(record))
        supplied_id = str(candidate.get("id", ""))
        if supplied_id != expected_id:
            raise ProvenanceError(f"content-addressed id mismatch: supplied={supplied_id!r} expected={expected_id}")
        previous = target.get(expected_id)
        if previous is not None and previous != candidate:
            raise ProvenanceError(f"content-addressed id collision or mutation: {expected_id}")
        target[expected_id] = candidate
        return deepcopy(candidate)

    def add_source(self, record: Mapping[str, Any]) -> dict[str, Any]:
        return self._insert(self._sources, record, expected_source_id(record))

    def add_claim(self, record: Mapping[str, Any]) -> dict[str, Any]:
        identity = _claim_identity(record)
        status = identity["epistemic_status"]
        confidence = record.get("confidence")
        if status == "unknown" and confidence is not None:
            raise ProvenanceError("unknown claims must have null confidence")
        if confidence is not None and (not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1):
            raise ProvenanceError("confidence must be between 0 and 1")
        if status == "verified" and not identity["source_refs"]:
            raise ProvenanceError("verified claims require at least one source reference")
        missing = sorted(set(identity["source_refs"]) - self._sources.keys())
        if missing:
            raise ProvenanceError(f"claim references unknown sources: {missing}")
        supersedes = record.get("supersedes")
        if supersedes is not None and supersedes not in self._claims:
            raise ProvenanceError(f"claim supersedes unknown claim: {supersedes}")
        return self._insert(self._claims, record, expected_claim_id(record))

    @property
    def root_hash(self) -> str:
        payload = {
            "schema_version": "1.0.0",
            "sources": [self._sources[key] for key in sorted(self._sources)],
            "claims": [self._claims[key] for key in sorted(self._claims)],
        }
        return sha256_digest(_canonical_bytes(payload))

    def to_document(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0.0",
            "root_hash": self.root_hash,
            "sources": [deepcopy(self._sources[key]) for key in sorted(self._sources)],
            "claims": [deepcopy(self._claims[key]) for key in sorted(self._claims)],
        }

    @classmethod
    def load(cls, path: str | Path) -> "ProvenanceRegistry":
        with Path(path).open("r", encoding="utf-8") as handle:
            document = json.load(handle)
        if not isinstance(document, dict):
            raise ProvenanceError("provenance document must be an object")
        return cls(document)

    @staticmethod
    def _assert_extension(previous: "ProvenanceRegistry", candidate: "ProvenanceRegistry") -> None:
        for record_id, record in previous._sources.items():
            if candidate._sources.get(record_id) != record:
                raise ProvenanceError(f"persistent registry cannot remove or mutate source: {record_id}")
        for record_id, record in previous._claims.items():
            if candidate._claims.get(record_id) != record:
                raise ProvenanceError(f"persistent registry cannot remove or mutate claim: {record_id}")

    def save(self, path: str | Path, *, expected_root_hash: str | None = None) -> str:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        lock_path = target.with_name(target.name + ".lock")
        with _exclusive_file_lock(lock_path):
            if target.exists():
                previous = self.load(target)
                if expected_root_hash is None:
                    raise ProvenanceError("expected_root_hash is required when updating an existing registry")
                if previous.root_hash != expected_root_hash:
                    raise ProvenanceError(
                        f"provenance registry changed concurrently: expected={expected_root_hash} actual={previous.root_hash}"
                    )
                self._assert_extension(previous, self)
            elif expected_root_hash is not None:
                raise ProvenanceError("cannot provide expected_root_hash for a new registry")

            document = self.to_document()
            fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(document, handle, indent=2, sort_keys=True, ensure_ascii=False)
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temp_name, target)
                try:
                    directory_fd = os.open(target.parent, os.O_RDONLY)
                except OSError:
                    directory_fd = None
                if directory_fd is not None:
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
            except Exception:
                try:
                    os.unlink(temp_name)
                except FileNotFoundError:
                    pass
                raise
        return self.root_hash
