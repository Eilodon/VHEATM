from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Any, Iterable, Iterator, Mapping

from .serialization import load_json

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
    digest = hashlib.sha256(_canonical_bytes(value)).hexdigest().upper()
    return f"{prefix}-{digest}"


def _journal_event_body(event: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in event.items() if key not in {"id", "event_hash"}}


def expected_journal_event_id(event: Mapping[str, Any]) -> str:
    return _content_id("EVT", _journal_event_body(event))


def _expected_event_hash(event: Mapping[str, Any]) -> str:
    return sha256_digest(_canonical_bytes({key: value for key, value in event.items() if key != "event_hash"}))


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


def _validate_source_trust_state(record: Mapping[str, Any]) -> None:
    trust_zone = str(record.get("trust_zone", ""))
    taint_state = str(record.get("taint_state", ""))
    if trust_zone in {"artifact_content", "model_output", "external_data"} and taint_state != "tainted":
        raise ProvenanceError("untrusted source content must remain tainted until an explicit validation receipt exists")


def _normalize_gate_trace(record: Mapping[str, Any]) -> list[str]:
    if "gate_trace" not in record:
        return []
    raw_trace = record.get("gate_trace")
    if not isinstance(raw_trace, (list, tuple, set)):
        raise ProvenanceError("claim gate_trace must be an array")
    values = [str(value) for value in raw_trace]
    if len(values) != len(set(values)):
        raise ProvenanceError("claim gate_trace must contain unique gate ids")
    trace = sorted(set(values))
    if not trace:
        raise ProvenanceError("claim gate_trace must contain at least one gate")
    invalid = sorted(value for value in trace if re.fullmatch(r"HG-[A-Z0-9]+", value) is None)
    if invalid:
        raise ProvenanceError(f"claim gate_trace contains invalid gate ids: {invalid}")
    return trace


def _claim_identity(record: Mapping[str, Any]) -> dict[str, Any]:
    text = " ".join(str(record.get("text", "")).split())
    refs = sorted(set(str(value) for value in record.get("source_refs", [])))
    identity = {
        "text": text,
        "epistemic_status": str(record.get("epistemic_status", "")),
        "source_refs": refs,
        "validation_receipt_refs": sorted(set(str(value) for value in record.get("validation_receipt_refs", []))),
        "evidence_kind": str(record.get("evidence_kind", "")),
    }
    # Keep no-lineage claims compatible with the pre-v2 content identity. A
    # non-empty lineage is part of the identity and therefore receives a new
    # content address.
    lineage_refs = sorted(set(str(value) for value in record.get("lineage_refs", [])))
    if lineage_refs:
        identity["lineage_refs"] = lineage_refs
    gate_trace = _normalize_gate_trace(record)
    if gate_trace:
        identity["gate_trace"] = gate_trace
    return identity


def expected_claim_id(record: Mapping[str, Any]) -> str:
    identity = _claim_identity(record)
    if not identity["text"]:
        raise ProvenanceError("claim text cannot be empty")
    return _content_id("CLM", identity)


def _validation_receipt_identity(record: Mapping[str, Any]) -> dict[str, Any]:
    source_refs = sorted(set(str(value) for value in record.get("source_refs", [])))
    validator = str(record.get("validator", ""))
    method = str(record.get("method", ""))
    result = str(record.get("result", ""))
    input_digest = str(record.get("input_digest", ""))
    if not source_refs:
        raise ProvenanceError("validation receipts require at least one source reference")
    if not validator.strip() or not method.strip():
        raise ProvenanceError("validation receipts require validator and method")
    if result not in {"validated", "rejected"}:
        raise ProvenanceError("validation receipt result must be validated or rejected")
    if input_digest and (len(input_digest) != 64 or any(char not in "0123456789abcdef" for char in input_digest.lower())):
        raise ProvenanceError("validation receipt input_digest must be a SHA-256 hex string")
    return {
        "source_refs": source_refs,
        "validator": validator,
        "method": method,
        "result": result,
        "input_digest": input_digest,
    }


def expected_validation_receipt_id(record: Mapping[str, Any]) -> str:
    return _content_id("VRF", _validation_receipt_identity(record))


def build_validation_receipt(
    *,
    source_refs: Iterable[str],
    validator: str,
    method: str,
    result: str = "validated",
    input_digest: str | None = None,
    validated_at: str | None = None,
) -> dict[str, Any]:
    identity = _validation_receipt_identity(
        {
            "source_refs": source_refs,
            "validator": validator,
            "method": method,
            "result": result,
            "input_digest": input_digest or "",
        }
    )
    return {
        "id": _content_id("VRF", identity),
        **identity,
        "validated_at": validated_at or datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }


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
    _validate_source_trust_state({"trust_zone": trust_zone, "taint_state": taint_state})
    final_digest = digest or computed
    if final_digest is None:
        raise ProvenanceError("source digest could not be derived")
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
    validation_receipt_refs: Iterable[str] = (),
    lineage_refs: Iterable[str] = (),
    gate_trace: Iterable[str] = (),
) -> dict[str, Any]:
    lineage_refs = sorted(set(lineage_refs))
    gate_trace = _normalize_gate_trace({"gate_trace": gate_trace}) if gate_trace else []
    identity = {
        "text": " ".join(text.split()),
        "epistemic_status": epistemic_status,
        "source_refs": sorted(set(source_refs)),
        "validation_receipt_refs": sorted(set(validation_receipt_refs)),
        "evidence_kind": evidence_kind,
    }
    if lineage_refs:
        identity["lineage_refs"] = lineage_refs
    if gate_trace:
        identity["gate_trace"] = gate_trace
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
        self._validation_receipts: dict[str, dict[str, Any]] = {}
        self._claims: dict[str, dict[str, Any]] = {}
        self._journal: list[dict[str, Any]] = []
        self._loading = False
        if document is not None:
            self._load_document(document)

    def _load_document(self, document: Mapping[str, Any]) -> None:
        if document.get("schema_version") != "1.0.0":
            raise ProvenanceError("unsupported provenance schema_version")
        self._loading = True
        try:
            for source in document.get("sources", []):
                self.add_source(source)
            for receipt in document.get("validation_receipts", []):
                self.add_validation_receipt(receipt)
            for claim in document.get("claims", []):
                self.add_claim(claim)
        finally:
            self._loading = False
        supplied_journal = document.get("journal")
        if supplied_journal is None:
            self._journal = self._legacy_journal()
            self._validate_journal()
        elif not isinstance(supplied_journal, list):
            raise ProvenanceError("provenance journal must be an array")
        else:
            self._journal = [deepcopy(dict(event)) for event in supplied_journal]
            self._validate_journal()
        declared_root = document.get("root_hash")
        if declared_root is not None and declared_root != self.root_hash:
            raise ProvenanceError("provenance root_hash mismatch")

    def _legacy_journal(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for record_type, records, timestamp_key in (
            ("source", self._sources, "captured_at"),
            ("validation_receipt", self._validation_receipts, "validated_at"),
            ("claim", self._claims, "captured_at"),
        ):
            for record_id in records:
                record = records[record_id]
                events.append(
                    self._make_journal_event(
                        record_type=record_type,
                        record_id=record_id,
                        actor="legacy-import",
                        occurred_at=str(record.get(timestamp_key) or "1970-01-01T00:00:00Z"),
                        previous_hash=events[-1]["event_hash"] if events else "",
                    )
                )
        return events

    @staticmethod
    def _make_journal_event(
        *, record_type: str, record_id: str, actor: str, occurred_at: str, previous_hash: str
    ) -> dict[str, Any]:
        if not actor.strip():
            raise ProvenanceError("journal actor cannot be empty")
        event: dict[str, Any] = {
            "id": "",
            "record_type": record_type,
            "record_id": record_id,
            "action": "add",
            "actor": actor,
            "occurred_at": occurred_at,
            "previous_hash": previous_hash,
        }
        event["id"] = expected_journal_event_id(event)
        event["event_hash"] = _expected_event_hash(event)
        return event

    def _append_journal(self, *, record_type: str, record_id: str, actor: str, occurred_at: str) -> None:
        previous_hash = self._journal[-1]["event_hash"] if self._journal else ""
        self._journal.append(
            self._make_journal_event(
                record_type=record_type,
                record_id=record_id,
                actor=actor,
                occurred_at=occurred_at,
                previous_hash=previous_hash,
            )
        )

    def _validate_journal(self) -> None:
        previous_hash = ""
        seen: set[str] = set()
        referenced_records: set[str] = set()
        for index, event in enumerate(self._journal):
            if not isinstance(event, Mapping):
                raise ProvenanceError(f"journal event {index} must be an object")
            if event.get("action") != "add":
                raise ProvenanceError(f"journal event {index} has an unsupported action")
            if not str(event.get("actor", "")).strip():
                raise ProvenanceError(f"journal event {index} actor cannot be empty")
            try:
                occurred_at = datetime.fromisoformat(str(event.get("occurred_at", "")).replace("Z", "+00:00"))
            except ValueError as exc:
                raise ProvenanceError(f"journal event {index} occurred_at is invalid") from exc
            if occurred_at.tzinfo is None:
                raise ProvenanceError(f"journal event {index} occurred_at must include a timezone")
            event_id = str(event.get("id", ""))
            if event_id in seen or event_id != expected_journal_event_id(event):
                raise ProvenanceError(f"journal event {index} id mismatch")
            if event.get("previous_hash") != previous_hash:
                raise ProvenanceError(f"journal event {index} previous_hash mismatch")
            if event.get("event_hash") != _expected_event_hash(event):
                raise ProvenanceError(f"journal event {index} event_hash mismatch")
            record_id = str(event.get("record_id", ""))
            record_type = str(event.get("record_type", ""))
            records = {
                "source": self._sources,
                "claim": self._claims,
                "validation_receipt": self._validation_receipts,
            }
            if record_id not in records.get(record_type, {}):
                raise ProvenanceError(f"journal event {index} references unknown record")
            if record_id in referenced_records:
                raise ProvenanceError(f"journal event {index} duplicates a provenance record")
            seen.add(event_id)
            referenced_records.add(record_id)
            previous_hash = str(event["event_hash"])
        known_records = set(self._sources) | set(self._claims) | set(self._validation_receipts)
        if referenced_records != known_records:
            raise ProvenanceError("journal must contain exactly one event for every provenance record")

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

    def add_source(
        self, record: Mapping[str, Any], *, actor: str = "system", occurred_at: str | None = None
    ) -> dict[str, Any]:
        _validate_source_trust_state(record)
        expected_id = expected_source_id(record)
        existed = expected_id in self._sources
        result = self._insert(self._sources, record, expected_id)
        if not existed and not self._loading:
            self._append_journal(
                record_type="source",
                record_id=expected_id,
                actor=actor,
                occurred_at=occurred_at or str(record.get("captured_at") or datetime.now(UTC).isoformat().replace("+00:00", "Z")),
            )
        return result

    def add_validation_receipt(
        self, record: Mapping[str, Any], *, actor: str = "system", occurred_at: str | None = None
    ) -> dict[str, Any]:
        identity = _validation_receipt_identity(record)
        missing = sorted(set(identity["source_refs"]) - self._sources.keys())
        if missing:
            raise ProvenanceError(f"validation receipt references unknown sources: {missing}")
        expected_id = expected_validation_receipt_id(record)
        existed = expected_id in self._validation_receipts
        result = self._insert(self._validation_receipts, record, expected_id)
        if not existed and not self._loading:
            self._append_journal(
                record_type="validation_receipt",
                record_id=expected_id,
                actor=actor,
                occurred_at=occurred_at or str(record.get("validated_at") or datetime.now(UTC).isoformat().replace("+00:00", "Z")),
            )
        return result

    def _validate_claim_lineage(self, claim_id: str, lineage_refs: Iterable[str]) -> None:
        refs = sorted(set(str(ref) for ref in lineage_refs))
        known = set(self._sources) | set(self._claims) | set(self._validation_receipts)
        missing = sorted(set(refs) - known)
        if missing:
            raise ProvenanceError(f"claim references unknown lineage: {missing}")
        if claim_id in refs:
            raise ProvenanceError("claim lineage cannot reference itself")
        graph = {
            existing_id: set(str(ref) for ref in existing.get("lineage_refs", []))
            for existing_id, existing in self._claims.items()
        }
        graph[claim_id] = set(refs)

        def visit(current: str, path: set[str]) -> None:
            if current in path:
                raise ProvenanceError("claim lineage contains a cycle")
            path = path | {current}
            for parent in graph.get(current, set()):
                if parent.startswith("CLM-"):
                    visit(parent, path)

        visit(claim_id, set())

    def add_claim(
        self, record: Mapping[str, Any], *, actor: str = "system", occurred_at: str | None = None
    ) -> dict[str, Any]:
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
        missing_receipts = sorted(set(identity["validation_receipt_refs"]) - self._validation_receipts.keys())
        if missing_receipts:
            raise ProvenanceError(f"claim references unknown validation receipts: {missing_receipts}")
        expected_id = expected_claim_id(record)
        self._validate_claim_lineage(expected_id, identity.get("lineage_refs", []))
        existed = expected_id in self._claims
        result = self._insert(self._claims, record, expected_id)
        if not existed and not self._loading:
            self._append_journal(
                record_type="claim",
                record_id=expected_id,
                actor=actor,
                occurred_at=occurred_at or str(record.get("captured_at") or datetime.now(UTC).isoformat().replace("+00:00", "Z")),
            )
        return result

    @property
    def root_hash(self) -> str:
        payload = {
            "schema_version": "1.0.0",
            "sources": [self._sources[key] for key in sorted(self._sources)],
            "validation_receipts": [self._validation_receipts[key] for key in sorted(self._validation_receipts)],
            "claims": [self._claims[key] for key in sorted(self._claims)],
        }
        return sha256_digest(_canonical_bytes(payload))

    def to_document(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0.0",
            "root_hash": self.root_hash,
            "sources": [deepcopy(self._sources[key]) for key in sorted(self._sources)],
            "validation_receipts": [deepcopy(self._validation_receipts[key]) for key in sorted(self._validation_receipts)],
            "claims": [deepcopy(self._claims[key]) for key in sorted(self._claims)],
            "journal": deepcopy(self._journal),
        }

    @classmethod
    def load(cls, path: str | Path) -> "ProvenanceRegistry":
        with Path(path).open("r", encoding="utf-8") as handle:
            document = load_json(handle)
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
        for record_id, record in previous._validation_receipts.items():
            if candidate._validation_receipts.get(record_id) != record:
                raise ProvenanceError(f"persistent registry cannot remove or mutate validation receipt: {record_id}")
        if candidate._journal[: len(previous._journal)] != previous._journal:
            raise ProvenanceError("persistent provenance journal cannot be removed or mutated")

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
