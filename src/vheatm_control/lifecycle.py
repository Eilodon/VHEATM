from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Mapping


class LifecycleError(ValueError):
    """Raised when an audit lifecycle transition violates the state machine."""


ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "created": frozenset({"context_validated"}),
    "context_validated": frozenset({"planned"}),
    "planned": frozenset({"running"}),
    "running": frozenset({"blocked", "partial", "complete"}),
    "blocked": frozenset({"running"}),
    "partial": frozenset({"running"}),
    "complete": frozenset({"attested"}),
    "attested": frozenset(),
}


def _event_id(payload: Mapping[str, Any]) -> str:
    raw = json.dumps(dict(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return f"EVT-{hashlib.sha256(raw).hexdigest().upper()}"


def _validate_time(value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise LifecycleError(f"invalid lifecycle timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise LifecycleError("lifecycle timestamps must include a timezone")


@dataclass
class AuditLifecycle:
    audit_id: str
    state: str = "created"
    events: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.audit_id.strip():
            raise LifecycleError("audit_id cannot be empty")
        if self.state not in ALLOWED_TRANSITIONS:
            raise LifecycleError(f"unknown lifecycle state: {self.state}")

    def transition(
        self,
        target: str,
        *,
        actor: str,
        reason: str,
        occurred_at: str | None = None,
        evidence_refs: Iterable[str] = (),
    ) -> dict[str, Any]:
        if target not in ALLOWED_TRANSITIONS:
            raise LifecycleError(f"unknown lifecycle state: {target}")
        if target not in ALLOWED_TRANSITIONS[self.state]:
            raise LifecycleError(f"invalid lifecycle transition: {self.state} -> {target}")
        if not actor.strip() or not reason.strip():
            raise LifecycleError("lifecycle transition requires actor and reason")
        timestamp = occurred_at or datetime.now().astimezone().isoformat()
        _validate_time(timestamp)
        payload = {
            "audit_id": self.audit_id,
            "from": self.state,
            "to": target,
            "actor": actor,
            "reason": reason,
            "occurred_at": timestamp,
            "evidence_refs": sorted(set(evidence_refs)),
            "sequence": len(self.events) + 1,
        }
        event = {"id": _event_id(payload), **payload}
        self.events.append(event)
        self.state = target
        return dict(event)

    def to_document(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0.0",
            "audit_id": self.audit_id,
            "state": self.state,
            "events": [dict(event) for event in self.events],
        }

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> "AuditLifecycle":
        if document.get("schema_version") != "1.0.0":
            raise LifecycleError("unsupported lifecycle schema_version")
        audit_id = str(document.get("audit_id", ""))
        replay = cls(audit_id)
        events = document.get("events")
        if not isinstance(events, list):
            raise LifecycleError("lifecycle events must be an array")
        for index, raw_event in enumerate(events, start=1):
            if not isinstance(raw_event, Mapping):
                raise LifecycleError(f"lifecycle event {index} must be an object")
            event = dict(raw_event)
            event_id = str(event.pop("id", ""))
            if event.get("sequence") != index:
                raise LifecycleError(f"lifecycle sequence must be contiguous at event {index}")
            if event.get("audit_id") != audit_id:
                raise LifecycleError(f"lifecycle event {index} audit_id mismatch")
            if event.get("from") != replay.state:
                raise LifecycleError(f"lifecycle event {index} from-state mismatch")
            target = str(event.get("to", ""))
            if target not in ALLOWED_TRANSITIONS.get(replay.state, frozenset()):
                raise LifecycleError(f"invalid lifecycle transition: {replay.state} -> {target}")
            if not str(event.get("actor", "")).strip() or not str(event.get("reason", "")).strip():
                raise LifecycleError(f"lifecycle event {index} requires actor and reason")
            _validate_time(str(event.get("occurred_at", "")))
            refs = event.get("evidence_refs")
            if not isinstance(refs, list) or refs != sorted(set(refs)):
                raise LifecycleError(f"lifecycle event {index} evidence_refs must be sorted and unique")
            if event_id != _event_id(event):
                raise LifecycleError(f"lifecycle event {index} id mismatch")
            replay.events.append({"id": event_id, **event})
            replay.state = target
        if document.get("state") != replay.state:
            raise LifecycleError("declared lifecycle state does not match replayed events")
        return replay
