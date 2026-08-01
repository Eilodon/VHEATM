from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Mapping, Sequence


class PilotError(ValueError):
    """Raised when a shadow/canary pilot record violates release controls."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _timestamp(value: str | None = None) -> str:
    result = value or datetime.now(UTC).isoformat().replace("+00:00", "Z")
    try:
        parsed = datetime.fromisoformat(result.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PilotError("pilot timestamp must be RFC 3339") from exc
    if parsed.tzinfo is None:
        raise PilotError("pilot timestamp must include a timezone")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def prepare_pilot(
    *,
    session_root: str,
    plan_id: str,
    release_report: Mapping[str, Any],
    profile: str = "shadow",
    drills: Sequence[Mapping[str, Any]],
    rollback_plan: str,
    created_at: str | None = None,
) -> dict[str, Any]:
    if profile not in {"shadow", "canary"}:
        raise PilotError("pilot profile must be shadow or canary")
    if not isinstance(session_root, str) or len(session_root) != 64 or any(char not in "0123456789abcdef" for char in session_root):
        raise PilotError("session_root must be a lowercase SHA-256 digest")
    if not isinstance(plan_id, str) or not plan_id.startswith("PLN-"):
        raise PilotError("plan_id must be content-addressed")
    if release_report.get("summary", {}).get("ga_eligible") is not True and profile == "canary":
        raise PilotError("canary requires every release gate to pass")
    if not str(rollback_plan).strip():
        raise PilotError("pilot requires a non-empty rollback plan")
    normalized_drills = []
    seen: set[str] = set()
    for raw in drills:
        if not isinstance(raw, Mapping) or raw.get("drill_id") in seen:
            raise PilotError("pilot drills must be unique objects")
        drill_id = str(raw.get("drill_id", ""))
        if drill_id not in {"incident", "rollback", "evidence_store_outage", "clock_skew", "provider_outage"}:
            raise PilotError(f"unknown pilot drill: {drill_id}")
        status = str(raw.get("status", "unknown"))
        if status not in {"pass", "fail", "unknown"}:
            raise PilotError(f"invalid pilot drill status: {status}")
        seen.add(drill_id)
        normalized_drills.append({"drill_id": drill_id, "status": status, "evidence_refs": sorted(set(str(ref) for ref in raw.get("evidence_refs", [])))})
    if not {"incident", "rollback", "evidence_store_outage", "clock_skew"}.issubset(seen):
        raise PilotError("pilot requires incident, rollback, evidence-store outage, and clock-skew drills")
    normalized_drills.sort(key=lambda item: item["drill_id"])
    tools_enabled = profile == "canary"
    status = "ready" if profile == "shadow" and all(item["status"] == "pass" for item in normalized_drills) else "blocked"
    if profile == "canary" and tools_enabled and all(item["status"] == "pass" for item in normalized_drills):
        status = "ready"
    identity = {"session_root": session_root, "plan_id": plan_id, "release_report_id": release_report["report_id"], "profile": profile, "read_only": not tools_enabled, "tools_enabled": tools_enabled, "status": status, "rollback_plan": rollback_plan, "drills": normalized_drills}
    return {"schema_version": "1.0.0", "pilot_id": "PIL-" + _digest(identity).upper(), **identity, "created_at": _timestamp(created_at)}


def rollback_pilot(pilot: Mapping[str, Any], *, reason: str, occurred_at: str | None = None) -> dict[str, Any]:
    if pilot.get("status") not in {"ready", "complete"}:
        raise PilotError("only ready or complete pilots can be rolled back")
    if not reason.strip():
        raise PilotError("rollback requires a reason")
    return {**dict(pilot), "status": "rollback", "rollback_reason": reason, "rollback_at": _timestamp(occurred_at)}
