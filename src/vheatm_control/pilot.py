from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from .evaluation import EvaluationError, evaluate_release_gates, validate_release_report
from .providers import ProviderAdapterError, verify_provider_run


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
    release_evidence: Mapping[str, Any] | None = None,
    verification_keys: Mapping[str, Any] | None = None,
    verification_key_ids: Mapping[str, str] | None = None,
    expected_bundle_root: str | None = None,
    schema_root: Path | None = None,
) -> dict[str, Any]:
    if profile not in {"shadow", "canary"}:
        raise PilotError("pilot profile must be shadow or canary")
    if not isinstance(session_root, str) or len(session_root) != 64 or any(char not in "0123456789abcdef" for char in session_root):
        raise PilotError("session_root must be a lowercase SHA-256 digest")
    if not isinstance(plan_id, str) or not plan_id.startswith("PLN-"):
        raise PilotError("plan_id must be content-addressed")
    try:
        release_report = validate_release_report(release_report, schema_root=schema_root)
    except EvaluationError as exc:
        raise PilotError(f"pilot requires a schema-valid release report: {exc}") from exc
    gates = release_report["gates"]
    if release_report.get("summary", {}).get("ga_eligible") is not True and profile == "canary":
        raise PilotError("canary requires every release gate to pass")
    if profile == "canary":
        summary = release_report.get("summary", {})
        if summary.get("pass") != 16 or summary.get("fail") != 0 or summary.get("unknown") != 0 or any(item.get("status") != "pass" for item in gates) or not release_report.get("evidence_bindings"):
            raise PilotError("canary requires a fully evidenced release report")
        if (
            not isinstance(release_evidence, Mapping)
            or not isinstance(verification_keys, Mapping)
            or not verification_keys
            or not isinstance(expected_bundle_root, str)
            or not isinstance(release_report.get("framework_version"), str)
        ):
            raise PilotError("canary requires re-verified release evidence")
        try:
            verified_report = evaluate_release_gates(
                str(release_report["framework_version"]),
                release_evidence,
                evaluated_at=str(release_report.get("evaluated_at", "")),
                expected_bundle_root=expected_bundle_root,
                verification_keys=verification_keys,
                verification_key_ids=verification_key_ids,
                schema_root=schema_root,
            )
        except (EvaluationError, TypeError, ValueError) as exc:
            raise PilotError(f"canary release evidence re-verification failed: {exc}") from exc
        if verified_report != dict(release_report):
            raise PilotError("canary release report does not match re-verified release evidence")
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
    updated = {key: value for key, value in pilot.items() if key != "pilot_id"}
    updated.update({"status": "rollback", "rollback_reason": reason, "rollback_at": _timestamp(occurred_at)})
    updated["pilot_id"] = "PIL-" + _digest({key: value for key, value in updated.items() if key != "pilot_id"}).upper()
    return updated


def complete_pilot(
    pilot: Mapping[str, Any],
    *,
    observations: Sequence[Mapping[str, Any]],
    provider_runs: Sequence[Mapping[str, Any]],
    completed_at: str | None = None,
) -> dict[str, Any]:
    if pilot.get("status") != "ready":
        raise PilotError("only a ready pilot can be completed")
    if not observations:
        raise PilotError("pilot completion requires observations")
    runs_by_id: dict[str, Mapping[str, Any]] = {}
    for run in provider_runs:
        if not isinstance(run, Mapping) or not isinstance(run.get("run_id"), str):
            raise PilotError("pilot completion requires typed provider runs")
        run_id = str(run["run_id"])
        if run_id in runs_by_id:
            raise PilotError("pilot provider run identity is invalid or duplicated")
        try:
            verify_provider_run(run)
        except ProviderAdapterError as exc:
            raise PilotError(f"pilot receipt authorization chain is invalid: {exc}") from exc
        if run.get("status") != "completed":
            raise PilotError("pilot completion cannot use blocked or unknown provider runs")
        receipt = run.get("network_receipt")
        if not isinstance(receipt, Mapping) or receipt.get("decision") != "allow" or not isinstance(run.get("response"), Mapping):
            raise PilotError("pilot completion requires an allowed network receipt and provider response")
        runs_by_id[run_id] = run
    if not runs_by_id:
        raise PilotError("pilot completion requires at least one completed provider run")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in observations:
        if not isinstance(raw, Mapping):
            raise PilotError("pilot observations must be objects")
        observation_id = str(raw.get("observation_id", ""))
        if not observation_id or observation_id in seen:
            raise PilotError("pilot observation IDs must be unique")
        status = str(raw.get("status", "unknown"))
        if status not in {"pass", "fail", "unknown"}:
            raise PilotError("pilot observation status is invalid")
        provider_id = str(raw.get("provider_id", ""))
        if not provider_id:
            raise PilotError("pilot observation provider_id is required")
        provider_run_refs = sorted(set(str(ref) for ref in raw.get("provider_run_refs", [])))
        if not provider_run_refs or any(ref not in runs_by_id for ref in provider_run_refs):
            raise PilotError("pilot observation requires resolvable provider run references")
        if any(runs_by_id[ref].get("provider_id") != provider_id for ref in provider_run_refs):
            raise PilotError("pilot observation provider does not match its provider runs")
        sample_count = raw.get("sample_count")
        if isinstance(sample_count, bool) or not isinstance(sample_count, int) or sample_count < 1:
            raise PilotError("pilot observation sample_count must be positive")
        refs = sorted(set(str(ref) for ref in raw.get("evidence_refs", [])))
        if not refs:
            raise PilotError("pilot observation requires evidence_refs")
        if pilot.get("read_only") is True and raw.get("read_only_confirmed") is not True:
            raise PilotError("shadow pilot observation must confirm read-only execution")
        if pilot.get("read_only") is not True and raw.get("read_only_confirmed") is not False:
            raise PilotError("canary pilot observation must confirm tools were enabled")
        seen.add(observation_id)
        normalized.append(
            {
                "observation_id": observation_id,
                "status": status,
                "provider_id": provider_id,
                "provider_run_refs": provider_run_refs,
                "sample_count": sample_count,
                "read_only_confirmed": raw.get("read_only_confirmed") is True,
                "evidence_refs": refs,
                "observed_at": _timestamp(str(raw.get("observed_at", completed_at))),
            }
        )
    if any(item["status"] != "pass" for item in normalized):
        raise PilotError("pilot completion is blocked by failed or unknown observations")
    updated = {key: value for key, value in pilot.items() if key != "pilot_id"}
    updated.update({"status": "complete", "observations": sorted(normalized, key=lambda item: item["observation_id"]), "completed_at": _timestamp(completed_at)})
    updated["pilot_id"] = "PIL-" + _digest({key: value for key, value in updated.items() if key != "pilot_id"}).upper()
    return updated
