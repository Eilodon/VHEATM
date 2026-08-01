from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker

from .serialization import load_json


class MigrationCapabilityError(ValueError):
    """Raised when a legacy capability record is malformed or cannot be completed safely."""


_PRIORITIES = ("mandatory", "required", "recommended", "optional")
_PROBABILITIES = ("negligible", "low", "medium", "high", "unknown")
_REQUIRED_SECTIONS: dict[str, tuple[str, ...]] = {
    "FAST": (
        "context", "summary", "top_findings", "bias_probe", "automation_bias_guard",
        "signal_noise_filter", "adversarial_pass", "recommendation", "next_cycle_trigger",
    ),
    "Standard": (
        "context", "pre_mortem", "catalog_replay", "compound_features", "findings",
        "bias_probes", "automation_bias_guard", "signal_noise_filter", "adrs",
        "adversarial_pass", "bug_class_catalog_update", "recommendation", "next_cycle",
    ),
    "Full": (
        "context", "scope_statement", "executive_judgment", "pre_mortem", "hypotheses_summary",
        "evidence_anchored_findings", "stakeholder_view", "bias_probes", "adrs",
        "adversarial_pass", "decision", "confidence", "next_cycle",
    ),
}
_SECTION_SCHEMAS = {
    "context": "audit-context.schema.json",
    "summary": "module-decision.schema.json",
    "top_findings": "finding.schema.json",
    "findings": "finding.schema.json",
    "evidence_anchored_findings": "finding.schema.json",
    "adrs": "module-artifact.schema.json",
    "recommendation": "module-decision.schema.json",
    "decision": "module-decision.schema.json",
    "next_cycle": "module-artifact.schema.json",
    "next_cycle_trigger": "module-artifact.schema.json",
    "stakeholder_view": "module-artifact.schema.json",
    "scope_statement": "module-artifact.schema.json",
    "executive_judgment": "module-decision.schema.json",
    "pre_mortem": "module-artifact.schema.json",
    "catalog_replay": "module-artifact.schema.json",
    "compound_features": "module-artifact.schema.json",
    "bias_probe": "module-artifact.schema.json",
    "bias_probes": "module-artifact.schema.json",
    "automation_bias_guard": "module-artifact.schema.json",
    "signal_noise_filter": "signal-noise-decision.schema.json",
    "adversarial_pass": "module-artifact.schema.json",
    "bug_class_catalog_update": "module-artifact.schema.json",
    "hypotheses_summary": "module-artifact.schema.json",
}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _schema_path(name: str, root: Path | None) -> Path:
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
    raise MigrationCapabilityError(f"required migration schema is unavailable: {name}")


def _validate(record: Mapping[str, Any], schema_name: str, root: Path | None) -> None:
    try:
        schema = load_json(_schema_path(schema_name, root).read_text(encoding="utf-8"))
        errors = sorted(
            Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(record),
            key=lambda error: list(error.absolute_path),
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise MigrationCapabilityError(f"migration schema could not be loaded: {exc}") from exc
    if errors:
        location = ".".join(str(part) for part in errors[0].absolute_path) or "<root>"
        raise MigrationCapabilityError(f"migration record is not schema-valid at {location}: {errors[0].message}")


def _record_id(prefix: str, record: Mapping[str, Any], field: str) -> str:
    return f"{prefix}-" + _digest({key: value for key, value in record.items() if key != field}).upper()


def _number(value: Any, label: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise MigrationCapabilityError(f"{label} must be a non-negative number or unknown")
    return float(value)


def _priority_after_downgrade(priority: str) -> str:
    return {"mandatory": "recommended", "required": "recommended", "recommended": "optional", "optional": "optional"}[priority]


def evaluate_signal_noise(hypothesis: Mapping[str, Any], *, mode: str = "standard", root: Path | None = None) -> dict[str, Any]:
    """Apply the legacy SNF questions while preserving unknown inputs."""

    if mode not in {"fast", "standard", "full"}:
        raise MigrationCapabilityError("signal-noise mode must be fast, standard, or full")
    if not isinstance(hypothesis, Mapping):
        raise MigrationCapabilityError("signal-noise hypothesis must be an object")
    hypothesis_id = hypothesis.get("hypothesis_id")
    priority = hypothesis.get("original_priority")
    worst_case = hypothesis.get("worst_case")
    if not isinstance(hypothesis_id, str) or not hypothesis_id:
        raise MigrationCapabilityError("signal-noise hypothesis_id is required")
    if priority not in _PRIORITIES:
        raise MigrationCapabilityError("signal-noise original_priority is not canonical")
    if not isinstance(worst_case, Mapping) or not isinstance(worst_case.get("description"), str) or not worst_case["description"].strip():
        raise MigrationCapabilityError("signal-noise worst_case description is required")
    probability = worst_case.get("probability")
    if probability not in _PROBABILITIES:
        raise MigrationCapabilityError("signal-noise worst_case probability is not canonical")

    skipped_questions = ["Q2", "Q4"] if mode == "fast" else []
    missing: list[str] = []
    security_implication = hypothesis.get("security_implication")
    monitorable = hypothesis.get("monitorable")
    if not isinstance(security_implication, bool):
        missing.append("security_implication")
    if not isinstance(monitorable, bool):
        missing.append("monitorable")
    detect_hours = _number(hypothesis.get("time_to_detect_hours"), "time_to_detect_hours")
    fix_hours = _number(hypothesis.get("time_to_fix_hours"), "time_to_fix_hours")
    if monitorable is True and (detect_hours is None or fix_hours is None):
        missing.append("monitoring_timing")
    fix_cost = not_fix_cost = None
    if mode != "fast":
        fix_cost = _number(hypothesis.get("fix_cost_units"), "fix_cost_units")
        not_fix_cost = _number(hypothesis.get("not_fix_cost_units"), "not_fix_cost_units")
        if fix_cost is None or not_fix_cost is None:
            missing.append("Q2_costs")
        known = hypothesis.get("known")
        if not isinstance(known, bool):
            missing.append("Q4_known")
    else:
        known = None

    diagnostics: list[str] = []
    security_exception_input = security_implication is True and priority == "mandatory"
    security_only_missing = {"Q2_costs", "Q4_known"}
    blocking_missing = [item for item in missing if item not in security_only_missing]
    if blocking_missing or probability == "unknown":
        diagnostics.extend(f"unresolved: {item}" for item in blocking_missing)
        if probability == "unknown":
            diagnostics.append("unresolved: worst_case_probability")
        record: dict[str, Any] = {
            "schema_version": "1.0.0", "hypothesis_id": hypothesis_id, "mode": mode,
            "status": "unknown", "verdict": None, "effective_priority": None,
            "security_exception": False, "skipped_questions": skipped_questions,
            "diagnostics": sorted(set(diagnostics)), "source_digest": _digest(dict(hypothesis)),
        }
        record["decision_id"] = _record_id("SNF", record, "decision_id")
        _validate(record, "signal-noise-decision.schema.json", root)
        return record

    security_exception = security_exception_input
    verdict = "maintain"
    effective_priority = priority
    if security_exception:
        diagnostics.append("mandatory security implication cannot be downgraded by signal-noise filtering")
        diagnostics.extend(f"not required for security exception: {item}" for item in missing if item in security_only_missing)
    elif known is True:
        verdict, effective_priority = "remove", "optional"
        diagnostics.append("already known or accepted risk is not duplicated as a new ADR")
    elif probability == "negligible":
        verdict, effective_priority = "remove", "optional"
        diagnostics.append("negligible worst-case probability removes the candidate from the ADR set")
    elif monitorable is True and fix_hours is not None and fix_hours <= 24:
        verdict, effective_priority = "downgrade", _priority_after_downgrade(priority)
        diagnostics.append("monitorable with a fix time of at most one day")
    elif mode != "fast" and probability == "low" and fix_cost is not None and not_fix_cost is not None and fix_cost > 3 * not_fix_cost:
        verdict, effective_priority = "downgrade", "optional"
        diagnostics.append("low-probability fix cost exceeds three times the not-fix cost")
    else:
        diagnostics.append("no conservative downgrade or removal condition was met")

    record = {
        "schema_version": "1.0.0", "hypothesis_id": hypothesis_id, "mode": mode,
        "status": "complete", "verdict": verdict, "effective_priority": effective_priority,
        "security_exception": security_exception, "skipped_questions": skipped_questions,
        "diagnostics": diagnostics, "source_digest": _digest(dict(hypothesis)),
    }
    record["decision_id"] = _record_id("SNF", record, "decision_id")
    _validate(record, "signal-noise-decision.schema.json", root)
    return record


def build_stakeholder_record(
    context: Mapping[str, Any],
    *,
    primary_role: str,
    secondary_roles: list[str] | tuple[str, ...] = (),
    org_context: Mapping[str, Any] | None = None,
    ownership_map: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...] = (),
    root: Path | None = None,
) -> dict[str, Any]:
    """Build a candidate stakeholder/ownership record; missing ownership stays unknown."""

    if not isinstance(context, Mapping) or not isinstance(primary_role, str) or not primary_role.strip():
        raise MigrationCapabilityError("stakeholder context and primary_role are required")
    enterprise = context.get("context_mode") == "enterprise" or context.get("organization_scope") == "enterprise"
    provided_org = dict(org_context or {})
    teams = provided_org.get("teams_in_scope", [])
    auditor_team = provided_org.get("auditor_team")
    if not isinstance(teams, list) or any(not isinstance(item, str) or not item.strip() for item in teams):
        raise MigrationCapabilityError("org_context teams_in_scope must be non-empty strings")
    normalized_map: list[dict[str, Any]] = []
    for item in ownership_map:
        if not isinstance(item, Mapping):
            raise MigrationCapabilityError("ownership_map entries must be objects")
        normalized = {key: item[key] for key in ("component", "owning_team", "on_call", "escalation") if key in item}
        if "sla" in item:
            normalized["sla"] = item["sla"]
        normalized_map.append(normalized)
    missing: list[str] = []
    for field in ("goal", "decision_owner", "stakeholder"):
        if not isinstance(context.get(field), str) or not context[field].strip():
            missing.append(field)
    if enterprise:
        if not isinstance(auditor_team, str) or not auditor_team.strip():
            missing.append("org_context.auditor_team")
        if not teams:
            missing.append("org_context.teams_in_scope")
        if not normalized_map:
            missing.append("ownership_map")
    record: dict[str, Any] = {
        "schema_version": "1.0.0",
        "context_digest": _digest(dict(context)),
        "status": "unknown" if missing else "complete",
        "epistemic_status": "unknown" if missing else "candidate",
        "authority_eligible": False,
        "primary_role": primary_role,
        "secondary_roles": sorted(set(secondary_roles)),
        "org_context": {"auditor_team": auditor_team if isinstance(auditor_team, str) else None, "teams_in_scope": sorted(set(teams))},
        "ownership_map": normalized_map,
        "missing_requirements": sorted(set(missing)),
    }
    record["record_id"] = _record_id("STK", record, "record_id")
    _validate(record, "stakeholder-record.schema.json", root)
    return record


def migrate_legacy_output(payload: Mapping[str, Any], *, mode: str, root: Path | None = None) -> dict[str, Any]:
    """Map legacy output sections to canonical schemas without clearing taint or authority."""

    if mode not in _REQUIRED_SECTIONS:
        raise MigrationCapabilityError("legacy output mode must be FAST, Standard, or Full")
    if not isinstance(payload, Mapping):
        raise MigrationCapabilityError("legacy output payload must be an object")
    if mode == "FAST" and "top_findings" in payload:
        findings = payload["top_findings"]
        if not isinstance(findings, list) or len(findings) != 3:
            raise MigrationCapabilityError("FAST top_findings must contain exactly 3 items")
    required = list(_REQUIRED_SECTIONS[mode])
    missing = sorted(section for section in required if section not in payload or payload[section] is None)
    mappings = [
        {"legacy_section": section, "canonical_schema": f"https://vheatm.dev/schemas/{_SECTION_SCHEMAS.get(section, 'module-artifact.schema.json')}", "present": section not in missing}
        for section in required
    ]
    record: dict[str, Any] = {
        "schema_version": "1.0.0",
        "legacy_mode": mode,
        "status": "unknown" if missing else "complete",
        "evidence_state": "unknown" if missing else "candidate",
        "authority_eligible": False,
        "taint_state": "tainted",
        "source_digest": _digest(dict(payload)),
        "required_sections": required,
        "missing_sections": missing,
        "section_mappings": mappings,
        "diagnostics": [f"missing legacy section: {section}" for section in missing],
    }
    record["record_id"] = _record_id("MIG", record, "record_id")
    _validate(record, "legacy-output-migration.schema.json", root)
    return record
