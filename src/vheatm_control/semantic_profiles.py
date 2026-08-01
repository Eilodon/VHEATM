from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml
from jsonschema import Draft202012Validator, FormatChecker

from .bundle import resolve_control_root
from .serialization import load_json, load_yaml


class SemanticProfileError(ValueError):
    """Raised when a score is outside the canonical semantic profile."""


@dataclass(frozen=True)
class RPNResult:
    severity: int
    occurrence: int
    detectability: int
    score: int
    priority: str


def load_semantic_profile(root: Path | None = None) -> Mapping[str, Any]:
    resolved_root = resolve_control_root(root)
    path = resolved_root / "policies" / "semantic-profiles.yaml"
    try:
        value = load_yaml(path.read_text(encoding="utf-8"))
        schema = load_json((resolved_root / "schemas" / "semantic-profiles.schema.json").read_text(encoding="utf-8"))
        manifest = load_yaml((resolved_root / "manifests" / "vheatm-v17.yaml").read_text(encoding="utf-8"))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise SemanticProfileError(f"canonical semantic profile is unavailable: {exc}") from exc
    if not isinstance(value, Mapping):
        raise SemanticProfileError("semantic profile must be an object")
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        location = ".".join(str(part) for part in errors[0].absolute_path) or "<root>"
        raise SemanticProfileError(f"canonical semantic profile is invalid at {location}: {errors[0].message}")
    if value.get("framework_version") != manifest.get("framework", {}).get("version"):
        raise SemanticProfileError("canonical semantic profile framework_version must match the manifest")
    return value


def _score_1_to_10(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 10:
        raise SemanticProfileError(f"{label} must be an integer from 1 to 10")
    return value


def calculate_rpn(severity: Any, occurrence: Any, detectability: Any, *, root: Path | None = None) -> RPNResult:
    profile = load_semantic_profile(root)
    s = _score_1_to_10(severity, "severity")
    o = _score_1_to_10(occurrence, "occurrence")
    d = _score_1_to_10(detectability, "detectability")
    score = s * o * d
    thresholds = profile["rpn"]["thresholds"]
    priority = "mandatory" if score >= thresholds["mandatory"] else "required" if score >= thresholds["required"] else "recommended" if score >= thresholds["recommended"] else "optional"
    return RPNResult(s, o, d, score, priority)


def map_fmea_to_qbr(
    *,
    severity: Any,
    detectability: Any,
    system_effect: str,
    cause_class: str,
    downstream_count: int,
    root: Path | None = None,
) -> dict[str, int]:
    profile = load_semantic_profile(root)
    mapping = profile["qbr"]["fmea_mapping"]
    s = _score_1_to_10(severity, "severity")
    d = _score_1_to_10(detectability, "detectability")
    if isinstance(downstream_count, bool) or not isinstance(downstream_count, int) or downstream_count < 0:
        raise SemanticProfileError("downstream_count must be a non-negative integer")
    try:
        integrity = int(mapping["system_effect_to_integrity"][system_effect])
        security = int(mapping["cause_to_security"][cause_class])
    except (KeyError, TypeError, ValueError) as exc:
        raise SemanticProfileError("FMEA system effect or cause class is not in the canonical profile") from exc
    user_facing = next(
        (int(rule["value"]) for rule in mapping["severity_to_user_facing"] if s <= int(rule["max"])),
        None,
    )
    if user_facing is None:
        raise SemanticProfileError("canonical FMEA severity mapping has no matching range")
    risk_max = int(profile["qbr"]["fmea_risk_max"])
    if d >= int(mapping["undetectable_floor"]):
        integrity = min(risk_max, integrity + 1)
        if security:
            security = min(risk_max, security + 1)
    boundaries = mapping["blast_radius_boundaries"]
    blast_scope = "local" if downstream_count <= int(boundaries["local_max"]) else "multi_component" if downstream_count <= int(boundaries["multi_component_max"]) else "widespread"
    try:
        blast = int(mapping["blast_radius_scope"][blast_scope])
    except (KeyError, TypeError, ValueError) as exc:
        raise SemanticProfileError("canonical FMEA blast-radius mapping is incomplete") from exc
    return {
        "user_facing_impact": user_facing,
        "data_integrity_risk": integrity,
        "security_risk": security,
        "blast_radius": blast,
    }


def calculate_qbr(
    dimensions: Mapping[str, Any],
    *,
    context_mode: str,
    self_audit: bool = False,
    org_capture: bool = False,
    brs: int | None = None,
    root: Path | None = None,
) -> dict[str, Any]:
    profile = load_semantic_profile(root)
    qbr_profile = profile["qbr"]
    if context_mode not in {"DESIGN", "CODE", "LIVE", "LEGACY", "ENTERPRISE"}:
        raise SemanticProfileError("context_mode is not canonical")
    dimension_weights = qbr_profile["dimensions"]
    dimension_max = int(qbr_profile["dimension_max"])
    normalized: dict[str, int] = {}
    for name in ("user_facing_impact", "data_integrity_risk", "security_risk", "blast_radius"):
        value = dimensions.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= dimension_max:
            raise SemanticProfileError(f"{name} must be an integer from 0 to {dimension_max}")
        normalized[name] = value
    if brs is not None:
        if isinstance(brs, bool) or not isinstance(brs, int) or brs < 0:
            raise SemanticProfileError("brs must be a non-negative integer")
        if brs >= qbr_profile["brs_blast_radius_floor"]:
            normalized["blast_radius"] = int(qbr_profile["dimension_max"])
    base = sum(normalized[name] * int(dimension_weights[name]) for name in normalized)
    factor = 1.0
    adjustments: list[str] = []
    if context_mode == "DESIGN":
        adjustment = float(qbr_profile["adjustments"]["design"])
        factor *= adjustment
        adjustments.append(f"design:+{adjustment:.0%}")
    if self_audit:
        adjustment = float(qbr_profile["adjustments"]["self_audit"])
        factor *= adjustment
        adjustments.append(f"self_audit:+{adjustment:.0%}")
    if org_capture:
        adjustment = float(qbr_profile["adjustments"]["org_capture"])
        factor *= adjustment
        adjustments.append(f"org_capture:+{adjustment:.0%}")
    score = min(int(qbr_profile["max_score"]), math.ceil(base * factor))
    priority = "mandatory" if score >= qbr_profile["mandatory_threshold"] else "required" if score >= qbr_profile["required_threshold"] else "recommended"
    return {"base_score": base, "score": score, "priority": priority, "dimensions": normalized, "adjustments": adjustments, "factor": factor}


def calculate_brs(*, teams_directly_affected: int, sla_chains_at_risk: int | None, regulatory_obligations: int | None, root: Path | None = None) -> dict[str, Any]:
    profile = load_semantic_profile(root)["brs"]
    if isinstance(teams_directly_affected, bool) or not isinstance(teams_directly_affected, int) or teams_directly_affected < 0:
        raise SemanticProfileError("teams_directly_affected must be a non-negative integer")
    for value, label in ((sla_chains_at_risk, "sla_chains_at_risk"), (regulatory_obligations, "regulatory_obligations")):
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
            raise SemanticProfileError(f"{label} must be a non-negative integer or unknown")
    weights = profile["weights"]
    if sla_chains_at_risk is None or regulatory_obligations is None:
        lower_bound = teams_directly_affected * weights["teams_directly_affected"] + (profile["unknown_sla_floor"] if sla_chains_at_risk is None else sla_chains_at_risk * weights["sla_chains_at_risk"]) + (0 if regulatory_obligations is None else regulatory_obligations * weights["regulatory_obligations"])
        return {"status": "unknown", "score": None, "lower_bound": lower_bound, "tier": "unknown", "escalation_required": None}
    score = teams_directly_affected * weights["teams_directly_affected"] + sla_chains_at_risk * weights["sla_chains_at_risk"] + regulatory_obligations * weights["regulatory_obligations"]
    thresholds = profile["thresholds"]
    tier = "contained" if score <= thresholds["contained"] else "elevated" if score <= thresholds["elevated"] else "high" if score <= thresholds["high"] else "critical"
    return {"status": "complete", "score": score, "lower_bound": score, "tier": tier, "escalation_required": score >= profile["escalation_threshold"]}
