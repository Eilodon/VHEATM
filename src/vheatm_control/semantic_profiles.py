from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .serialization import load_yaml


class SemanticProfileError(ValueError):
    """Raised when a score is outside the canonical semantic profile."""


@dataclass(frozen=True)
class RPNResult:
    severity: int
    occurrence: int
    detectability: int
    score: int
    priority: str


def load_semantic_profile(root: Path) -> Mapping[str, Any]:
    path = root / "policies" / "semantic-profiles.yaml"
    value = load_yaml(path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise SemanticProfileError("semantic profile must be an object")
    return value


def _score_1_to_10(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 10:
        raise SemanticProfileError(f"{label} must be an integer from 1 to 10")
    return value


def calculate_rpn(severity: Any, occurrence: Any, detectability: Any) -> RPNResult:
    s = _score_1_to_10(severity, "severity")
    o = _score_1_to_10(occurrence, "occurrence")
    d = _score_1_to_10(detectability, "detectability")
    score = s * o * d
    priority = "mandatory" if score >= 125 else "required" if score >= 50 else "recommended" if score >= 25 else "optional"
    return RPNResult(s, o, d, score, priority)


def _severity_to_user_facing(severity: int) -> int:
    if severity <= 2:
        return 0
    if severity <= 4:
        return 1
    if severity <= 7:
        return 2
    return 3


def map_fmea_to_qbr(
    *,
    severity: Any,
    detectability: Any,
    system_effect: str,
    cause_class: str,
    downstream_count: int,
) -> dict[str, int]:
    s = _score_1_to_10(severity, "severity")
    d = _score_1_to_10(detectability, "detectability")
    if system_effect not in {"corruption", "partial", "operational"}:
        raise SemanticProfileError("system_effect must be corruption, partial, or operational")
    if cause_class not in {"auth_bypass_injection", "data_exposure", "resource_exhaustion", "other"}:
        raise SemanticProfileError("cause_class is not in the canonical FMEA profile")
    if isinstance(downstream_count, bool) or not isinstance(downstream_count, int) or downstream_count < 0:
        raise SemanticProfileError("downstream_count must be a non-negative integer")
    integrity = {"corruption": 3, "partial": 2, "operational": 1}[system_effect]
    security = {"auth_bypass_injection": 3, "data_exposure": 2, "resource_exhaustion": 1, "other": 0}[cause_class]
    if d >= 8:
        integrity = min(3, integrity + 1)
        if security:
            security = min(3, security + 1)
    blast = 1 if downstream_count <= 1 else 2 if downstream_count <= 4 else 3
    return {
        "user_facing_impact": _severity_to_user_facing(s),
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
) -> dict[str, Any]:
    if context_mode not in {"DESIGN", "CODE", "LIVE", "LEGACY", "ENTERPRISE"}:
        raise SemanticProfileError("context_mode is not canonical")
    normalized: dict[str, int] = {}
    for name in ("user_facing_impact", "data_integrity_risk", "security_risk", "blast_radius"):
        value = dimensions.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 3:
            raise SemanticProfileError(f"{name} must be an integer from 0 to 3")
        normalized[name] = value
    if brs is not None:
        if isinstance(brs, bool) or not isinstance(brs, int) or brs < 0:
            raise SemanticProfileError("brs must be a non-negative integer")
        if brs >= 8:
            normalized["blast_radius"] = 3
    base = normalized["user_facing_impact"] * 4 + normalized["data_integrity_risk"] * 4 + normalized["security_risk"] * 3 + normalized["blast_radius"] * 2
    factor = 1.0
    adjustments: list[str] = []
    if context_mode == "DESIGN":
        factor *= 1.20
        adjustments.append("design:+20%")
    if self_audit:
        factor *= 1.20
        adjustments.append("self_audit:+20%")
    if org_capture:
        factor *= 1.15
        adjustments.append("org_capture:+15%")
    score = min(48, math.ceil(base * factor))
    return {"base_score": base, "score": score, "priority": "mandatory" if score >= 17 else "required" if score >= 9 else "recommended", "dimensions": normalized, "adjustments": adjustments, "factor": factor}


def calculate_brs(*, teams_directly_affected: int, sla_chains_at_risk: int | None, regulatory_obligations: int | None) -> dict[str, Any]:
    if isinstance(teams_directly_affected, bool) or not isinstance(teams_directly_affected, int) or teams_directly_affected < 0:
        raise SemanticProfileError("teams_directly_affected must be a non-negative integer")
    for value, label in ((sla_chains_at_risk, "sla_chains_at_risk"), (regulatory_obligations, "regulatory_obligations")):
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
            raise SemanticProfileError(f"{label} must be a non-negative integer or unknown")
    if sla_chains_at_risk is None or regulatory_obligations is None:
        lower_bound = teams_directly_affected + (1 if sla_chains_at_risk is None else sla_chains_at_risk * 2) + (0 if regulatory_obligations is None else regulatory_obligations * 3)
        return {"status": "unknown", "score": None, "lower_bound": lower_bound, "tier": "unknown", "escalation_required": None}
    score = teams_directly_affected + sla_chains_at_risk * 2 + regulatory_obligations * 3
    tier = "contained" if score <= 3 else "elevated" if score <= 7 else "high" if score <= 12 else "critical"
    return {"status": "complete", "score": score, "lower_bound": score, "tier": tier, "escalation_required": score >= 8}
