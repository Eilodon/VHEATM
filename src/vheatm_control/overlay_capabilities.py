from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml
from jsonschema import Draft202012Validator, FormatChecker

from .serialization import load_json, load_yaml


class OverlayCapabilityError(ValueError):
    """Raised when a semantic overlay cannot be represented without guessing."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _schema_path(name: str, root: Path | None) -> Path:
    candidates: list[Path] = []
    if root is not None:
        candidates.append(root.resolve() / "schemas" / name)
    candidates.extend((Path(__file__).resolve().parent / "assets" / "schemas" / name, Path(__file__).resolve().parents[2] / "schemas" / name))
    for candidate in candidates:
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    raise OverlayCapabilityError(f"required overlay schema is unavailable: {name}")


def _validate(record: Mapping[str, Any], schema_name: str, root: Path | None) -> None:
    try:
        schema = load_json(_schema_path(schema_name, root).read_text(encoding="utf-8"))
        errors = sorted(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(record), key=lambda error: list(error.absolute_path))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise OverlayCapabilityError(f"overlay schema could not be loaded: {exc}") from exc
    if errors:
        location = ".".join(str(part) for part in errors[0].absolute_path) or "<root>"
        raise OverlayCapabilityError(f"overlay record is not schema-valid at {location}: {errors[0].message}")


def _record_id(prefix: str, record: Mapping[str, Any], field: str = "record_id") -> str:
    return f"{prefix}-" + _digest({key: value for key, value in record.items() if key != field}).upper()


_L7_OWNERS = {
    "L7.1": "MOD-EXECUTION-FIDELITY", "L7.2": "MOD-EXECUTION-FIDELITY", "L7.3": "MOD-EXECUTION-FIDELITY",
    "L7.4": "MOD-EVIDENCE-ANCHORS", "L7.5": "MOD-EXECUTION-FIDELITY", "L7.6": "MOD-EXECUTION-FIDELITY",
    "L7.7": "MOD-ADVERSARIAL-PASS", "L7.8": "MOD-CONTEXT-CONTRACT", "L7.9": "MOD-EXECUTION-FIDELITY",
    "L7.10": "MOD-EXECUTION-FIDELITY", "L7.11": "MOD-EVIDENCE-ANCHORS",
}
_L4_SUBLAYERS = (
    ("L4.1", "Data Race"), ("L4.2", "TOCTOU"), ("L4.3", "Initialization Race"),
    ("L4.4", "Order Violation"), ("L4.5", "Event Race"), ("L4.6", "Livelock / Deadlock"),
)


def build_cross_cutting_scan(context: Mapping[str, Any], *, active_subcategories: Sequence[str], root: Path | None = None) -> dict[str, Any]:
    if not isinstance(context, Mapping):
        raise OverlayCapabilityError("cross-cutting context must be an object")
    active = list(dict.fromkeys(str(item) for item in active_subcategories))
    if not active or any(item not in _L7_OWNERS for item in active):
        raise OverlayCapabilityError("cross-cutting subcategories must be canonical L7 identifiers")
    context_mode = context.get("context_mode")
    required = list(active)
    if context_mode == "enterprise" and "L7.11" not in required:
        required.append("L7.11")
    missing = [] if isinstance(context_mode, str) and context_mode in {"single", "enterprise"} else ["context_mode"]
    obligations = [{"id": item, "required": True, "owner": _L7_OWNERS[item]} for item in required]
    record: dict[str, Any] = {
        "schema_version": "1.0.0", "context_digest": _digest(dict(context)),
        "status": "unknown" if missing else "complete", "evidence_state": "unknown" if missing else "candidate",
        "authority_eligible": False, "obligations": obligations,
        "missing_requirements": missing, "diagnostics": [f"unresolved: {item}" for item in missing],
    }
    record["record_id"] = _record_id("CTC", record)
    _validate(record, "cross-cutting-scan.schema.json", root)
    return record


def _parse_timestamp(value: Any) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise OverlayCapabilityError("temporal snapshot timestamps must be RFC 3339") from exc
    if parsed.tzinfo is None:
        raise OverlayCapabilityError("temporal snapshot timestamps must include a timezone")
    return parsed.astimezone(UTC)


def build_temporal_scan(snapshots: Sequence[Mapping[str, Any]], *, mode: str, root: Path | None = None) -> dict[str, Any]:
    if mode not in {"fast", "standard", "full"}:
        raise OverlayCapabilityError("temporal mode must be fast, standard, or full")
    if not isinstance(snapshots, Sequence) or isinstance(snapshots, (str, bytes)) or not snapshots:
        raise OverlayCapabilityError("temporal scan requires at least one immutable snapshot")
    normalized: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_digests: set[str] = set()
    previous: datetime | None = None
    for item in snapshots:
        if not isinstance(item, Mapping):
            raise OverlayCapabilityError("temporal snapshots must be objects")
        snapshot_id = item.get("snapshot_id")
        digest = item.get("digest")
        if not isinstance(snapshot_id, str) or not snapshot_id or snapshot_id in seen_ids:
            raise OverlayCapabilityError("temporal snapshot IDs must be unique non-empty strings")
        if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest) or digest in seen_digests:
            raise OverlayCapabilityError("temporal snapshot digests must be unique lowercase SHA-256 values")
        captured_at = _parse_timestamp(item.get("captured_at"))
        if previous is not None and captured_at <= previous:
            raise OverlayCapabilityError("temporal snapshots must be strictly increasing by captured_at")
        seen_ids.add(snapshot_id)
        seen_digests.add(digest)
        previous = captured_at
        normalized.append({"snapshot_id": snapshot_id, "captured_at": captured_at.isoformat().replace("+00:00", "Z"), "digest": digest})
    record: dict[str, Any] = {
        "schema_version": "1.0.0", "mode": mode, "status": "complete", "evidence_state": "candidate",
        "authority_eligible": False, "snapshots": normalized,
        "sublayers": [{"id": identifier, "name": name, "owner": "MOD-EVIDENCE-ANCHORS"} for identifier, name in _L4_SUBLAYERS],
        "diagnostics": [],
    }
    record["record_id"] = _record_id("TSC", record)
    _validate(record, "temporal-scan.schema.json", root)
    return record


def _valid_digest(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _standards_binding(root: Path | None) -> dict[str, Any] | None:
    if root is None:
        return None
    policy_path = root.resolve() / "policies" / "standards-baseline.yaml"
    if not policy_path.is_file() or policy_path.is_symlink():
        return None
    try:
        policy = load_yaml(policy_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, yaml.YAMLError):
        return None
    if not isinstance(policy, Mapping):
        return None
    for item in policy.get("standards", []):
        if not isinstance(item, Mapping) or item.get("id") != "NIST-AI-RMF-1.0":
            continue
        if item.get("namespace") != "normative" or item.get("status") != "pinned":
            return None
        return {
            "id": str(item["id"]),
            "version": str(item["version"]),
            "namespace": str(item["namespace"]),
            "status": str(item["status"]),
            "policy_digest": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
            "scope": "AI governance overlay only; canonical VHEATM policy remains authoritative",
        }
    return None


def _string_sequence(value: Any) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes)) and bool(value) and all(isinstance(item, str) and item.strip() for item in value)


def build_ai_rmf_overlay(
    context: Mapping[str, Any],
    *,
    model: Mapping[str, Any] | None,
    ai_inputs: Sequence[str],
    ai_outputs: Sequence[str],
    human_oversight_points: int,
    governance: Mapping[str, Any],
    monitoring_coverage: float | None,
    root: Path | None = None,
) -> dict[str, Any]:
    if not isinstance(context, Mapping) or not isinstance(governance, Mapping):
        raise OverlayCapabilityError("AI-RMF context and governance must be objects")
    ai_state = context.get("declarations", {}).get("ai_integrated") if isinstance(context.get("declarations"), Mapping) else None
    normalized_model = None
    if isinstance(model, Mapping):
        normalized_model = {"provider_id": model.get("provider_id"), "model_id": model.get("model_id"), "config_digest": model.get("config_digest")}
    missing: list[str] = []
    if ai_state == "no":
        status, evidence_state = "not_applicable", "not_applicable"
    else:
        standards_binding = _standards_binding(root)
        if ai_state != "yes":
            missing.append("declarations.ai_integrated")
        if normalized_model is None or not isinstance(normalized_model.get("provider_id"), str) or not normalized_model["provider_id"].strip():
            missing.append("model.provider_id")
        if normalized_model is None or not isinstance(normalized_model.get("model_id"), str) or not normalized_model["model_id"].strip():
            missing.append("model.model_id")
        if normalized_model is None or not _valid_digest(normalized_model.get("config_digest")):
            missing.append("model.config_digest")
        if not _string_sequence(ai_inputs):
            missing.append("ai_inputs")
        if not _string_sequence(ai_outputs):
            missing.append("ai_outputs")
        if isinstance(human_oversight_points, bool) or not isinstance(human_oversight_points, int) or human_oversight_points < 1:
            missing.append("human_oversight_points")
        for name in ("policy_exists", "accountability_documented", "human_review_for_high_stakes"):
            if governance.get(name) is not True:
                missing.append(f"governance.{name}")
        if standards_binding is None:
            missing.append("standards_binding")
        if monitoring_coverage is None or isinstance(monitoring_coverage, bool) or not isinstance(monitoring_coverage, (int, float)) or not 0 <= monitoring_coverage <= 1:
            missing.append("monitoring_coverage")
        status, evidence_state = ("unknown", "unknown") if missing else ("complete", "candidate")
    if ai_state == "no":
        standards_binding = _standards_binding(root)
    record: dict[str, Any] = {
        "schema_version": "1.0.0", "status": status, "evidence_state": evidence_state,
        "authority_eligible": False, "model": normalized_model,
        "ai_inputs": list(ai_inputs) if _string_sequence(ai_inputs) else [],
        "ai_outputs": list(ai_outputs) if _string_sequence(ai_outputs) else [],
        "human_oversight_points": human_oversight_points if isinstance(human_oversight_points, int) and not isinstance(human_oversight_points, bool) and human_oversight_points >= 0 else 0,
        "monitoring_coverage": monitoring_coverage if isinstance(monitoring_coverage, (int, float)) and not isinstance(monitoring_coverage, bool) and 0 <= monitoring_coverage <= 1 else None,
        "standards_binding": standards_binding,
        "functions": {"govern": status == "complete", "map": status == "complete", "measure": status == "complete", "manage": status == "complete"},
        "missing_requirements": sorted(set(missing)), "diagnostics": [f"unresolved: {item}" for item in sorted(set(missing))],
    }
    record["record_id"] = _record_id("AIR", record)
    _validate(record, "ai-rmf-overlay.schema.json", root)
    return record


_MATURITY_FIELDS = ("finding_type", "samm_function", "samm_practice", "ssdf_mapping", "bsimm_baseline", "improvement_recommendation", "priority_action")


def build_assurance_maturity_delta(findings: Sequence[Mapping[str, Any]], *, root: Path | None = None) -> dict[str, Any]:
    if not isinstance(findings, Sequence) or isinstance(findings, (str, bytes)):
        raise OverlayCapabilityError("assurance findings must be an array")
    deltas: list[dict[str, Any]] = []
    missing: list[str] = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, Mapping):
            raise OverlayCapabilityError("assurance findings must be objects")
        if finding.get("priority") not in {"mandatory", "required"}:
            continue
        finding_id = str(finding.get("finding_id", f"finding[{index}]"))
        absent = [field for field in _MATURITY_FIELDS if field not in finding or finding[field] is None]
        if absent:
            missing.extend(f"{finding_id}.{field}" for field in absent)
            continue
        deltas.append({field: finding[field] for field in ("finding_id",) + _MATURITY_FIELDS})
    record: dict[str, Any] = {
        "schema_version": "1.0.0", "status": "unknown" if missing else "complete", "claim_type": "delta_only",
        "evidence_state": "unknown" if missing else "candidate", "authority_eligible": False,
        "maturity_deltas": deltas, "missing_requirements": sorted(set(missing)),
        "diagnostics": [f"unresolved: {item}" for item in sorted(set(missing))],
    }
    record["record_id"] = _record_id("AMD", record)
    _validate(record, "assurance-maturity-delta.schema.json", root)
    return record
