from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Mapping

import yaml
from jsonschema import Draft202012Validator

from .activation import ActivationError, TruthValue, compile_activation
from .bundle import resolve_control_root
from .serialization import load_document


class ContextValidationError(ValueError):
    """Raised when an audit context violates its machine contract."""


class PlanIntegrityError(ValueError):
    """Raised when an activation plan is not the evaluator's result for its context."""


EVALUATOR_BUILD = "vheatm-control-evaluator-v1"


def canonical_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def plan_digest(plan: Mapping[str, Any]) -> str:
    subject = {key: value for key, value in plan.items() if key not in {"plan_digest", "plan_id"}}
    return canonical_digest(subject)


def _fallback_bundle_root(manifest: Mapping[str, Any]) -> str:
    return canonical_digest(
        {"manifest_digest": canonical_digest(manifest), "bundle_mode": "in-memory-manifest-only"}
    )


def _session_root(context: Mapping[str, Any], bundle_root: str) -> str:
    return canonical_digest(
        {"context": context, "bundle_root": bundle_root, "evaluator_build": EVALUATOR_BUILD}
    )


def _load_document(path: Path) -> dict[str, Any]:
    value = load_document(path)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain an object")
    return value


def validate_context(context: Mapping[str, Any], schema: Mapping[str, Any]) -> None:
    errors = sorted(Draft202012Validator(dict(schema)).iter_errors(context), key=lambda item: list(item.absolute_path))
    if not errors:
        return
    messages = []
    for error in errors:
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        if error.validator == "minProperties":
            messages.append(f"{location}: context must contain at least one property")
        else:
            messages.append(f"{location}: {error.message}")
    raise ContextValidationError("; ".join(messages))


def normalize_context(manifest: Mapping[str, Any], supplied: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if supplied is not None and not supplied:
        raise ContextValidationError("context must contain at least one property")
    supplied = supplied or {}
    defaults = manifest.get("defaults", {})
    normalized: dict[str, Any] = {
        "mode": defaults.get("mode", "standard"),
        "target_tier": defaults.get("target_tier", 2),
        "declarations": dict(defaults.get("declarations", {})),
    }
    for key, value in supplied.items():
        if key == "declarations":
            if not isinstance(value, Mapping):
                raise ValueError("context.declarations must be an object")
            normalized["declarations"].update(value)
        else:
            normalized[key] = value
    if supplied.get("schema_version") == "2.0.0":
        profile = supplied.get("execution_profile")
        if profile is not None:
            normalized["mode"] = profile
        organization_scope = supplied.get("organization_scope")
        if organization_scope is not None:
            normalized["context_mode"] = "single" if organization_scope == "single-team" else "enterprise"
        facts = supplied.get("facts")
        if isinstance(facts, Mapping):
            for key in ("blast_radius", "write_chain_components"):
                if key in facts:
                    normalized[key] = facts[key]
        if "finding_ledger" in supplied:
            ledger = supplied.get("finding_ledger")
            if not isinstance(ledger, list):
                raise ValueError("context.finding_ledger must be an array")
            normalized["mandatory_findings"] = sum(
                1 for finding in ledger
                if isinstance(finding, Mapping) and finding.get("priority") == "mandatory"
                and finding.get("state") not in {"resolved", "closed", "rejected"}
            )
    return normalized


def evaluate_manifest(
    manifest: Mapping[str, Any],
    supplied_context: Mapping[str, Any] | None = None,
    *,
    plan_revision: int = 0,
    parent_plan_id: str | None = None,
    revision_reason: str | None = None,
    bundle_root: str | None = None,
) -> dict[str, Any]:
    """Build an activation plan; this function never claims that a gate passed."""

    if isinstance(plan_revision, bool) or not isinstance(plan_revision, int) or plan_revision < 0:
        raise ValueError("plan_revision must be a non-negative integer")
    if plan_revision == 0 and (parent_plan_id is not None or revision_reason is not None):
        raise ValueError("initial plans cannot declare a parent or revision reason")
    if plan_revision > 0 and (not parent_plan_id or not revision_reason):
        raise ValueError("revised plans require parent_plan_id and revision_reason")

    context = normalize_context(manifest, supplied_context)
    resolved_bundle_root = bundle_root or _fallback_bundle_root(manifest)
    if not isinstance(resolved_bundle_root, str) or len(resolved_bundle_root) != 64:
        raise ValueError("bundle_root must be a SHA-256 hex string")
    try:
        int(resolved_bundle_root, 16)
    except ValueError as exc:
        raise ValueError("bundle_root must be a SHA-256 hex string") from exc
    gate_results: list[dict[str, Any]] = []
    counts = {"active": 0, "inactive": 0, "unknown": 0}

    for gate in manifest["gates"]["items"]:
        expression = gate["activation"]
        try:
            compiled = compile_activation(expression)
            truth = compiled.evaluate(context)
            unknown_references = (
                list(compiled.unknown_references(context)) if truth is TruthValue.UNKNOWN else []
            )
            error = None
        except ActivationError as exc:
            truth = TruthValue.UNKNOWN
            unknown_references = []
            error = str(exc)

        state = {
            TruthValue.TRUE: "active",
            TruthValue.FALSE: "inactive",
            TruthValue.UNKNOWN: "unknown",
        }[truth]
        counts[state] += 1
        reason = f"activation evaluated to {truth.value}"
        if unknown_references:
            reason += f"; unresolved: {', '.join(unknown_references)}"
        if error:
            reason += f"; error: {error}"

        gate_results.append(
            {
                "id": gate["id"],
                "layer": gate["layer"],
                "phase": gate["phase"],
                "activation": expression,
                "activation_state": state,
                "unknown_references": unknown_references,
                "reason": reason,
            }
        )

    plan: dict[str, Any] = {
        "schema_version": "1.0.0",
        "framework_version": manifest["framework"]["version"],
        "manifest_digest": canonical_digest(manifest),
        "bundle_root": resolved_bundle_root,
        "context_digest": canonical_digest(context),
        "evaluator_build": EVALUATOR_BUILD,
        "evaluator_digest": canonical_digest(EVALUATOR_BUILD),
        "plan_revision": plan_revision,
        "session_root": _session_root(context, resolved_bundle_root),
        "context": context,
        "summary": {
            **counts,
            "total": len(gate_results),
            "completion_blocked": counts["unknown"] > 0,
        },
        "gates": gate_results,
    }
    if plan_revision > 0:
        plan["parent_plan_id"] = parent_plan_id
        plan["revision_reason"] = revision_reason
    digest = plan_digest(plan)
    plan["plan_digest"] = digest
    plan["plan_id"] = f"PLN-{digest}"
    return plan


def assert_plan_matches(
    manifest: Mapping[str, Any],
    plan: Mapping[str, Any],
    *,
    require_binding: bool = False,
    bundle_root: str | None = None,
) -> dict[str, Any]:
    """Re-evaluate a plan's context and reject caller-controlled activation states."""

    if not isinstance(plan, Mapping):
        raise PlanIntegrityError("activation plan must be an object")
    context = plan.get("context", {})
    if not isinstance(context, Mapping):
        raise PlanIntegrityError("activation plan context must be an object")
    if not context:
        raise PlanIntegrityError("activation plan context cannot be empty")

    plan_revision = plan.get("plan_revision", 0)
    parent_plan_id = plan.get("parent_plan_id")
    revision_reason = plan.get("revision_reason")
    expected_bundle_root = bundle_root or plan.get("bundle_root") or _fallback_bundle_root(manifest)
    try:
        expected = evaluate_manifest(
            manifest,
            context,
            plan_revision=plan_revision,
            parent_plan_id=parent_plan_id,
            revision_reason=revision_reason,
            bundle_root=expected_bundle_root,
        )
    except (TypeError, ValueError) as exc:
        raise PlanIntegrityError(f"activation plan revision metadata is invalid: {exc}") from exc
    binding_fields = (
        "manifest_digest",
        "bundle_root",
        "context_digest",
        "evaluator_build",
        "evaluator_digest",
        "plan_revision",
        "session_root",
        "parent_plan_id",
        "revision_reason",
        "plan_digest",
        "plan_id",
    )
    present = [field for field in binding_fields if field in plan]
    required_binding_fields = {
        "manifest_digest",
        "bundle_root",
        "context_digest",
        "evaluator_build",
        "evaluator_digest",
        "plan_revision",
        "session_root",
        "plan_digest",
        "plan_id",
    }
    if require_binding and not required_binding_fields.issubset(present):
        missing = sorted(required_binding_fields - set(present))
        raise PlanIntegrityError(f"activation plan binding is incomplete; missing={missing}")
    if present:
        mismatches = [field for field in present if plan.get(field) != expected.get(field)]
        if mismatches:
            raise PlanIntegrityError(f"activation plan binding does not match recomputed plan: {mismatches}")

    expected_gates = {str(gate["id"]): gate for gate in expected["gates"]}
    actual_gates = {str(gate.get("id")): gate for gate in plan.get("gates", []) if isinstance(gate, Mapping)}
    if set(actual_gates) != set(expected_gates):
        raise PlanIntegrityError("activation plan gate coverage does not match recomputed plan")
    for gate_id, expected_gate in expected_gates.items():
        actual_gate = actual_gates[gate_id]
        for field in ("layer", "phase", "activation", "activation_state", "unknown_references"):
            if actual_gate.get(field) != expected_gate.get(field):
                raise PlanIntegrityError(
                    f"activation plan gate {gate_id} field {field!r} does not match recomputed plan"
                )
    if plan.get("summary") != expected.get("summary"):
        raise PlanIntegrityError("activation plan summary does not match recomputed plan")
    return expected


def _merge_context(base: Mapping[str, Any], amendment: Mapping[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(dict(base))
    is_v2 = merged.get("schema_version") == "2.0.0" or amendment.get("schema_version") == "2.0.0"

    immutable_fields = {
        "schema_version",
        "goal",
        "decision_owner",
        "stakeholder",
        "subject",
        "scope",
        "audit_stage",
        "legacy_state",
        "organization_scope",
        "execution_profile",
        "audit_intent",
        "mode",
        "context_mode",
        "target_tier",
    }
    tri_state_fields = {"pii", "multi_tenant", "post_incident"}

    def merge_declarations(value: Any) -> None:
        if not isinstance(value, Mapping):
            raise ValueError("context.declarations must be an object")
        existing = merged.get("declarations", {})
        if not isinstance(existing, Mapping):
            raise ValueError("context.declarations must be an object")
        combined = dict(existing)
        for name, candidate in value.items():
            current = combined.get(name, "unknown")
            if current != "unknown" and current != candidate:
                raise PlanIntegrityError(f"replan cannot change resolved declaration {name!r}")
            combined[name] = copy.deepcopy(candidate)
        merged["declarations"] = combined

    def merge_facts(value: Any) -> None:
        if not isinstance(value, Mapping):
            raise ValueError("context.facts must be an object")
        existing = merged.get("facts", {})
        if not isinstance(existing, Mapping):
            raise ValueError("context.facts must be an object")
        combined = dict(existing)
        for name, candidate in value.items():
            current = combined.get(name)
            if isinstance(current, int) and isinstance(candidate, int) and candidate < current:
                raise PlanIntegrityError(f"replan cannot reduce discovered fact {name!r}")
            combined[name] = copy.deepcopy(candidate)
        merged["facts"] = combined

    def merge_ledger(value: Any) -> None:
        if not isinstance(value, list):
            raise ValueError("context.finding_ledger must be an array")
        existing = merged.get("finding_ledger", [])
        if not isinstance(existing, list):
            raise ValueError("context.finding_ledger must be an array")
        by_id = {str(item.get("id")): item for item in existing if isinstance(item, Mapping)}
        combined = list(existing)
        for item in value:
            if not isinstance(item, Mapping):
                raise ValueError("context.finding_ledger entries must be objects")
            item_id = str(item.get("id", ""))
            previous = by_id.get(item_id)
            if previous is not None and previous != item:
                raise PlanIntegrityError(f"replan cannot mutate finding ledger entry {item_id!r}")
            if previous is None:
                combined.append(copy.deepcopy(dict(item)))
                by_id[item_id] = item
        merged["finding_ledger"] = combined

    for key, value in amendment.items():
        if key in immutable_fields:
            if key in merged and merged[key] != value:
                raise PlanIntegrityError(
                    f"replan cannot change immutable context field {key!r}; this could deactivate obligations"
                )
            merged[key] = copy.deepcopy(value)
            continue
        if key == "declarations":
            merge_declarations(value)
            continue
        if key == "facts" and not is_v2:
            if not isinstance(value, Mapping):
                raise ValueError("context.facts must be an object")
            for fact_key in ("blast_radius", "write_chain_components"):
                if fact_key in value:
                    current = merged.get(fact_key)
                    candidate = value[fact_key]
                    if isinstance(current, int) and isinstance(candidate, int) and candidate < current:
                        raise PlanIntegrityError(f"replan cannot reduce discovered fact {fact_key!r}")
                    merged[fact_key] = max(current, candidate) if isinstance(current, int) and isinstance(candidate, int) else copy.deepcopy(candidate)
            continue
        if key == "finding_ledger" and not is_v2:
            if not isinstance(value, list):
                raise ValueError("context.finding_ledger must be an array")
            discovered = sum(
                1 for finding in value
                if isinstance(finding, Mapping) and finding.get("priority") == "mandatory"
                and finding.get("state") not in {"resolved", "closed", "rejected"}
            )
            current = merged.get("mandatory_findings", 0)
            if isinstance(current, int) and discovered < current:
                raise PlanIntegrityError("replan cannot reduce mandatory finding obligations")
            merged["mandatory_findings"] = max(current, discovered) if isinstance(current, int) else discovered
            continue
        if key == "facts":
            merge_facts(value)
            continue
        if key == "finding_ledger":
            merge_ledger(value)
            continue
        if key == "amendments":
            if not isinstance(value, list) or not isinstance(merged.get("amendments", []), list):
                raise ValueError("context.amendments must be an array")
            existing = list(merged.get("amendments", []))
            for item in value:
                if item not in existing:
                    existing.append(copy.deepcopy(item))
            merged["amendments"] = existing
            continue
        if key in {"blast_radius", "write_chain_components"}:
            current = merged.get(key)
            if isinstance(current, int) and isinstance(value, int) and value < current:
                raise PlanIntegrityError(f"replan cannot reduce discovered fact {key!r}")
            merged[key] = max(current, value) if isinstance(current, int) and isinstance(value, int) else copy.deepcopy(value)
            continue
        if key in tri_state_fields:
            current = merged.get(key, "unknown")
            if current != "unknown" and current != value:
                raise PlanIntegrityError(f"replan cannot change resolved risk field {key!r}")
        merged[key] = copy.deepcopy(value)
    facts = merged.get("facts")
    if isinstance(facts, Mapping):
        for key in ("blast_radius", "write_chain_components"):
            if key in facts:
                current = merged.get(key)
                candidate = facts[key]
                merged[key] = max(current, candidate) if isinstance(current, int) and isinstance(candidate, int) else candidate
    ledger = merged.get("finding_ledger")
    if isinstance(ledger, list):
        merged["mandatory_findings"] = sum(
            1 for finding in ledger
            if isinstance(finding, Mapping) and finding.get("priority") == "mandatory"
            and finding.get("state") not in {"resolved", "closed", "rejected"}
        )
    return merged


def revise_plan(
    manifest: Mapping[str, Any],
    previous_plan: Mapping[str, Any],
    discovered_context: Mapping[str, Any],
    *,
    reason: str,
) -> dict[str, Any]:
    """Create an immutable child plan when late audit facts change obligations."""

    if not isinstance(discovered_context, Mapping):
        raise ValueError("discovered_context must be an object")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("revised plans require a non-empty reason")
    assert_plan_matches(manifest, previous_plan, require_binding=True)
    previous_revision = previous_plan.get("plan_revision")
    if isinstance(previous_revision, bool) or not isinstance(previous_revision, int):
        raise PlanIntegrityError("parent plan revision is invalid")
    merged_context = _merge_context(previous_plan["context"], discovered_context)
    revised = evaluate_manifest(
        manifest,
        merged_context,
        plan_revision=previous_revision + 1,
        parent_plan_id=str(previous_plan["plan_id"]),
        revision_reason=reason.strip(),
        bundle_root=str(previous_plan["bundle_root"]),
    )
    previous_states = {str(gate["id"]): gate.get("activation_state") for gate in previous_plan.get("gates", [])}
    revised_states = {str(gate["id"]): gate.get("activation_state") for gate in revised.get("gates", [])}
    dropped = sorted(
        gate_id
        for gate_id, state in previous_states.items()
        if state == "active" and revised_states.get(gate_id) != "active"
    )
    if dropped:
        raise PlanIntegrityError(f"replan cannot deactivate previously active gates without an approved amendment: {dropped}")
    return revised


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate VHEATM gate activation without executing audit tools.")
    parser.add_argument("--root", type=Path)
    parser.add_argument("--context", type=Path)
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()

    try:
        root = resolve_control_root(args.root)
        manifest = _load_document(root / "manifests" / "vheatm-v17.yaml")
        context = _load_document(args.context) if args.context else {"schema_version": "1.0.0"}
        context_schema = _load_document(root / "schemas" / "audit-context.schema.json")
        validate_context(context, context_schema)
        from .bundle import build_bundle

        plan = evaluate_manifest(manifest, context, bundle_root=build_bundle(root)["bundle_root"])
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(plan, indent=None if args.compact else 2, sort_keys=args.compact))
    return 2 if plan["summary"]["completion_blocked"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
