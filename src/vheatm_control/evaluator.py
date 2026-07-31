from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping

import yaml
from jsonschema import Draft202012Validator

from .activation import ActivationError, TruthValue, compile_activation


class ContextValidationError(ValueError):
    """Raised when an audit context violates its machine contract."""


def _load_document(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        if path.suffix.lower() == ".json":
            value = json.load(handle)
        else:
            value = yaml.safe_load(handle)
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
        messages.append(f"{location}: {error.message}")
    raise ContextValidationError("; ".join(messages))


def normalize_context(manifest: Mapping[str, Any], supplied: Mapping[str, Any] | None = None) -> dict[str, Any]:
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
    return normalized


def evaluate_manifest(manifest: Mapping[str, Any], supplied_context: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Build an activation plan; this function never claims that a gate passed."""

    context = normalize_context(manifest, supplied_context)
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

    return {
        "schema_version": "1.0.0",
        "framework_version": manifest["framework"]["version"],
        "context": context,
        "summary": {
            **counts,
            "total": len(gate_results),
            "completion_blocked": counts["unknown"] > 0,
        },
        "gates": gate_results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate VHEATM gate activation without executing audit tools.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--context", type=Path)
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()

    try:
        manifest = _load_document(args.root / "manifests" / "vheatm-v17.yaml")
        context = _load_document(args.context) if args.context else {}
        context_schema = _load_document(args.root / "schemas" / "audit-context.schema.json")
        validate_context(context, context_schema)
        plan = evaluate_manifest(manifest, context)
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(plan, indent=None if args.compact else 2, sort_keys=args.compact))
    return 2 if plan["summary"]["completion_blocked"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
