from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from .activation import ActivationError, compile_activation
from .models import Manifest
from .module_router import validate_module_repository


REQUIRED_SCHEMA_FILES = frozenset(
    {
        "approval-token.schema.json",
        "audit-context.schema.json",
        "audit-lifecycle.schema.json",
        "audit-report.schema.json",
        "claim.schema.json",
        "finding.schema.json",
        "gate-plan.schema.json",
        "module-contract.schema.json",
        "module-registry.schema.json",
        "module-selection.schema.json",
        "policy-decision.schema.json",
        "provenance-record.schema.json",
        "provenance-registry.schema.json",
        "runtime-policy.schema.json",
        "tool-request.schema.json",
        "vheatm-manifest.schema.json",
    }
)


@dataclass(frozen=True)
class ValidationIssue:
    source: str
    message: str


def _load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _validate_schema_documents(schema_dir: Path) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    paths = sorted(schema_dir.glob("*.schema.json"))
    present = {path.name for path in paths}
    for missing in sorted(REQUIRED_SCHEMA_FILES - present):
        issues.append(ValidationIssue("schemas", f"missing required schema: {missing}"))
    seen_ids: dict[str, str] = {}
    for path in paths:
        try:
            schema = _load_json(path)
            Draft202012Validator.check_schema(schema)
        except Exception as exc:
            issues.append(ValidationIssue(str(path.name), f"invalid Draft 2020-12 schema: {exc}"))
            continue
        schema_id = schema.get("$id") if isinstance(schema, dict) else None
        if not isinstance(schema_id, str) or not schema_id:
            issues.append(ValidationIssue(str(path.name), "schema requires a non-empty $id"))
            continue
        previous = seen_ids.get(schema_id)
        if previous is not None:
            issues.append(ValidationIssue(str(path.name), f"duplicate schema $id also used by {previous}: {schema_id}"))
        seen_ids[schema_id] = path.name
    return issues


def _schema_registry(schema_dir: Path) -> Registry:
    registry = Registry()
    for path in sorted(schema_dir.glob("*.schema.json")):
        schema = _load_json(path)
        resource = Resource.from_contents(schema)
        registry = registry.with_resource(schema["$id"], resource)
    return registry


def _validate_schema(instance: Any, schema: dict[str, Any], registry: Registry, source: str) -> list[ValidationIssue]:
    validator = Draft202012Validator(schema, registry=registry)
    issues: list[ValidationIssue] = []
    for error in sorted(validator.iter_errors(instance), key=lambda item: list(item.absolute_path)):
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        issues.append(ValidationIssue(source, f"{location}: {error.message}"))
    return issues


def _activation_fields(context_schema: dict[str, Any]) -> set[str]:
    properties = context_schema.get("properties", {})
    fields = set(properties) - {"schema_version", "declarations"}
    declaration_properties = properties.get("declarations", {}).get("properties", {})
    fields.update(declaration_properties)
    return fields


def _validate_activations(parsed: Manifest, context_schema: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    allowed_fields = _activation_fields(context_schema)
    declared_defaults = set(parsed.defaults.declarations)

    for gate in parsed.gates.items:
        try:
            compiled = compile_activation(gate.activation)
        except ActivationError as exc:
            issues.append(ValidationIssue(f"manifest gate {gate.id}", f"invalid activation: {exc}"))
            continue
        unknown_fields = sorted(compiled.references - allowed_fields)
        if unknown_fields:
            issues.append(
                ValidationIssue(
                    f"manifest gate {gate.id}",
                    f"activation references fields absent from audit-context schema: {unknown_fields}",
                )
            )
        declaration_refs = compiled.references & set(
            context_schema.get("properties", {}).get("declarations", {}).get("properties", {})
        )
        missing_defaults = sorted(declaration_refs - declared_defaults)
        if missing_defaults:
            issues.append(
                ValidationIssue(
                    f"manifest gate {gate.id}",
                    f"security declaration references lack explicit unknown defaults: {missing_defaults}",
                )
            )
        if gate.layer == "core" and gate.activation.strip() != "always":
            issues.append(ValidationIssue(f"manifest gate {gate.id}", "core gates must activate with 'always'"))
    return issues


def validate_repository(root: Path) -> list[ValidationIssue]:
    root = root.resolve()
    schema_dir = root / "schemas"
    manifest_path = root / "manifests" / "vheatm-v17.yaml"
    policy_path = root / "policies" / "runtime-boundaries.yaml"
    module_registry_path = root / "modules" / "registry.yaml"
    skill_path = root / "SKILL.md"

    required = [schema_dir, manifest_path, policy_path, module_registry_path, skill_path]
    missing = [str(path.relative_to(root)) for path in required if not path.exists()]
    if missing:
        return [ValidationIssue("repository", f"missing required path: {path}") for path in missing]

    schema_issues = _validate_schema_documents(schema_dir)
    if schema_issues:
        return schema_issues

    registry = _schema_registry(schema_dir)
    manifest = _load_yaml(manifest_path)
    policy = _load_yaml(policy_path)
    manifest_schema = _load_json(schema_dir / "vheatm-manifest.schema.json")
    policy_schema = _load_json(schema_dir / "runtime-policy.schema.json")
    context_schema = _load_json(schema_dir / "audit-context.schema.json")

    issues: list[ValidationIssue] = []
    issues.extend(_validate_schema(manifest, manifest_schema, registry, str(manifest_path.relative_to(root))))
    issues.extend(_validate_schema(policy, policy_schema, registry, str(policy_path.relative_to(root))))

    if not issues:
        try:
            parsed = Manifest.model_validate(manifest)
        except Exception as exc:
            issues.append(ValidationIssue(str(manifest_path.relative_to(root)), str(exc)))
        else:
            phase_ids = {phase.id for phase in parsed.phases.items}
            unknown_phase_gates = [gate.id for gate in parsed.gates.items if gate.phase not in phase_ids]
            if unknown_phase_gates:
                issues.append(ValidationIssue("manifest", f"gates reference unknown phases: {unknown_phase_gates}"))
            issues.extend(_validate_activations(parsed, context_schema))

            module_issues, _ = validate_module_repository(
                root,
                manifest,
                module_schema=_load_json(schema_dir / "module-contract.schema.json"),
                registry_schema=_load_json(schema_dir / "module-registry.schema.json"),
                context_schema=context_schema,
            )
            issues.extend(ValidationIssue(issue.source, issue.message) for issue in module_issues)

    issues.extend(_validate_runtime_policy_invariants(policy))
    return issues


def _validate_runtime_policy_invariants(policy: dict[str, Any]) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if policy.get("default_decision") != "unknown":
        issues.append(ValidationIssue("runtime policy", "default_decision must be unknown"))
    if policy.get("tools", {}).get("default") != "deny":
        issues.append(ValidationIssue("runtime policy", "tools.default must be deny"))
    if policy.get("egress", {}).get("default") != "deny":
        issues.append(ValidationIssue("runtime policy", "egress.default must be deny"))
    approval = set(policy.get("human_approval", {}).get("token_required_for", []))
    required = {"execute", "write", "network", "secrets"}
    if not required.issubset(approval):
        issues.append(ValidationIssue("runtime policy", f"human approval missing tool classes: {sorted(required - approval)}"))
    required_bindings = {"tool_class", "exact_scope", "expiry", "requester"}
    bindings = set(policy.get("human_approval", {}).get("approval_must_bind", []))
    if not required_bindings.issubset(bindings):
        issues.append(ValidationIssue("runtime policy", f"approval binding missing fields: {sorted(required_bindings - bindings)}"))
    if policy.get("human_approval", {}).get("reusable") is not False:
        issues.append(ValidationIssue("runtime policy", "approval tokens must be single-use"))
    if policy.get("taint", {}).get("propagation") != "transitive":
        issues.append(ValidationIssue("runtime policy", "taint propagation must be transitive"))
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the VHEATM canonical control-plane artifacts.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()

    issues = validate_repository(args.root)
    if args.as_json:
        print(json.dumps({"valid": not issues, "issues": [issue.__dict__ for issue in issues]}, indent=2))
    elif issues:
        for issue in issues:
            print(f"ERROR [{issue.source}] {issue.message}")
    else:
        print("VHEATM control-plane validation passed.")
    return 1 if issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
