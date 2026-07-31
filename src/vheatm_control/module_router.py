from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

import yaml
from jsonschema import Draft202012Validator


class ModuleRoutingError(ValueError):
    """Raised when module artifacts or a routing request are invalid."""


@dataclass(frozen=True)
class ModuleIssue:
    source: str
    message: str


@dataclass(frozen=True)
class LoadedModule:
    document: dict[str, Any]
    path: Path
    instruction_path: Path
    digest: str
    instruction_digest: str
    estimated_tokens: int
    instruction_ref: str

    @property
    def id(self) -> str:
        return str(self.document["id"])


def _load_document(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        if path.suffix.lower() == ".json":
            value = json.load(handle)
        else:
            value = yaml.safe_load(handle)
    if not isinstance(value, dict):
        raise ModuleRoutingError(f"{path} must contain an object")
    return value


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _estimated_tokens(data: bytes) -> int:
    # Conservative tokenizer-independent proxy used only for disclosure budgets.
    return max(1, (len(data) + 2) // 3)


def _safe_relative_path(value: str, *, label: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise ModuleRoutingError(f"{label} must be a repository-relative path without '..': {value!r}")
    return path


def _schema_errors(instance: Any, schema: Mapping[str, Any], source: str) -> list[ModuleIssue]:
    issues: list[ModuleIssue] = []
    validator = Draft202012Validator(dict(schema))
    for error in sorted(validator.iter_errors(instance), key=lambda item: list(item.absolute_path)):
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        issues.append(ModuleIssue(source, f"{location}: {error.message}"))
    return issues


def _find_cycle(graph: Mapping[str, tuple[str, ...]]) -> tuple[str, ...] | None:
    visiting: set[str] = set()
    visited: set[str] = set()
    stack: list[str] = []

    def visit(node: str) -> tuple[str, ...] | None:
        if node in visiting:
            index = stack.index(node)
            return tuple(stack[index:] + [node])
        if node in visited:
            return None
        visiting.add(node)
        stack.append(node)
        for dependency in graph.get(node, ()):
            cycle = visit(dependency)
            if cycle:
                return cycle
        stack.pop()
        visiting.remove(node)
        visited.add(node)
        return None

    for node in sorted(graph):
        cycle = visit(node)
        if cycle:
            return cycle
    return None


def validate_module_repository(
    root: Path,
    manifest: Mapping[str, Any],
    *,
    module_schema: Mapping[str, Any] | None = None,
    registry_schema: Mapping[str, Any] | None = None,
    context_schema: Mapping[str, Any] | None = None,
) -> tuple[list[ModuleIssue], dict[str, LoadedModule]]:
    root = root.resolve()
    module_root = root / "modules"
    registry_path = module_root / "registry.yaml"
    skill_path = root / "SKILL.md"
    issues: list[ModuleIssue] = []

    if not registry_path.exists():
        return [ModuleIssue("modules", "missing modules/registry.yaml")], {}
    if not skill_path.exists():
        issues.append(ModuleIssue("SKILL.md", "missing compact skill router"))
    else:
        line_count = len(skill_path.read_text(encoding="utf-8").splitlines())
        if line_count > 350:
            issues.append(ModuleIssue("SKILL.md", f"router must be at most 350 lines, found {line_count}"))
        if line_count < 20:
            issues.append(ModuleIssue("SKILL.md", f"router is unexpectedly small, found {line_count} lines"))

    try:
        registry = _load_document(registry_path)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        issues.append(ModuleIssue("modules/registry.yaml", str(exc)))
        return issues, {}

    if registry_schema is not None:
        issues.extend(_schema_errors(registry, registry_schema, "modules/registry.yaml"))
    if issues:
        return issues, {}

    framework_version = manifest.get("framework", {}).get("version")
    if registry.get("framework_version") != framework_version:
        issues.append(
            ModuleIssue(
                "modules/registry.yaml",
                f"framework_version must match manifest ({framework_version!r})",
            )
        )

    manifest_gates = {item["id"]: item for item in manifest.get("gates", {}).get("items", [])}
    manifest_phases = {item["id"] for item in manifest.get("phases", {}).get("items", [])}
    loaded: dict[str, LoadedModule] = {}
    registry_ids: set[str] = set()

    for entry in registry.get("modules", []):
        module_id = str(entry.get("id", ""))
        if module_id in registry_ids:
            issues.append(ModuleIssue("modules/registry.yaml", f"duplicate module id: {module_id}"))
            continue
        registry_ids.add(module_id)
        try:
            relative = _safe_relative_path(str(entry.get("path", "")), label="module path")
        except ModuleRoutingError as exc:
            issues.append(ModuleIssue(f"registry module {module_id}", str(exc)))
            continue
        path = root / Path(*relative.parts)
        resolved_module_root = module_root.resolve()
        resolved_path = path.resolve()
        try:
            resolved_path.relative_to(resolved_module_root)
        except ValueError:
            issues.append(ModuleIssue(f"registry module {module_id}", "module path must remain under modules/"))
            continue
        if path.is_symlink():
            issues.append(ModuleIssue(f"registry module {module_id}", "module document must not be a symlink"))
            continue
        if not path.is_file():
            issues.append(ModuleIssue(f"registry module {module_id}", f"missing module document: {relative}"))
            continue
        raw = path.read_bytes()
        digest = _sha256(raw)
        if digest != entry.get("sha256"):
            issues.append(ModuleIssue(f"registry module {module_id}", "module SHA-256 does not match registry"))
            continue
        try:
            document = _load_document(path)
        except (OSError, ValueError, yaml.YAMLError) as exc:
            issues.append(ModuleIssue(str(relative), str(exc)))
            continue
        if module_schema is not None:
            module_issues = _schema_errors(document, module_schema, str(relative))
            issues.extend(module_issues)
            if module_issues:
                continue
        if document.get("id") != module_id:
            issues.append(ModuleIssue(str(relative), f"module id must match registry id {module_id!r}"))
            continue

        gates = tuple(document.get("gate_coverage", []))
        unknown_gates = sorted(set(gates) - set(manifest_gates))
        if unknown_gates:
            issues.append(ModuleIssue(str(relative), f"unknown gate coverage: {unknown_gates}"))
        expected_phases = {manifest_gates[gate]["phase"] for gate in gates if gate in manifest_gates}
        declared_phases = set(document.get("phase_coverage", []))
        if not expected_phases.issubset(declared_phases):
            issues.append(
                ModuleIssue(
                    str(relative),
                    f"phase_coverage missing phases implied by gates: {sorted(expected_phases - declared_phases)}",
                )
            )
        unknown_phases = sorted(declared_phases - manifest_phases)
        if unknown_phases:
            issues.append(ModuleIssue(str(relative), f"unknown phase coverage: {unknown_phases}"))

        disclosure = document.get("contract", {}).get("disclosure", {})
        try:
            instruction_relative = _safe_relative_path(
                str(disclosure.get("instruction_path", "")), label="instruction path"
            )
        except ModuleRoutingError as exc:
            issues.append(ModuleIssue(str(relative), str(exc)))
            continue
        module_dir = path.parent.resolve()
        instruction_path = (module_dir / Path(*instruction_relative.parts)).resolve()
        try:
            instruction_path.relative_to(module_dir)
        except ValueError:
            issues.append(ModuleIssue(str(relative), "instruction path must remain inside the module directory"))
            continue
        raw_instruction_path = path.parent / Path(*instruction_relative.parts)
        if raw_instruction_path.is_symlink():
            issues.append(ModuleIssue(str(relative), "instruction file must not be a symlink"))
            continue
        if not instruction_path.is_file():
            issues.append(ModuleIssue(str(relative), f"missing instruction file: {instruction_relative}"))
            continue
        instruction_bytes = instruction_path.read_bytes()
        instruction_digest = _sha256(instruction_bytes)
        if instruction_digest != disclosure.get("instruction_sha256"):
            issues.append(ModuleIssue(str(relative), "instruction SHA-256 does not match module contract"))
        tokens = _estimated_tokens(instruction_bytes)
        token_budget = int(disclosure.get("token_budget", 0))
        if tokens > token_budget:
            issues.append(
                ModuleIssue(str(relative), f"instruction estimate {tokens} exceeds token budget {token_budget}")
            )
        if context_schema is not None:
            properties = context_schema.get("properties", {})
            allowed_context = set(properties) - {"schema_version", "declarations"}
            allowed_context.update(properties.get("declarations", {}).get("properties", {}))
            required_context = set(document.get("contract", {}).get("inputs", {}).get("required_context_fields", []))
            unknown_context = sorted(required_context - allowed_context)
            if unknown_context:
                issues.append(ModuleIssue(str(relative), f"unknown required context fields: {unknown_context}"))

        runtime = document.get("contract", {}).get("runtime", {})
        tool_classes = set(runtime.get("tool_classes", []))
        if runtime.get("network_required") and "network" not in tool_classes:
            issues.append(ModuleIssue(str(relative), "network_required modules must declare the network tool class"))
        if runtime.get("sandbox_required") and "execute" not in tool_classes:
            issues.append(ModuleIssue(str(relative), "sandbox_required modules must declare the execute tool class"))

        instruction_ref = (relative.parent / instruction_relative).as_posix()
        loaded[module_id] = LoadedModule(
            document=document,
            path=path,
            instruction_path=instruction_path,
            digest=digest,
            instruction_digest=instruction_digest,
            estimated_tokens=tokens,
            instruction_ref=instruction_ref,
        )

    module_ids = set(loaded)
    graph: dict[str, tuple[str, ...]] = {}
    for module_id, module in loaded.items():
        selection = module.document.get("selection", {})
        dependencies = tuple(selection.get("dependencies", []))
        conflicts = tuple(selection.get("conflicts", []))
        graph[module_id] = dependencies
        missing_dependencies = sorted(set(dependencies) - module_ids)
        if missing_dependencies:
            issues.append(ModuleIssue(module_id, f"unknown dependencies: {missing_dependencies}"))
        missing_conflicts = sorted(set(conflicts) - module_ids)
        if missing_conflicts:
            issues.append(ModuleIssue(module_id, f"unknown conflicts: {missing_conflicts}"))
        for conflict in conflicts:
            if conflict in loaded:
                reverse = set(loaded[conflict].document.get("selection", {}).get("conflicts", []))
                if module_id not in reverse:
                    issues.append(ModuleIssue(module_id, f"conflict with {conflict} must be symmetric"))

    cycle = _find_cycle(graph)
    if cycle:
        issues.append(ModuleIssue("modules", f"dependency cycle: {' -> '.join(cycle)}"))

    required_coverage = set(registry.get("required_gate_coverage", []))
    actual_coverage = {gate for module in loaded.values() for gate in module.document.get("gate_coverage", [])}
    missing_coverage = sorted(required_coverage - actual_coverage)
    if missing_coverage:
        issues.append(ModuleIssue("modules/registry.yaml", f"required gates lack module coverage: {missing_coverage}"))
    if registry.get("coverage_mode") == "complete":
        all_gates = set(manifest_gates)
        uncovered = sorted(all_gates - actual_coverage)
        if uncovered:
            issues.append(ModuleIssue("modules/registry.yaml", f"complete registry leaves gates uncovered: {uncovered}"))

    return issues, loaded


def _registry_root(registry: Mapping[str, Any]) -> str:
    subject = {
        "schema_version": registry.get("schema_version"),
        "framework_version": registry.get("framework_version"),
        "coverage_mode": registry.get("coverage_mode"),
        "hard_token_budget": registry.get("hard_token_budget"),
        "required_gate_coverage": sorted(registry.get("required_gate_coverage", [])),
        "modules": [
            {"id": item.get("id"), "path": item.get("path"), "sha256": item.get("sha256")}
            for item in registry.get("modules", [])
        ],
    }
    return _sha256(json.dumps(subject, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _topological_order(selected: set[str], modules: Mapping[str, LoadedModule], phase_order: Mapping[str, int]) -> list[str]:
    result: list[str] = []
    temporary: set[str] = set()
    permanent: set[str] = set()

    def sort_key(module_id: str) -> tuple[int, int, str]:
        document = modules[module_id].document
        phases = document.get("phase_coverage", [])
        first_phase = min((phase_order.get(phase, 10_000) for phase in phases), default=10_000)
        priority = int(document.get("selection", {}).get("priority", 50))
        return first_phase, priority, module_id

    def visit(module_id: str) -> None:
        if module_id in permanent:
            return
        if module_id in temporary:
            raise ModuleRoutingError(f"dependency cycle encountered while routing at {module_id}")
        temporary.add(module_id)
        for dependency in sorted(modules[module_id].document.get("selection", {}).get("dependencies", []), key=sort_key):
            if dependency in selected:
                visit(dependency)
        temporary.remove(module_id)
        permanent.add(module_id)
        result.append(module_id)

    for module_id in sorted(selected, key=sort_key):
        visit(module_id)
    return result


def route_modules(
    manifest: Mapping[str, Any],
    registry: Mapping[str, Any],
    modules: Mapping[str, LoadedModule],
    gate_plan: Mapping[str, Any],
    *,
    include_instructions: bool = False,
) -> dict[str, Any]:
    if gate_plan.get("framework_version") != manifest.get("framework", {}).get("version"):
        raise ModuleRoutingError("gate plan framework_version does not match the canonical manifest")
    plan_gates = gate_plan.get("gates")
    if not isinstance(plan_gates, list):
        raise ModuleRoutingError("gate plan requires a gates array")
    gate_states: dict[str, str] = {}
    for gate in plan_gates:
        if not isinstance(gate, Mapping) or not isinstance(gate.get("id"), str):
            raise ModuleRoutingError("every gate plan entry requires an id")
        if gate["id"] in gate_states:
            raise ModuleRoutingError(f"duplicate gate plan id: {gate['id']}")
        state = str(gate.get("activation_state"))
        if state not in {"active", "inactive", "unknown"}:
            raise ModuleRoutingError(f"invalid activation_state for {gate['id']}: {state!r}")
        gate_states[gate["id"]] = state

    manifest_gates = {item["id"] for item in manifest.get("gates", {}).get("items", [])}
    if set(gate_states) != manifest_gates:
        missing = sorted(manifest_gates - set(gate_states))
        extra = sorted(set(gate_states) - manifest_gates)
        raise ModuleRoutingError(f"gate plan coverage mismatch; missing={missing}, extra={extra}")

    selected: set[str] = set()
    reasons: dict[str, list[str]] = {module_id: [] for module_id in modules}
    unresolved: dict[str, list[str]] = {}
    unselected: list[dict[str, Any]] = []

    for module_id, module in modules.items():
        gates = tuple(module.document.get("gate_coverage", []))
        active = sorted(gate for gate in gates if gate_states.get(gate) == "active")
        unknown = sorted(gate for gate in gates if gate_states.get(gate) == "unknown")
        policy = module.document.get("selection", {}).get("policy", "any_active_gate")
        should_select = bool(active) if policy == "any_active_gate" else bool(gates) and len(active) == len(gates)
        if should_select:
            selected.add(module_id)
            reasons[module_id].append(f"active gate coverage: {', '.join(active)}")
        elif unknown:
            unresolved[module_id] = unknown
        else:
            unselected.append({"id": module_id, "reason": "no covered gate is active"})

    queue = list(selected)
    while queue:
        module_id = queue.pop()
        for dependency in modules[module_id].document.get("selection", {}).get("dependencies", []):
            if dependency not in selected:
                selected.add(dependency)
                reasons[dependency].append(f"dependency of {module_id}")
                queue.append(dependency)

    unselected = [item for item in unselected if item["id"] not in selected]

    conflicts: list[dict[str, str]] = []
    for module_id in sorted(selected):
        for conflict in modules[module_id].document.get("selection", {}).get("conflicts", []):
            if conflict in selected and module_id < conflict:
                conflicts.append({"left": module_id, "right": conflict})

    phase_order = {
        item["id"]: int(item["order"])
        for item in manifest.get("phases", {}).get("items", [])
    }
    order = _topological_order(selected, modules, phase_order)
    entries: list[dict[str, Any]] = []
    total_tokens = 0
    for module_id in order:
        module = modules[module_id]
        total_tokens += module.estimated_tokens
        entry: dict[str, Any] = {
            "id": module_id,
            "kind": module.document.get("kind"),
            "title": module.document.get("title"),
            "summary": module.document.get("summary"),
            "gate_coverage": module.document.get("gate_coverage", []),
            "phase_coverage": module.document.get("phase_coverage", []),
            "instruction_path": module.instruction_ref,
            "instruction_sha256": module.instruction_digest,
            "estimated_tokens": module.estimated_tokens,
            "reasons": reasons[module_id],
        }
        if include_instructions:
            entry["instructions"] = module.instruction_path.read_text(encoding="utf-8")
        entries.append(entry)

    hard_budget = int(registry.get("hard_token_budget", 0))
    budget_exceeded = total_tokens > hard_budget
    unknown_gate_ids = sorted(gate for gate, state in gate_states.items() if state == "unknown")
    completion_blocked = bool(conflicts or unresolved or unknown_gate_ids or budget_exceeded)
    return {
        "schema_version": "1.0.0",
        "framework_version": manifest["framework"]["version"],
        "registry_root": _registry_root(registry),
        "summary": {
            "selected": len(entries),
            "unselected": len(unselected),
            "unresolved": len(unresolved),
            "estimated_tokens": total_tokens,
            "hard_token_budget": hard_budget,
            "budget_exceeded": budget_exceeded,
            "completion_blocked": completion_blocked,
        },
        "selected_modules": entries,
        "unselected_modules": sorted(unselected, key=lambda item: item["id"]),
        "unresolved_modules": [
            {"id": module_id, "unknown_gates": unresolved[module_id]}
            for module_id in sorted(unresolved)
        ],
        "unknown_gates": unknown_gate_ids,
        "conflicts": conflicts,
    }


def load_and_route(root: Path, gate_plan: Mapping[str, Any], *, include_instructions: bool = False) -> dict[str, Any]:
    root = root.resolve()
    manifest = _load_document(root / "manifests" / "vheatm-v17.yaml")
    registry = _load_document(root / "modules" / "registry.yaml")
    module_schema = _load_document(root / "schemas" / "module-contract.schema.json")
    registry_schema = _load_document(root / "schemas" / "module-registry.schema.json")
    context_schema = _load_document(root / "schemas" / "audit-context.schema.json")
    issues, modules = validate_module_repository(
        root,
        manifest,
        module_schema=module_schema,
        registry_schema=registry_schema,
        context_schema=context_schema,
    )
    if issues:
        raise ModuleRoutingError("; ".join(f"[{issue.source}] {issue.message}" for issue in issues))
    return route_modules(manifest, registry, modules, gate_plan, include_instructions=include_instructions)


def main() -> int:
    parser = argparse.ArgumentParser(description="Select VHEATM instruction modules from a canonical gate plan.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--plan", type=Path, help="Existing gate plan in JSON or YAML format")
    source.add_argument("--context", type=Path, help="Audit context to evaluate before routing")
    parser.add_argument("--include-instructions", action="store_true")
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()

    try:
        if args.plan:
            gate_plan = _load_document(args.plan)
        else:
            from .evaluator import evaluate_manifest, validate_context

            manifest = _load_document(args.root / "manifests" / "vheatm-v17.yaml")
            context = _load_document(args.context)
            context_schema = _load_document(args.root / "schemas" / "audit-context.schema.json")
            validate_context(context, context_schema)
            gate_plan = evaluate_manifest(manifest, context)
        result = load_and_route(args.root, gate_plan, include_instructions=args.include_instructions)
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=None if args.compact else 2, sort_keys=args.compact))
    return 2 if result["summary"]["completion_blocked"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
