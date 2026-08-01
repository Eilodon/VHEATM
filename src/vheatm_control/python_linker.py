from __future__ import annotations

import argparse
import hashlib
import json
import keyword
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from .structural_probe import ProbeError, verify_probe_bundle

SCHEMA_VERSION = "1.0.0"
LINKAGE_TYPE = "python_import_graph_v1"


class LinkerError(ValueError):
    """Raised when a structural linkage request or bundle is invalid."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _content_id(prefix: str, value: Any) -> str:
    return f"{prefix}-{_sha256(value)[:16].upper()}"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _normalize_timestamp(value: str) -> str:
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise LinkerError("generated_at must be an RFC 3339 date-time") from exc
    if parsed.tzinfo is None:
        raise LinkerError("generated_at must include a timezone")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _normalize_source_root(value: str) -> str:
    if value == ".":
        return value
    if not value or "\x00" in value:
        raise LinkerError("source root must be non-empty and contain no NUL")
    if "\\" in value or value.startswith("/") or value.startswith("./") or value.endswith("/") or "//" in value:
        raise LinkerError(f"source root is not normalized: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise LinkerError(f"source root escapes or is not normalized: {value!r}")
    return path.as_posix()


def _root_parts(value: str) -> tuple[str, ...]:
    return () if value == "." else PurePosixPath(value).parts


def _validate_source_roots(values: Sequence[str]) -> list[str]:
    roots = sorted(set(_normalize_source_root(value) for value in values))
    if not roots:
        raise LinkerError("at least one source root is required")
    for index, left in enumerate(roots):
        left_parts = _root_parts(left)
        for right in roots[index + 1 :]:
            right_parts = _root_parts(right)
            shortest = min(len(left_parts), len(right_parts))
            if left_parts[:shortest] == right_parts[:shortest]:
                raise LinkerError(f"source roots must not overlap: {left!r} and {right!r}")
    return roots


def _path_under_root(path: str, source_root: str) -> PurePosixPath | None:
    path_parts = PurePosixPath(path).parts
    root_parts = _root_parts(source_root)
    if path_parts[: len(root_parts)] != root_parts:
        return None
    relative = path_parts[len(root_parts) :]
    return PurePosixPath(*relative) if relative else None


def _module_from_path(path: str, source_root: str) -> tuple[str, bool] | None:
    relative = _path_under_root(path, source_root)
    if relative is None or relative.suffix != ".py":
        return None
    if relative.name == "__init__.py":
        parts = relative.parts[:-1]
        is_package = True
    else:
        parts = (*relative.parts[:-1], relative.stem)
        is_package = False
    if not parts:
        return None
    if any(not part.isidentifier() or keyword.iskeyword(part) for part in parts):
        return None
    return ".".join(parts), is_package


def _target(*, kind: str, module: str, file_record: Mapping[str, Any], symbol: str | None = None) -> dict[str, Any]:
    qualified = module if symbol is None else f"{module}.{symbol}"
    return {
        "kind": kind,
        "module": module,
        "symbol": symbol,
        "qualified_name": qualified,
        "path": file_record["path"],
        "source_id": file_record["source_id"],
        "definition_line": file_record.get("definition_line"),
        "definition_column": file_record.get("definition_column"),
    }


def _dedupe_targets(targets: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    unique = {tuple(sorted(dict(item).items())): dict(item) for item in targets}
    return sorted(unique.values(), key=lambda item: (item["qualified_name"], item["path"], item["kind"]))


def _resolve_from_base(module: str, is_package: bool, level: int, imported_module: str | None) -> str | None:
    if level == 0:
        return imported_module or ""
    package = module if is_package else module.rpartition(".")[0]
    package_parts = package.split(".") if package else []
    upward = level - 1
    if upward > len(package_parts):
        return None
    anchor = package_parts[: len(package_parts) - upward]
    suffix = imported_module.split(".") if imported_module else []
    result = [*anchor, *suffix]
    return ".".join(result) if result else None


def _module_target_list(module: str, module_index: Mapping[str, Sequence[Mapping[str, Any]]]) -> list[dict[str, Any]]:
    return [_target(kind="module", module=module, file_record=item) for item in module_index.get(module, [])]


def _symbol_target_list(
    module: str,
    symbol: str,
    symbol_index: Mapping[str, Mapping[str, Sequence[Mapping[str, Any]]]],
    *,
    before: tuple[int, int] | None = None,
) -> list[dict[str, Any]]:
    records = symbol_index.get(module, {}).get(symbol, [])
    if before is not None:
        records = [
            item
            for item in records
            if (int(item["definition_line"]), int(item["definition_column"])) < before
        ]
    return [_target(kind="symbol", module=module, symbol=symbol, file_record=item) for item in records]


def _import_requested(item: Mapping[str, Any]) -> str:
    if item.get("kind") == "import":
        return str(item.get("module"))
    prefix = "." * int(item.get("level", 0))
    module = item.get("module") or ""
    name = item.get("name") or ""
    return f"{prefix}{module}:{name}"


def _build_import_edge(
    *,
    file_record: Mapping[str, Any],
    import_fact: Mapping[str, Any],
    module_index: Mapping[str, Sequence[Mapping[str, Any]]],
    symbol_index: Mapping[str, Mapping[str, Sequence[Mapping[str, Any]]]],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    source_module = str(file_record["module"])
    source_path = str(file_record["path"])
    kind = str(import_fact["kind"])
    alias = import_fact.get("alias")
    requested = _import_requested(import_fact)
    targets: list[dict[str, Any]] = []
    state: str
    binding: dict[str, Any] | None = None

    if kind == "import":
        imported_module = str(import_fact["module"])
        targets = _module_target_list(imported_module, module_index)
        if len(targets) == 1:
            state = "internal_module"
        elif len(targets) > 1:
            state = "ambiguous"
        else:
            state = "external"
        local_name = str(alias) if alias else imported_module.split(".", 1)[0]
        pattern = str(alias) if alias else imported_module
        binding = {
            "local_name": local_name,
            "pattern": pattern,
            "state": state,
            "targets": targets,
            "line": int(import_fact["line"]),
            "column": int(import_fact["column"]),
        }
    else:
        name = str(import_fact.get("name") or "")
        level = int(import_fact.get("level", 0))
        base = _resolve_from_base(source_module, bool(file_record["is_package"]), level, import_fact.get("module"))
        if base is None:
            state = "unresolved_relative"
        elif name == "*":
            state = "wildcard"
        else:
            module_targets = _module_target_list(f"{base}.{name}" if base else name, module_index)
            symbol_targets = _symbol_target_list(base, name, symbol_index) if base else []
            targets = _dedupe_targets([*module_targets, *symbol_targets])
            if len(targets) == 1:
                state = "internal_module" if targets[0]["kind"] == "module" else "internal_symbol"
            elif len(targets) > 1:
                state = "ambiguous"
            elif base and module_index.get(base):
                state = "unresolved_internal"
            else:
                state = "external"
            local_name = str(alias) if alias else name
            binding = {
                "local_name": local_name,
                "pattern": local_name,
                "state": state,
                "targets": targets,
                "line": int(import_fact["line"]),
                "column": int(import_fact["column"]),
            }

    edge = {
        "source_module": source_module,
        "source_path": source_path,
        "kind": kind,
        "requested": requested,
        "binding": None if kind == "from" and import_fact.get("name") == "*" else (str(alias) if alias else (str(import_fact.get("name")) if kind == "from" else str(import_fact.get("module")).split(".", 1)[0])),
        "state": state,
        "targets": _dedupe_targets(targets),
        "line": int(import_fact["line"]),
        "column": int(import_fact["column"]),
        "end_line": int(import_fact["end_line"]),
        "end_column": int(import_fact["end_column"]),
    }
    return edge, binding


def _resolve_module_symbol(
    module_target: Mapping[str, Any],
    suffix: str,
    symbol_index: Mapping[str, Mapping[str, Sequence[Mapping[str, Any]]]],
) -> list[dict[str, Any]]:
    if not suffix or "." in suffix:
        return []
    return _symbol_target_list(str(module_target["module"]), suffix, symbol_index)


def _resolve_call(
    *,
    file_record: Mapping[str, Any],
    call: Mapping[str, Any],
    bindings: Sequence[Mapping[str, Any]],
    wildcard_positions: Sequence[tuple[int, int]],
    symbol_index: Mapping[str, Mapping[str, Sequence[Mapping[str, Any]]]],
) -> dict[str, Any]:
    targets: list[dict[str, Any]] = []
    callee = call.get("callee")
    state = "unresolved"
    reason = "unknown_binding"

    if call.get("dynamic") is True or callee is None:
        reason = "dynamic_callee"
    elif call.get("caller") != "<module>":
        reason = "lexical_shadowing_not_modeled"
    else:
        callee_text = str(callee)
        call_position = (int(call["line"]), int(call["column"]))
        matched_external = False
        matched_internal = False
        matched_ambiguous = False
        if "." not in callee_text:
            targets.extend(
                _symbol_target_list(
                    str(file_record["module"]),
                    callee_text,
                    symbol_index,
                    before=call_position,
                )
            )
        for binding in bindings:
            if (int(binding["line"]), int(binding["column"])) >= call_position:
                continue
            pattern = str(binding["pattern"])
            binding_state = str(binding["state"])
            if callee_text != pattern and not callee_text.startswith(pattern + "."):
                continue
            if binding_state == "external":
                matched_external = True
                continue
            if binding_state in {"internal_module", "internal_symbol", "ambiguous"}:
                matched_internal = True
            if binding_state == "ambiguous":
                matched_ambiguous = True
            for target in binding.get("targets", []):
                if callee_text == pattern:
                    if target["kind"] == "symbol" or binding_state == "ambiguous":
                        targets.append(dict(target))
                elif callee_text.startswith(pattern + ".") and target["kind"] == "module":
                    suffix = callee_text[len(pattern) + 1 :]
                    targets.extend(_resolve_module_symbol(target, suffix, symbol_index))
        targets = _dedupe_targets(targets)
        if matched_external and targets:
            state = "ambiguous"
            reason = "mixed_internal_external_bindings"
        elif len(targets) == 1 and not matched_ambiguous:
            state = "candidate"
            reason = "unique_structural_candidate"
        elif len(targets) > 1 or (targets and matched_ambiguous):
            state = "ambiguous"
            reason = "multiple_internal_targets"
        elif any(position < call_position for position in wildcard_positions) and "." not in callee_text:
            reason = "wildcard_import_scope"
        elif matched_external:
            reason = "external_target"
        elif matched_internal:
            reason = "internal_target_not_found"

    return {
        "source_module": file_record["module"],
        "source_path": file_record["path"],
        "caller": call["caller"],
        "callee": callee,
        "state": state,
        "reason": reason,
        "targets": targets,
        "line": int(call["line"]),
        "column": int(call["column"]),
        "end_line": int(call["end_line"]),
        "end_column": int(call["end_column"]),
    }


def _linkage_identity(document: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "linkage_type": document.get("linkage_type"),
        "input_probe_id": document.get("input_probe_id"),
        "input_probe_root_hash": document.get("input_probe_root_hash"),
        "source_roots": document.get("source_roots"),
        "modules": document.get("modules"),
        "module_collisions": document.get("module_collisions"),
        "imports": document.get("imports"),
        "calls": document.get("calls"),
        "errors": document.get("errors"),
    }


def expected_linkage_root_hash(document: Mapping[str, Any]) -> str:
    return _sha256({key: value for key, value in document.items() if key != "root_hash"})


def _build_linkage_bundle(
    probe: Mapping[str, Any],
    source_roots: Sequence[str],
    *,
    generated_at: str,
) -> dict[str, Any]:
    roots = _validate_source_roots(source_roots)
    files = probe.get("files", [])
    errors: list[dict[str, Any]] = []
    if probe.get("status") == "blocked":
        errors.append({"path": "<probe>", "code": "input_probe_blocked", "message": "input structural probe is blocked"})

    modules: list[dict[str, Any]] = []
    file_by_path: dict[str, dict[str, Any]] = {}
    matched_roots: set[str] = set()
    for item in files:
        path = str(item["path"])
        matches = [(root, _module_from_path(path, root)) for root in roots]
        matches = [(root, module) for root, module in matches if module is not None]
        if not matches:
            under_any = any(_path_under_root(path, root) is not None for root in roots)
            code = "unimportable_module" if under_any else "unmapped_file"
            message = "file path cannot form an importable Python module" if under_any else "file is outside every declared source root"
            errors.append({"path": path, "code": code, "message": message})
            continue
        root, (module, is_package) = matches[0]
        matched_roots.add(root)
        record = {
            "module": module,
            "path": path,
            "source_root": root,
            "is_package": is_package,
            "source_id": item["source"]["id"],
        }
        modules.append(record)
        file_by_path[path] = {**record, "facts": item}

    for root in roots:
        if root not in matched_roots:
            errors.append({"path": root, "code": "empty_source_root", "message": "source root contains no importable probed Python files"})

    modules.sort(key=lambda item: (item["module"], item["path"], item["source_root"]))
    module_index: dict[str, list[dict[str, Any]]] = {}
    for item in modules:
        module_index.setdefault(item["module"], []).append(item)
    collisions = [
        {"module": module, "paths": sorted(item["path"] for item in records)}
        for module, records in sorted(module_index.items())
        if len(records) > 1
    ]

    symbol_index: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for item in modules:
        facts = file_by_path[item["path"]]["facts"]
        for symbol in facts.get("symbols", []):
            qualified_name = str(symbol.get("qualified_name", ""))
            if "." in qualified_name or not qualified_name:
                continue
            symbol_index.setdefault(item["module"], {}).setdefault(qualified_name, []).append(
                {
                    **item,
                    "definition_line": int(symbol["line"]),
                    "definition_column": int(symbol["column"]),
                }
            )

    import_edges: list[dict[str, Any]] = []
    bindings_by_path: dict[str, list[dict[str, Any]]] = {}
    wildcard_positions_by_path: dict[str, list[tuple[int, int]]] = {}
    for path, file_record in sorted(file_by_path.items()):
        bindings: list[dict[str, Any]] = []
        for import_fact in file_record["facts"].get("imports", []):
            edge, binding = _build_import_edge(
                file_record=file_record,
                import_fact=import_fact,
                module_index=module_index,
                symbol_index=symbol_index,
            )
            import_edges.append(edge)
            if edge["state"] == "wildcard":
                wildcard_positions_by_path.setdefault(path, []).append((edge["line"], edge["column"]))
            if binding is not None:
                bindings.append(binding)
        bindings_by_path[path] = bindings

    import_edges.sort(key=lambda item: (item["source_path"], item["line"], item["column"], item["requested"]))
    calls: list[dict[str, Any]] = []
    for path, file_record in sorted(file_by_path.items()):
        for call in file_record["facts"].get("calls", []):
            calls.append(
                _resolve_call(
                    file_record=file_record,
                    call=call,
                    bindings=bindings_by_path[path],
                    wildcard_positions=wildcard_positions_by_path.get(path, []),
                    symbol_index=symbol_index,
                )
            )
    calls.sort(key=lambda item: (item["source_path"], item["line"], item["column"], str(item["callee"])))
    errors.sort(key=lambda item: (item["path"], item["code"], item["message"]))

    summary = {
        "modules": len(modules),
        "module_collisions": len(collisions),
        "imports": len(import_edges),
        "internal_imports": sum(1 for item in import_edges if item["state"] in {"internal_module", "internal_symbol"}),
        "ambiguous_imports": sum(1 for item in import_edges if item["state"] == "ambiguous"),
        "external_imports": sum(1 for item in import_edges if item["state"] == "external"),
        "calls": len(calls),
        "candidate_calls": sum(1 for item in calls if item["state"] == "candidate"),
        "ambiguous_calls": sum(1 for item in calls if item["state"] == "ambiguous"),
        "unresolved_calls": sum(1 for item in calls if item["state"] == "unresolved"),
        "errors": len(errors),
    }
    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "linkage_type": LINKAGE_TYPE,
        "input_probe_id": probe["probe_id"],
        "input_probe_root_hash": probe["root_hash"],
        "source_roots": roots,
        "status": "blocked" if errors else "complete",
        "generated_at": generated_at,
        "summary": summary,
        "modules": modules,
        "module_collisions": collisions,
        "imports": import_edges,
        "calls": calls,
        "errors": errors,
    }
    document["linkage_id"] = _content_id("LNK", _linkage_identity(document))
    document["root_hash"] = expected_linkage_root_hash(document)
    return document


def link_probe_bundle(
    probe: Mapping[str, Any],
    source_roots: Sequence[str],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    try:
        verify_probe_bundle(probe)
    except ProbeError as exc:
        raise LinkerError(f"invalid input structural probe: {exc}") from exc
    timestamp = _normalize_timestamp(generated_at) if generated_at is not None else _utc_now()
    document = _build_linkage_bundle(probe, source_roots, generated_at=timestamp)
    verify_linkage_bundle(document)
    return document


def verify_linkage_bundle(document: Mapping[str, Any], probe: Mapping[str, Any] | None = None) -> None:
    if document.get("schema_version") != SCHEMA_VERSION or document.get("linkage_type") != LINKAGE_TYPE:
        raise LinkerError("unsupported Python linkage bundle")
    modules = document.get("modules")
    collisions = document.get("module_collisions")
    imports = document.get("imports")
    calls = document.get("calls")
    errors = document.get("errors")
    if not all(isinstance(value, list) for value in (modules, collisions, imports, calls, errors)):
        raise LinkerError("linkage modules, collisions, imports, calls, and errors must be arrays")
    if modules != sorted(modules, key=lambda item: (item.get("module"), item.get("path"), item.get("source_root"))):
        raise LinkerError("linkage modules must be deterministically sorted")
    if collisions != sorted(collisions, key=lambda item: item.get("module")):
        raise LinkerError("module collisions must be deterministically sorted")
    if imports != sorted(imports, key=lambda item: (item.get("source_path"), item.get("line"), item.get("column"), item.get("requested"))):
        raise LinkerError("import edges must be deterministically sorted")
    if calls != sorted(calls, key=lambda item: (item.get("source_path"), item.get("line"), item.get("column"), str(item.get("callee")))):
        raise LinkerError("call resolutions must be deterministically sorted")
    if errors != sorted(errors, key=lambda item: (item.get("path"), item.get("code"), item.get("message"))):
        raise LinkerError("linkage errors must be deterministically sorted")

    expected_summary = {
        "modules": len(modules),
        "module_collisions": len(collisions),
        "imports": len(imports),
        "internal_imports": sum(1 for item in imports if item.get("state") in {"internal_module", "internal_symbol"}),
        "ambiguous_imports": sum(1 for item in imports if item.get("state") == "ambiguous"),
        "external_imports": sum(1 for item in imports if item.get("state") == "external"),
        "calls": len(calls),
        "candidate_calls": sum(1 for item in calls if item.get("state") == "candidate"),
        "ambiguous_calls": sum(1 for item in calls if item.get("state") == "ambiguous"),
        "unresolved_calls": sum(1 for item in calls if item.get("state") == "unresolved"),
        "errors": len(errors),
    }
    if document.get("summary") != expected_summary:
        raise LinkerError("linkage summary mismatch")
    if document.get("status") != ("blocked" if errors else "complete"):
        raise LinkerError("linkage status does not match errors")
    if document.get("linkage_id") != _content_id("LNK", _linkage_identity(document)):
        raise LinkerError("linkage id mismatch")
    if document.get("root_hash") != expected_linkage_root_hash(document):
        raise LinkerError("linkage root_hash mismatch")

    if probe is not None:
        try:
            verify_probe_bundle(probe)
        except ProbeError as exc:
            raise LinkerError(f"invalid input structural probe: {exc}") from exc
        regenerated = _build_linkage_bundle(
            probe,
            document.get("source_roots", []),
            generated_at=_normalize_timestamp(str(document.get("generated_at", ""))),
        )
        if _canonical_bytes(regenerated) != _canonical_bytes(document):
            raise LinkerError("linkage bundle does not match the supplied structural probe")


def main() -> int:
    parser = argparse.ArgumentParser(description="Link a verified Python structural probe into a conservative import and call graph.")
    parser.add_argument("--probe", type=Path, required=True, help="Path to a structural-probe JSON bundle.")
    parser.add_argument("--source-root", action="append", required=True, dest="source_roots", help="Import root relative to the probed workspace; repeatable. Use '.' for workspace root.")
    parser.add_argument("--generated-at", help="RFC 3339 timestamp for reproducible linkage bundles.")
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()
    try:
        probe = json.loads(args.probe.read_text(encoding="utf-8"))
        if not isinstance(probe, dict):
            raise LinkerError("probe document must be an object")
        document = link_probe_bundle(probe, args.source_roots, generated_at=args.generated_at)
    except (OSError, json.JSONDecodeError, LinkerError) as exc:
        print(json.dumps({"valid": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(document, sort_keys=True, separators=(",", ":") if args.compact else None, indent=None if args.compact else 2))
    return 2 if document["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
