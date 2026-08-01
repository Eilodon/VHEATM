from __future__ import annotations

import argparse
import hashlib
import json
import keyword
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from .structural_probe import ProbeError, verify_probe_bundle
from .serialization import load_json

SCHEMA_VERSION = "1.0.0"
LINKAGE_TYPE = "python_import_graph_v1"


class LinkerError(ValueError):
    """Raised when a structural linkage request or bundle is invalid."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _content_id(prefix: str, value: Any) -> str:
    return f"{prefix}-{_sha256(value).upper()}"


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
            "scope_id": str(import_fact.get("scope_id", "<module>")),
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
                "scope_id": str(import_fact.get("scope_id", "<module>")),
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
        "source_scope": str(import_fact.get("scope_id", "<module>")),
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


def _position(item: Mapping[str, Any]) -> tuple[int, int]:
    return int(item.get("line", 0)), int(item.get("column", 0))


def _binding_reference(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "scope_id": item["scope_id"],
        "name": item["name"],
        "kind": item["kind"],
        "declaration": item["declaration"],
        "line": int(item["line"]),
        "column": int(item["column"]),
    }


def _resolution(
    state: str,
    reason: str,
    *,
    targets: Sequence[Mapping[str, Any]] = (),
    chain: Sequence[Mapping[str, Any]] = (),
    event: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "state": state,
        "reason": reason,
        "targets": _dedupe_targets(targets),
        "binding_chain": [dict(item) for item in chain],
        "event": event,
    }


def _scope_parent(scope: Mapping[str, Any]) -> str | None:
    value = scope.get("lookup_parent_scope")
    return str(value) if value is not None else None


def _events_before(
    events: Sequence[Mapping[str, Any]],
    position: tuple[int, int],
) -> list[Mapping[str, Any]]:
    return [item for item in events if _position(item) < position]


def _find_nonlocal_scope(
    scope_id: str,
    name: str,
    scope_index: Mapping[str, Mapping[str, Any]],
) -> str | None:
    current = scope_index.get(scope_id)
    parent_id = _scope_parent(current or {})
    while parent_id is not None:
        parent = scope_index.get(parent_id)
        if parent is None:
            return None
        if parent.get("kind") in {"function", "async_function", "lambda", "comprehension"} and name in parent.get("local_names", []):
            return parent_id
        parent_id = _scope_parent(parent)
    return None


def _resolve_binding_event(
    event: Mapping[str, Any],
    *,
    context: Mapping[str, Any],
    visited: frozenset[tuple[str, str, int, int]],
) -> dict[str, Any]:
    chain = [_binding_reference(event)]
    key = (str(event["scope_id"]), str(event["name"]), int(event["line"]), int(event["column"]))
    if key in visited:
        return _resolution("unresolved", "alias_cycle", chain=chain, event=event)
    visited = visited | {key}
    control_context = event.get("control_context", [])
    kind = str(event["kind"])
    if control_context:
        targets = list(event.get("targets", []))
        if not targets and kind in {"assignment", "annotated_assignment", "named_expression"}:
            value = event.get("value")
            if isinstance(value, str) and value and event.get("dynamic") is not True:
                partial = _resolve_callee_text(
                    value,
                    scope_id=str(event["scope_id"]),
                    position=_position(event),
                    context=context,
                    visited=visited,
                    enclosing=False,
                    alias_mode=True,
                )
                targets = partial["targets"]
                chain.extend(partial["binding_chain"])
        return _resolution("ambiguous", "control_dependent_rebinding", targets=targets, chain=chain, event=event)

    if kind == "import":
        import_state = str(event.get("import_state", "unresolved_internal"))
        targets = event.get("targets", [])
        if import_state in {"internal_module", "internal_symbol"} and len(targets) == 1:
            return _resolution("candidate", "unique_lexical_binding", targets=targets, chain=chain, event=event)
        if import_state == "ambiguous" or len(targets) > 1:
            return _resolution("ambiguous", "multiple_internal_targets", targets=targets, chain=chain, event=event)
        if import_state == "external":
            return _resolution("unresolved", "external_target", chain=chain, event=event)
        return _resolution("unresolved", "internal_target_not_found", targets=targets, chain=chain, event=event)

    if kind in {"function", "async_function", "class"}:
        targets = event.get("targets", [])
        if len(targets) == 1:
            return _resolution("candidate", "unique_lexical_binding", targets=targets, chain=chain, event=event)
        if len(targets) > 1:
            return _resolution("ambiguous", "multiple_internal_targets", targets=targets, chain=chain, event=event)
        return _resolution("unresolved", "internal_target_not_found", chain=chain, event=event)

    if kind == "parameter":
        return _resolution("unresolved", "parameter_binding", chain=chain, event=event)
    if kind == "delete":
        return _resolution("unresolved", "deleted_binding", chain=chain, event=event)
    if kind == "annotation" or event.get("runtime_binding") is False:
        return _resolution("unresolved", "annotation_only_binding", chain=chain, event=event)
    if kind in {"augmented_assignment", "for_target", "with_target", "except_target", "pattern_capture", "comprehension_target"}:
        return _resolution("unresolved", "dynamic_rebinding", chain=chain, event=event)

    value = event.get("value")
    if event.get("dynamic") is True or not isinstance(value, str) or not value:
        return _resolution("unresolved", "dynamic_rebinding", chain=chain, event=event)
    resolved = _resolve_callee_text(
        value,
        scope_id=str(event["scope_id"]),
        position=_position(event),
        context=context,
        visited=visited,
        enclosing=False,
        alias_mode=True,
    )
    return _resolution(
        resolved["state"],
        "unique_alias_binding" if resolved["state"] == "candidate" else resolved["reason"],
        targets=resolved["targets"],
        chain=[*chain, *resolved["binding_chain"]],
        event=event,
    )


def _resolve_name(
    name: str,
    *,
    scope_id: str,
    position: tuple[int, int],
    context: Mapping[str, Any],
    visited: frozenset[tuple[str, str, int, int]],
    enclosing: bool,
) -> dict[str, Any]:
    scope_index: Mapping[str, Mapping[str, Any]] = context["scope_index"]
    events_index: Mapping[tuple[str, str], Sequence[Mapping[str, Any]]] = context["events_index"]
    wildcard_index: Mapping[str, Sequence[tuple[int, int]]] = context["wildcard_index"]
    scope = scope_index.get(scope_id)
    if scope is None:
        return _resolution("unresolved", "unknown_scope")

    events = list(events_index.get((scope_id, name), []))
    globals_ = set(scope.get("global_names", []))
    nonlocals = set(scope.get("nonlocal_names", []))
    local_names = set(scope.get("local_names", []))
    kind = str(scope.get("kind"))

    if name in globals_ or name in nonlocals:
        visible = _events_before(events, position)
        if visible:
            return _resolve_binding_event(visible[-1], context=context, visited=visited)
        if name in globals_:
            target_scope = "<module>"
        else:
            target_scope = _find_nonlocal_scope(scope_id, name, scope_index)
            if target_scope is None:
                return _resolution("unresolved", "nonlocal_binding_not_found")
        return _resolve_name(
            name,
            scope_id=target_scope,
            position=position,
            context=context,
            visited=visited,
            enclosing=True,
        )

    if enclosing:
        if events:
            if len(events) != 1:
                partials = [_resolve_binding_event(item, context=context, visited=visited) for item in events]
                return _resolution(
                    "ambiguous",
                    "enclosing_rebinding_not_proven",
                    targets=[target for partial in partials for target in partial["targets"]],
                    chain=[reference for partial in partials for reference in partial["binding_chain"]],
                )
            return _resolve_binding_event(events[0], context=context, visited=visited)
        if name in local_names:
            return _resolution("unresolved", "local_before_binding")
    else:
        visible = _events_before(events, position)
        if visible:
            return _resolve_binding_event(visible[-1], context=context, visited=visited)
        if kind in {"function", "async_function", "lambda", "comprehension"} and name in local_names:
            future = [item for item in events if _position(item) >= position]
            return _resolution(
                "unresolved",
                "local_before_binding",
                chain=[_binding_reference(future[0])] if future else [],
            )
        if kind == "class" and name in local_names:
            pass
        elif kind == "module" and name in local_names:
            future = [item for item in events if _position(item) >= position]
            return _resolution(
                "unresolved",
                "local_before_binding",
                chain=[_binding_reference(future[0])] if future else [],
            )

    if any(item < position for item in wildcard_index.get(scope_id, [])):
        return _resolution("unresolved", "wildcard_import_scope")
    parent_id = _scope_parent(scope)
    if parent_id is None:
        return _resolution("unresolved", "unknown_binding")
    return _resolve_name(
        name,
        scope_id=parent_id,
        position=position,
        context=context,
        visited=visited,
        enclosing=True,
    )


def _apply_callee_suffix(
    callee_text: str,
    root_result: Mapping[str, Any],
    *,
    context: Mapping[str, Any],
    alias_mode: bool,
) -> dict[str, Any]:
    targets = list(root_result.get("targets", []))
    event = root_result.get("event")
    root = callee_text.split(".", 1)[0]
    suffix = callee_text[len(root) + 1 :] if "." in callee_text else ""

    if event is not None and event.get("kind") == "import":
        pattern = str(event.get("pattern") or root)
        if callee_text == pattern:
            suffix = ""
        elif callee_text.startswith(pattern + "."):
            suffix = callee_text[len(pattern) + 1 :]
        elif pattern != root:
            return _resolution("unresolved", "import_pattern_mismatch", chain=root_result.get("binding_chain", []))

    if not suffix:
        callable_targets = [item for item in targets if item.get("kind") == "symbol"]
        if len(callable_targets) == 1 and root_result.get("state") == "candidate":
            return _resolution(
                "candidate",
                str(root_result.get("reason")),
                targets=callable_targets,
                chain=root_result.get("binding_chain", []),
                event=event,
            )
        if len(callable_targets) > 1 or root_result.get("state") == "ambiguous":
            return _resolution(
                "ambiguous",
                str(root_result.get("reason")),
                targets=callable_targets or targets,
                chain=root_result.get("binding_chain", []),
                event=event,
            )
        if alias_mode and len(targets) == 1 and targets[0].get("kind") == "module":
            return _resolution(
                "candidate",
                str(root_result.get("reason")),
                targets=targets,
                chain=root_result.get("binding_chain", []),
                event=event,
            )
        if root_result.get("state") != "candidate":
            return dict(root_result)
        return _resolution("unresolved", "module_not_callable", chain=root_result.get("binding_chain", []), event=event)

    module_targets = [item for item in targets if item.get("kind") == "module"]
    resolved: list[dict[str, Any]] = []
    for target in module_targets:
        resolved.extend(_resolve_module_symbol(target, suffix, context["symbol_index"]))
    resolved = _dedupe_targets(resolved)
    if len(resolved) == 1 and root_result.get("state") == "candidate":
        return _resolution(
            "candidate",
            str(root_result.get("reason")),
            targets=resolved,
            chain=root_result.get("binding_chain", []),
            event=event,
        )
    if len(resolved) > 1 or root_result.get("state") == "ambiguous":
        return _resolution(
            "ambiguous",
            "multiple_internal_targets",
            targets=resolved or targets,
            chain=root_result.get("binding_chain", []),
            event=event,
        )
    if root_result.get("state") != "candidate":
        return dict(root_result)
    return _resolution("unresolved", "attribute_target_not_modeled", chain=root_result.get("binding_chain", []), event=event)


def _resolve_callee_text(
    callee_text: str,
    *,
    scope_id: str,
    position: tuple[int, int],
    context: Mapping[str, Any],
    visited: frozenset[tuple[str, str, int, int]],
    enclosing: bool,
    alias_mode: bool = False,
) -> dict[str, Any]:
    root = callee_text.split(".", 1)[0]
    root_result = _resolve_name(
        root,
        scope_id=scope_id,
        position=position,
        context=context,
        visited=visited,
        enclosing=enclosing,
    )
    return _apply_callee_suffix(callee_text, root_result, context=context, alias_mode=alias_mode)


def _resolve_call(
    *,
    file_record: Mapping[str, Any],
    call: Mapping[str, Any],
    context: Mapping[str, Any],
) -> dict[str, Any]:
    callee = call.get("callee")
    if call.get("dynamic") is True or callee is None:
        resolved = _resolution("unresolved", "dynamic_callee")
    else:
        resolved = _resolve_callee_text(
            str(callee),
            scope_id=str(call.get("scope_id", "<module>")),
            position=_position(call),
            context=context,
            visited=frozenset(),
            enclosing=False,
        )
    return {
        "source_module": file_record["module"],
        "source_path": file_record["path"],
        "scope_id": str(call.get("scope_id", "<module>")),
        "caller": call["caller"],
        "callee": callee,
        "control_context": list(call.get("control_context", [])),
        "state": resolved["state"],
        "reason": resolved["reason"],
        "targets": resolved["targets"],
        "binding_chain": resolved["binding_chain"],
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
        "scopes": document.get("scopes"),
        "imports": document.get("imports"),
        "bindings": document.get("bindings"),
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
    qualified_targets_by_path: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for item in modules:
        facts = file_by_path[item["path"]]["facts"]
        for symbol in facts.get("symbols", []):
            qualified_name = str(symbol.get("qualified_name", ""))
            if not qualified_name:
                continue
            record = {
                **item,
                "definition_line": int(symbol["line"]),
                "definition_column": int(symbol["column"]),
            }
            qualified_targets_by_path.setdefault(item["path"], {}).setdefault(qualified_name, []).append(
                _target(kind="symbol", module=item["module"], symbol=qualified_name, file_record=record)
            )
            if "." not in qualified_name:
                symbol_index.setdefault(item["module"], {}).setdefault(qualified_name, []).append(record)

    scopes: list[dict[str, Any]] = []
    scope_index_by_path: dict[str, dict[str, dict[str, Any]]] = {}
    for path, file_record in sorted(file_by_path.items()):
        scope_index: dict[str, dict[str, Any]] = {}
        for scope in file_record["facts"].get("scopes", []):
            normalized = {
                "source_module": file_record["module"],
                "source_path": path,
                "scope_id": str(scope["scope_id"]),
                "kind": str(scope["kind"]),
                "qualified_name": str(scope["qualified_name"]),
                "parent_scope": scope.get("parent_scope"),
                "lookup_parent_scope": scope.get("lookup_parent_scope"),
                "global_names": list(scope.get("global_names", [])),
                "nonlocal_names": list(scope.get("nonlocal_names", [])),
                "local_names": list(scope.get("local_names", [])),
                "line": int(scope["line"]),
                "column": int(scope["column"]),
                "end_line": int(scope["end_line"]),
                "end_column": int(scope["end_column"]),
            }
            scopes.append(normalized)
            scope_index[normalized["scope_id"]] = normalized
        scope_index_by_path[path] = scope_index

    import_edges: list[dict[str, Any]] = []
    import_binding_by_path: dict[str, dict[tuple[str, int, int, str], dict[str, Any]]] = {}
    wildcard_index_by_path: dict[str, dict[str, list[tuple[int, int]]]] = {}
    for path, file_record in sorted(file_by_path.items()):
        binding_index: dict[tuple[str, int, int, str], dict[str, Any]] = {}
        wildcard_index: dict[str, list[tuple[int, int]]] = {}
        for import_fact in file_record["facts"].get("imports", []):
            edge, binding = _build_import_edge(
                file_record=file_record,
                import_fact=import_fact,
                module_index=module_index,
                symbol_index=symbol_index,
            )
            import_edges.append(edge)
            if edge["state"] == "wildcard":
                wildcard_index.setdefault(edge["source_scope"], []).append((edge["line"], edge["column"]))
            if binding is not None:
                key = (str(binding["scope_id"]), int(binding["line"]), int(binding["column"]), str(binding["local_name"]))
                binding_index[key] = binding
        import_binding_by_path[path] = binding_index
        wildcard_index_by_path[path] = wildcard_index

    import_edges.sort(key=lambda item: (item["source_path"], item["line"], item["column"], item["requested"]))

    base_events_by_path: dict[str, list[dict[str, Any]]] = {}
    context_by_path: dict[str, dict[str, Any]] = {}
    for path, file_record in sorted(file_by_path.items()):
        events: list[dict[str, Any]] = []
        import_bindings = import_binding_by_path[path]
        for raw in file_record["facts"].get("bindings", []):
            event = {
                "source_module": file_record["module"],
                "source_path": path,
                "scope_id": str(raw["scope_id"]),
                "name": str(raw["name"]),
                "kind": str(raw["kind"]),
                "declaration": str(raw["declaration"]),
                "value": raw.get("value"),
                "dynamic": bool(raw.get("dynamic", False)),
                "runtime_binding": bool(raw.get("runtime_binding", True)),
                "target_qualified_name": raw.get("target_qualified_name"),
                "control_context": list(raw.get("control_context", [])),
                "pattern": None,
                "import_state": None,
                "targets": [],
                "line": int(raw["line"]),
                "column": int(raw["column"]),
                "end_line": int(raw["end_line"]),
                "end_column": int(raw["end_column"]),
            }
            if event["kind"] == "import":
                import_binding = import_bindings.get((event["scope_id"], event["line"], event["column"], event["name"]))
                if import_binding is not None:
                    event["pattern"] = import_binding["pattern"]
                    event["import_state"] = import_binding["state"]
                    event["targets"] = _dedupe_targets(import_binding.get("targets", []))
            elif event["kind"] in {"function", "async_function", "class"}:
                qualified_name = event.get("target_qualified_name")
                if isinstance(qualified_name, str):
                    event["targets"] = _dedupe_targets(qualified_targets_by_path.get(path, {}).get(qualified_name, []))
            events.append(event)
        events.sort(key=lambda item: (item["scope_id"], item["name"], item["line"], item["column"], item["kind"]))
        events_index: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for event in events:
            events_index.setdefault((event["scope_id"], event["name"]), []).append(event)
        base_events_by_path[path] = events
        context_by_path[path] = {
            "scope_index": scope_index_by_path[path],
            "events_index": events_index,
            "wildcard_index": wildcard_index_by_path[path],
            "symbol_index": symbol_index,
        }

    bindings: list[dict[str, Any]] = []
    for path, events in sorted(base_events_by_path.items()):
        context = context_by_path[path]
        for event in events:
            resolved = _resolve_binding_event(event, context=context, visited=frozenset())
            bindings.append(
                {
                    **{key: value for key, value in event.items() if key not in {"import_state"}},
                    "state": resolved["state"],
                    "reason": resolved["reason"],
                    "targets": resolved["targets"],
                    "binding_chain": resolved["binding_chain"],
                }
            )
    bindings.sort(key=lambda item: (item["source_path"], item["scope_id"], item["name"], item["line"], item["column"], item["kind"]))

    calls: list[dict[str, Any]] = []
    for path, file_record in sorted(file_by_path.items()):
        context = context_by_path[path]
        for call in file_record["facts"].get("calls", []):
            calls.append(_resolve_call(file_record=file_record, call=call, context=context))
    calls.sort(key=lambda item: (item["source_path"], item["line"], item["column"], str(item["callee"])))
    scopes.sort(key=lambda item: (item["source_path"], item["line"], item["column"], item["scope_id"]))
    errors.sort(key=lambda item: (item["path"], item["code"], item["message"]))

    rebinding_groups: dict[tuple[str, str, str], int] = {}
    for item in bindings:
        key = (item["source_path"], item["scope_id"], item["name"])
        rebinding_groups[key] = rebinding_groups.get(key, 0) + 1
    summary = {
        "modules": len(modules),
        "module_collisions": len(collisions),
        "scopes": len(scopes),
        "imports": len(import_edges),
        "internal_imports": sum(1 for item in import_edges if item["state"] in {"internal_module", "internal_symbol"}),
        "ambiguous_imports": sum(1 for item in import_edges if item["state"] == "ambiguous"),
        "external_imports": sum(1 for item in import_edges if item["state"] == "external"),
        "bindings": len(bindings),
        "candidate_bindings": sum(1 for item in bindings if item["state"] == "candidate"),
        "ambiguous_bindings": sum(1 for item in bindings if item["state"] == "ambiguous"),
        "unresolved_bindings": sum(1 for item in bindings if item["state"] == "unresolved"),
        "rebound_names": sum(1 for count in rebinding_groups.values() if count > 1),
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
        "scopes": scopes,
        "imports": import_edges,
        "bindings": bindings,
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
    scopes = document.get("scopes")
    imports = document.get("imports")
    bindings = document.get("bindings")
    calls = document.get("calls")
    errors = document.get("errors")
    if not all(isinstance(value, list) for value in (modules, collisions, scopes, imports, bindings, calls, errors)):
        raise LinkerError("linkage modules, collisions, scopes, imports, bindings, calls, and errors must be arrays")
    if modules != sorted(modules, key=lambda item: (item.get("module"), item.get("path"), item.get("source_root"))):
        raise LinkerError("linkage modules must be deterministically sorted")
    if collisions != sorted(collisions, key=lambda item: item.get("module")):
        raise LinkerError("module collisions must be deterministically sorted")
    if scopes != sorted(scopes, key=lambda item: (item.get("source_path"), item.get("line"), item.get("column"), item.get("scope_id"))):
        raise LinkerError("linkage scopes must be deterministically sorted")
    if imports != sorted(imports, key=lambda item: (item.get("source_path"), item.get("line"), item.get("column"), item.get("requested"))):
        raise LinkerError("import edges must be deterministically sorted")
    if bindings != sorted(bindings, key=lambda item: (item.get("source_path"), item.get("scope_id"), item.get("name"), item.get("line"), item.get("column"), item.get("kind"))):
        raise LinkerError("binding records must be deterministically sorted")
    if calls != sorted(calls, key=lambda item: (item.get("source_path"), item.get("line"), item.get("column"), str(item.get("callee")))):
        raise LinkerError("call resolutions must be deterministically sorted")
    if errors != sorted(errors, key=lambda item: (item.get("path"), item.get("code"), item.get("message"))):
        raise LinkerError("linkage errors must be deterministically sorted")

    rebinding_groups: dict[tuple[Any, Any, Any], int] = {}
    for item in bindings:
        key = (item.get("source_path"), item.get("scope_id"), item.get("name"))
        rebinding_groups[key] = rebinding_groups.get(key, 0) + 1
    expected_summary = {
        "modules": len(modules),
        "module_collisions": len(collisions),
        "scopes": len(scopes),
        "imports": len(imports),
        "internal_imports": sum(1 for item in imports if item.get("state") in {"internal_module", "internal_symbol"}),
        "ambiguous_imports": sum(1 for item in imports if item.get("state") == "ambiguous"),
        "external_imports": sum(1 for item in imports if item.get("state") == "external"),
        "bindings": len(bindings),
        "candidate_bindings": sum(1 for item in bindings if item.get("state") == "candidate"),
        "ambiguous_bindings": sum(1 for item in bindings if item.get("state") == "ambiguous"),
        "unresolved_bindings": sum(1 for item in bindings if item.get("state") == "unresolved"),
        "rebound_names": sum(1 for count in rebinding_groups.values() if count > 1),
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
        probe = load_json(args.probe.read_text(encoding="utf-8"))
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
