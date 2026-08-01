from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

from .provenance import build_source_record, expected_source_id, sha256_digest

SCHEMA_VERSION = "1.0.0"
PROBE_TYPE = "python_ast_v1"
DEFAULT_MAX_FILES = 1_000
DEFAULT_MAX_BYTES_PER_FILE = 2 * 1024 * 1024
DEFAULT_MAX_AST_NODES = 100_000
EXCLUDED_DIRECTORIES = frozenset(
    {".git", ".hg", ".svn", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".venv", "__pycache__", "build", "dist", "node_modules", "venv"}
)


class ProbeError(ValueError):
    """Raised when a probe request violates a structural safety invariant."""


@dataclass(frozen=True)
class ProbeLimits:
    max_files: int = DEFAULT_MAX_FILES
    max_bytes_per_file: int = DEFAULT_MAX_BYTES_PER_FILE
    max_ast_nodes: int = DEFAULT_MAX_AST_NODES

    def __post_init__(self) -> None:
        if self.max_files < 1:
            raise ProbeError("max_files must be at least 1")
        if self.max_bytes_per_file < 1:
            raise ProbeError("max_bytes_per_file must be at least 1")
        if self.max_ast_nodes < 1:
            raise ProbeError("max_ast_nodes must be at least 1")

    def to_document(self) -> dict[str, int]:
        return {
            "max_files": self.max_files,
            "max_bytes_per_file": self.max_bytes_per_file,
            "max_ast_nodes": self.max_ast_nodes,
        }


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _content_id(prefix: str, value: Any) -> str:
    digest = hashlib.sha256(_canonical_bytes(value)).hexdigest().upper()
    return f"{prefix}-{digest}"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _validate_timestamp(value: str) -> str:
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ProbeError("captured_at must be an RFC 3339 date-time") from exc
    if parsed.tzinfo is None:
        raise ProbeError("captured_at must include a timezone")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _normalize_requested_path(value: str) -> str:
    if not value or "\x00" in value:
        raise ProbeError("requested path must be non-empty and contain no NUL")
    if "\\" in value:
        raise ProbeError("requested paths must use POSIX separators")
    if value.startswith("/") or value.startswith("./") or value.endswith("/") or "//" in value:
        raise ProbeError(f"requested path is not normalized: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or value in {".", ".."} or any(part in {"", ".", ".."} for part in path.parts):
        raise ProbeError(f"requested path escapes or is not normalized: {value!r}")
    return path.as_posix()


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _reject_symlink_components(root: Path, candidate: Path) -> None:
    relative = candidate.relative_to(root)
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ProbeError(f"symlink path component is not allowed: {relative.as_posix()}")


def _safe_read_regular_file(root: Path, path: Path, max_bytes: int) -> bytes:
    _reject_symlink_components(root, path)
    resolved = path.resolve(strict=True)
    if not _is_relative_to(resolved, root):
        raise ProbeError(f"file resolves outside workspace: {path.relative_to(root).as_posix()}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ProbeError(f"path is not a regular file: {path.relative_to(root).as_posix()}")
        if info.st_size > max_bytes:
            raise ProbeError(
                f"file exceeds max_bytes_per_file ({info.st_size} > {max_bytes}): "
                f"{path.relative_to(root).as_posix()}"
            )
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > max_bytes:
            raise ProbeError(f"file grew beyond max_bytes_per_file while reading: {path.relative_to(root).as_posix()}")
        return content
    finally:
        os.close(descriptor)


def _discover_python_files(root: Path, requested_paths: Sequence[str], max_files: int) -> tuple[list[Path], list[dict[str, Any]]]:
    files: set[Path] = set()
    errors: list[dict[str, Any]] = []

    def add_file(candidate: Path) -> None:
        relative = candidate.relative_to(root).as_posix()
        if candidate.suffix != ".py":
            errors.append({"path": relative, "code": "unsupported_extension", "message": "only .py files are supported"})
            return
        if candidate.is_symlink():
            errors.append({"path": relative, "code": "symlink_rejected", "message": "symlink files are not read"})
            return
        files.add(candidate)
        if len(files) > max_files:
            raise ProbeError(f"discovered file count exceeds max_files ({len(files)} > {max_files})")

    for relative in requested_paths:
        candidate = root.joinpath(*PurePosixPath(relative).parts)
        try:
            _reject_symlink_components(root, candidate)
        except ProbeError as exc:
            errors.append({"path": relative, "code": "symlink_rejected", "message": str(exc)})
            continue
        if not candidate.exists():
            errors.append({"path": relative, "code": "not_found", "message": "requested path does not exist"})
            continue
        if candidate.is_file():
            add_file(candidate)
            continue
        if not candidate.is_dir():
            errors.append({"path": relative, "code": "unsupported_path", "message": "requested path is not a file or directory"})
            continue
        for directory, directory_names, file_names in os.walk(candidate, topdown=True, followlinks=False):
            directory_path = Path(directory)
            kept: list[str] = []
            for name in sorted(directory_names):
                child = directory_path / name
                child_relative = child.relative_to(root).as_posix()
                if name in EXCLUDED_DIRECTORIES:
                    continue
                if child.is_symlink():
                    errors.append({"path": child_relative, "code": "symlink_rejected", "message": "symlink directories are not traversed"})
                    continue
                kept.append(name)
            directory_names[:] = kept
            for name in sorted(file_names):
                child = directory_path / name
                if child.suffix == ".py" or child.is_symlink():
                    add_file(child)
    return sorted(files, key=lambda item: item.relative_to(root).as_posix()), sorted(
        errors, key=lambda item: (item["path"], item["code"], item["message"])
    )


def _location(node: ast.AST) -> dict[str, int]:
    return {
        "line": int(getattr(node, "lineno", 1)),
        "column": int(getattr(node, "col_offset", 0)),
        "end_line": int(getattr(node, "end_lineno", getattr(node, "lineno", 1))),
        "end_column": int(getattr(node, "end_col_offset", getattr(node, "col_offset", 0))),
    }


def _expression_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _expression_name(node.value)
        return f"{parent}.{node.attr}" if parent else None
    return None


def _expression_text(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    try:
        value = ast.unparse(node)
    except (RecursionError, ValueError):
        return None
    return value if len(value) <= 500 else value[:497] + "..."


def _parameters(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    positional = [*(node.args.posonlyargs or []), *node.args.args]
    default_offset = len(positional) - len(node.args.defaults)
    for index, argument in enumerate(positional):
        result.append(
            {
                "name": argument.arg,
                "kind": "positional_only" if index < len(node.args.posonlyargs) else "positional",
                "annotation": _expression_text(argument.annotation),
                "has_default": index >= default_offset,
            }
        )
    if node.args.vararg is not None:
        result.append({"name": node.args.vararg.arg, "kind": "var_positional", "annotation": _expression_text(node.args.vararg.annotation), "has_default": False})
    for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True):
        result.append({"name": argument.arg, "kind": "keyword_only", "annotation": _expression_text(argument.annotation), "has_default": default is not None})
    if node.args.kwarg is not None:
        result.append({"name": node.args.kwarg.arg, "kind": "var_keyword", "annotation": _expression_text(node.args.kwarg.annotation), "has_default": False})
    return result


class _DeclarationCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.globals: set[str] = set()
        self.nonlocals: set[str] = set()

    def visit_Global(self, node: ast.Global) -> Any:
        self.globals.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> Any:
        self.nonlocals.update(node.names)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        return None

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        return None

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        return None

    def visit_Lambda(self, node: ast.Lambda) -> Any:
        return None


def _scope_declarations(nodes: Sequence[ast.stmt]) -> tuple[list[str], list[str]]:
    collector = _DeclarationCollector()
    for node in nodes:
        collector.visit(node)
    return sorted(collector.globals), sorted(collector.nonlocals)


def _binding_targets(node: ast.AST | None) -> list[tuple[str, ast.AST]]:
    if isinstance(node, ast.Name):
        return [(node.id, node)]
    if isinstance(node, (ast.Tuple, ast.List)):
        result: list[tuple[str, ast.AST]] = []
        for item in node.elts:
            result.extend(_binding_targets(item))
        return result
    if isinstance(node, ast.Starred):
        return _binding_targets(node.value)
    return []


def _pattern_bindings(node: ast.pattern) -> list[tuple[str, ast.AST]]:
    result: list[tuple[str, ast.AST]] = []
    if isinstance(node, ast.MatchAs):
        if node.pattern is not None:
            result.extend(_pattern_bindings(node.pattern))
        if node.name is not None:
            result.append((node.name, node))
    elif isinstance(node, ast.MatchStar):
        if node.name is not None:
            result.append((node.name, node))
    elif isinstance(node, ast.MatchMapping):
        for pattern in node.patterns:
            result.extend(_pattern_bindings(pattern))
        if node.rest is not None:
            result.append((node.rest, node))
    elif isinstance(node, ast.MatchSequence):
        for pattern in node.patterns:
            result.extend(_pattern_bindings(pattern))
    elif isinstance(node, ast.MatchClass):
        for pattern in [*node.patterns, *node.kwd_patterns]:
            result.extend(_pattern_bindings(pattern))
    elif isinstance(node, ast.MatchOr):
        for pattern in node.patterns:
            result.extend(_pattern_bindings(pattern))
    return result


class _FactCollector(ast.NodeVisitor):
    _FUNCTION_LIKE = frozenset({"function", "async_function", "lambda", "comprehension"})

    def __init__(self) -> None:
        self.symbols: list[dict[str, Any]] = []
        self.imports: list[dict[str, Any]] = []
        self.calls: list[dict[str, Any]] = []
        self.bindings: list[dict[str, Any]] = []
        self.scopes: list[dict[str, Any]] = [
            {
                "scope_id": "<module>",
                "kind": "module",
                "qualified_name": "<module>",
                "parent_scope": None,
                "lookup_parent_scope": None,
                "global_names": [],
                "nonlocal_names": [],
                "local_names": [],
                "line": 1,
                "column": 0,
                "end_line": 1,
                "end_column": 0,
            }
        ]
        self._scope_stack: list[dict[str, Any]] = [self.scopes[0]]
        self._scope_counters: dict[str, int] = {}
        self._control_stack: list[str] = []
        self._scope_local_names: dict[str, set[str]] = {"<module>": set()}

    @property
    def _scope(self) -> dict[str, Any]:
        return self._scope_stack[-1]

    def _qualified(self, name: str) -> str:
        parent = str(self._scope["qualified_name"])
        return name if parent == "<module>" else f"{parent}.{name}"

    def _new_scope_id(self, kind: str, qualified_name: str) -> str:
        stem = f"{kind}:{qualified_name}"
        count = self._scope_counters.get(stem, 0) + 1
        self._scope_counters[stem] = count
        return f"{stem}#{count}"

    def _lookup_parent(self, kind: str) -> str | None:
        parent = self._scope
        if kind in self._FUNCTION_LIKE and parent["kind"] == "class":
            return parent["lookup_parent_scope"]
        return str(parent["scope_id"])

    def _enter_scope(
        self,
        *,
        kind: str,
        qualified_name: str,
        node: ast.AST,
        body: Sequence[ast.stmt] = (),
    ) -> None:
        globals_, nonlocals = _scope_declarations(body)
        record = {
            "scope_id": self._new_scope_id(kind, qualified_name),
            "kind": kind,
            "qualified_name": qualified_name,
            "parent_scope": self._scope["scope_id"],
            "lookup_parent_scope": self._lookup_parent(kind),
            "global_names": globals_,
            "nonlocal_names": nonlocals,
            "local_names": [],
            **_location(node),
        }
        self.scopes.append(record)
        self._scope_stack.append(record)
        self._scope_local_names[str(record["scope_id"])] = set()

    def _leave_scope(self) -> None:
        self._scope_stack.pop()

    def finalize(self) -> None:
        for scope in self.scopes:
            scope["local_names"] = sorted(self._scope_local_names[str(scope["scope_id"])])

    def _declaration(self, name: str) -> str:
        if self._scope["kind"] == "module":
            return "local"
        if name in self._scope["global_names"]:
            return "global"
        if name in self._scope["nonlocal_names"]:
            return "nonlocal"
        return "local"

    def _record_binding(
        self,
        name: str,
        kind: str,
        node: ast.AST,
        *,
        value: str | None = None,
        dynamic: bool = False,
        runtime_binding: bool = True,
        target_qualified_name: str | None = None,
    ) -> None:
        declaration = self._declaration(name)
        if declaration == "local":
            self._scope_local_names[str(self._scope["scope_id"])].add(name)
        self.bindings.append(
            {
                "scope_id": self._scope["scope_id"],
                "name": name,
                "kind": kind,
                "declaration": declaration,
                "value": value,
                "dynamic": dynamic,
                "runtime_binding": runtime_binding,
                "target_qualified_name": target_qualified_name,
                "control_context": list(self._control_stack),
                **_location(node),
            }
        )

    def _record_targets(
        self,
        target: ast.AST | None,
        kind: str,
        *,
        value: str | None = None,
        dynamic: bool = True,
        runtime_binding: bool = True,
    ) -> None:
        names = _binding_targets(target)
        single = len(names) == 1
        for name, node in names:
            self._record_binding(
                name,
                kind,
                node,
                value=value if single else None,
                dynamic=dynamic or not single,
                runtime_binding=runtime_binding,
            )

    def _decorators(self, nodes: Iterable[ast.expr]) -> list[str]:
        values: list[str] = []
        for node in nodes:
            target = node.func if isinstance(node, ast.Call) else node
            value = _expression_name(target) or _expression_text(target)
            if value:
                values.append(value)
        return values

    def _visit_parameter_expressions(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> None:
        arguments = node.args
        for default in arguments.defaults:
            self.visit(default)
        for default in arguments.kw_defaults:
            if default is not None:
                self.visit(default)
        for argument in [*(arguments.posonlyargs or []), *arguments.args, *arguments.kwonlyargs]:
            if argument.annotation is not None:
                self.visit(argument.annotation)
        if arguments.vararg is not None and arguments.vararg.annotation is not None:
            self.visit(arguments.vararg.annotation)
        if arguments.kwarg is not None and arguments.kwarg.annotation is not None:
            self.visit(arguments.kwarg.annotation)

    def _record_parameters(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> None:
        arguments = node.args
        all_arguments = [*(arguments.posonlyargs or []), *arguments.args, *arguments.kwonlyargs]
        if arguments.vararg is not None:
            all_arguments.append(arguments.vararg)
        if arguments.kwarg is not None:
            all_arguments.append(arguments.kwarg)
        for argument in all_arguments:
            self._record_binding(argument.arg, "parameter", argument, dynamic=True)

    def visit_Module(self, node: ast.Module) -> Any:
        for statement in node.body:
            self.visit(statement)
        self.finalize()

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        qualified = self._qualified(node.name)
        self.symbols.append(
            {
                "kind": "class",
                "name": node.name,
                "qualified_name": qualified,
                "decorators": self._decorators(node.decorator_list),
                "bases": [value for base in node.bases if (value := _expression_text(base)) is not None],
                **_location(node),
            }
        )
        self._record_binding(node.name, "class", node, dynamic=False, target_qualified_name=qualified)
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword_node in node.keywords:
            self.visit(keyword_node.value)
        self._enter_scope(kind="class", qualified_name=qualified, node=node, body=node.body)
        for statement in node.body:
            self.visit(statement)
        self._leave_scope()

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef, kind: str, scope_kind: str) -> None:
        qualified = self._qualified(node.name)
        self.symbols.append(
            {
                "kind": kind,
                "name": node.name,
                "qualified_name": qualified,
                "decorators": self._decorators(node.decorator_list),
                "parameters": _parameters(node),
                "returns": _expression_text(node.returns),
                **_location(node),
            }
        )
        self._record_binding(node.name, scope_kind, node, dynamic=False, target_qualified_name=qualified)
        for decorator in node.decorator_list:
            self.visit(decorator)
        self._visit_parameter_expressions(node)
        if node.returns is not None:
            self.visit(node.returns)
        self._enter_scope(kind=scope_kind, qualified_name=qualified, node=node, body=node.body)
        self._record_parameters(node)
        for statement in node.body:
            self.visit(statement)
        self._leave_scope()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self._visit_function(node, "method" if self._scope["kind"] == "class" else "function", "function")

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self._visit_function(node, "async_method" if self._scope["kind"] == "class" else "async_function", "async_function")

    def visit_Lambda(self, node: ast.Lambda) -> Any:
        self._visit_parameter_expressions(node)
        qualified = self._qualified("<lambda>")
        self._enter_scope(kind="lambda", qualified_name=qualified, node=node)
        self._record_parameters(node)
        self.visit(node.body)
        self._leave_scope()

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            self.imports.append(
                {
                    "kind": "import",
                    "module": alias.name,
                    "name": None,
                    "alias": alias.asname,
                    "level": 0,
                    "scope_id": self._scope["scope_id"],
                    **_location(node),
                }
            )
            local_name = alias.asname or alias.name.split(".", 1)[0]
            self._record_binding(local_name, "import", node, value=alias.name, dynamic=False)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        for alias in node.names:
            self.imports.append(
                {
                    "kind": "from",
                    "module": node.module,
                    "name": alias.name,
                    "alias": alias.asname,
                    "level": node.level,
                    "scope_id": self._scope["scope_id"],
                    **_location(node),
                }
            )
            if alias.name != "*":
                local_name = alias.asname or alias.name
                requested = f"{'.' * node.level}{node.module or ''}:{alias.name}"
                self._record_binding(local_name, "import", node, value=requested, dynamic=False)

    def visit_Global(self, node: ast.Global) -> Any:
        return None

    def visit_Nonlocal(self, node: ast.Nonlocal) -> Any:
        return None

    def visit_Assign(self, node: ast.Assign) -> Any:
        self.visit(node.value)
        value = _expression_name(node.value)
        for target in node.targets:
            self.visit(target)
            self._record_targets(target, "assignment", value=value, dynamic=value is None)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        self.visit(node.annotation)
        if node.value is not None:
            self.visit(node.value)
        self.visit(node.target)
        self._record_targets(
            node.target,
            "annotated_assignment" if node.value is not None else "annotation",
            value=_expression_name(node.value),
            dynamic=node.value is None or _expression_name(node.value) is None,
            runtime_binding=node.value is not None,
        )

    def visit_AugAssign(self, node: ast.AugAssign) -> Any:
        self.visit(node.target)
        self.visit(node.value)
        self._record_targets(node.target, "augmented_assignment", dynamic=True)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> Any:
        self.visit(node.value)
        self._record_targets(node.target, "named_expression", value=_expression_name(node.value), dynamic=_expression_name(node.value) is None)

    def visit_Delete(self, node: ast.Delete) -> Any:
        for target in node.targets:
            self.visit(target)
            self._record_targets(target, "delete", dynamic=True, runtime_binding=False)

    def _push_control(self, kind: str) -> None:
        self._control_stack.append(kind)

    def _pop_control(self) -> None:
        self._control_stack.pop()

    def visit_If(self, node: ast.If) -> Any:
        self.visit(node.test)
        self._push_control("if")
        for statement in [*node.body, *node.orelse]:
            self.visit(statement)
        self._pop_control()

    def visit_IfExp(self, node: ast.IfExp) -> Any:
        self.visit(node.test)
        self._push_control("expression_branch")
        self.visit(node.body)
        self.visit(node.orelse)
        self._pop_control()

    def visit_BoolOp(self, node: ast.BoolOp) -> Any:
        if not node.values:
            return None
        self.visit(node.values[0])
        self._push_control("short_circuit")
        for value in node.values[1:]:
            self.visit(value)
        self._pop_control()

    def _visit_loop(self, node: ast.For | ast.AsyncFor, kind: str) -> None:
        self.visit(node.iter)
        self._push_control(kind)
        self.visit(node.target)
        self._record_targets(node.target, "for_target", dynamic=True)
        for statement in [*node.body, *node.orelse]:
            self.visit(statement)
        self._pop_control()

    def visit_For(self, node: ast.For) -> Any:
        self._visit_loop(node, "for")

    def visit_AsyncFor(self, node: ast.AsyncFor) -> Any:
        self._visit_loop(node, "async_for")

    def visit_While(self, node: ast.While) -> Any:
        self.visit(node.test)
        self._push_control("while")
        for statement in [*node.body, *node.orelse]:
            self.visit(statement)
        self._pop_control()

    def _visit_with(self, node: ast.With | ast.AsyncWith, kind: str) -> None:
        for item in node.items:
            self.visit(item.context_expr)
        self._push_control(kind)
        for item in node.items:
            if item.optional_vars is not None:
                self.visit(item.optional_vars)
                self._record_targets(item.optional_vars, "with_target", dynamic=True)
        for statement in node.body:
            self.visit(statement)
        self._pop_control()

    def visit_With(self, node: ast.With) -> Any:
        self._visit_with(node, "with")

    def visit_AsyncWith(self, node: ast.AsyncWith) -> Any:
        self._visit_with(node, "async_with")

    def visit_Try(self, node: ast.Try) -> Any:
        self._push_control("try")
        for statement in node.body:
            self.visit(statement)
        for handler in node.handlers:
            self.visit(handler)
        for statement in [*node.orelse, *node.finalbody]:
            self.visit(statement)
        self._pop_control()

    def visit_TryStar(self, node: ast.TryStar) -> Any:
        self.visit_Try(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> Any:
        if node.type is not None:
            self.visit(node.type)
        if node.name is not None:
            self._record_binding(node.name, "except_target", node, dynamic=True)
        for statement in node.body:
            self.visit(statement)

    def visit_Match(self, node: ast.Match) -> Any:
        self.visit(node.subject)
        self._push_control("match")
        for case in node.cases:
            captures = {name: binding_node for name, binding_node in _pattern_bindings(case.pattern)}
            for name, binding_node in captures.items():
                self._record_binding(name, "pattern_capture", binding_node, dynamic=True)
            if case.guard is not None:
                self.visit(case.guard)
            for statement in case.body:
                self.visit(statement)
        self._pop_control()

    def _visit_comprehension_expression(self, node: ast.AST, values: Sequence[ast.AST]) -> None:
        generators = list(getattr(node, "generators"))
        if not generators:
            for value in values:
                self.visit(value)
            return
        self.visit(generators[0].iter)
        qualified = self._qualified(f"<{node.__class__.__name__.lower()}>")
        self._enter_scope(kind="comprehension", qualified_name=qualified, node=node)
        self._push_control("comprehension")
        first = generators[0]
        self.visit(first.target)
        self._record_targets(first.target, "comprehension_target", dynamic=True)
        for condition in first.ifs:
            self.visit(condition)
        for generator in generators[1:]:
            self.visit(generator.iter)
            self.visit(generator.target)
            self._record_targets(generator.target, "comprehension_target", dynamic=True)
            for condition in generator.ifs:
                self.visit(condition)
        for value in values:
            self.visit(value)
        self._pop_control()
        self._leave_scope()

    def visit_ListComp(self, node: ast.ListComp) -> Any:
        self._visit_comprehension_expression(node, [node.elt])

    def visit_SetComp(self, node: ast.SetComp) -> Any:
        self._visit_comprehension_expression(node, [node.elt])

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> Any:
        self._visit_comprehension_expression(node, [node.elt])

    def visit_DictComp(self, node: ast.DictComp) -> Any:
        self._visit_comprehension_expression(node, [node.key, node.value])

    def visit_Call(self, node: ast.Call) -> Any:
        callee = _expression_name(node.func)
        self.calls.append(
            {
                "callee": callee,
                "dynamic": callee is None,
                "caller": self._scope["qualified_name"],
                "scope_id": self._scope["scope_id"],
                "control_context": list(self._control_stack),
                "positional_arguments": len(node.args),
                "keyword_arguments": len(node.keywords),
                "has_star_arguments": any(isinstance(value, ast.Starred) for value in node.args),
                "has_star_keywords": any(value.arg is None for value in node.keywords),
                **_location(node),
            }
        )
        self.generic_visit(node)

def _sort_facts(facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        facts,
        key=lambda item: (
            item.get("line", 0),
            item.get("column", 0),
            str(item.get("scope_id", "")),
            str(item.get("kind", "")),
            str(item.get("qualified_name", item.get("name", item.get("module", item.get("callee", ""))))),
        ),
    )


def _structural_facts(facts: dict[str, list[dict[str, Any]]]) -> dict[str, list[dict[str, Any]]]:
    location_fields = {"line", "column", "end_line", "end_column"}
    return {
        category: [
            {key: value for key, value in item.items() if key not in location_fields}
            for item in items
        ]
        for category, items in facts.items()
    }


def _analyze_file(root: Path, path: Path, *, captured_at: str, limits: ProbeLimits) -> dict[str, Any]:
    relative = path.relative_to(root).as_posix()
    content = _safe_read_regular_file(root, path, limits.max_bytes_per_file)
    try:
        source_text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProbeError(f"source is not valid UTF-8 at byte {exc.start}: {relative}") from exc
    try:
        tree = ast.parse(source_text, filename=relative, type_comments=True, feature_version=(3, 11))
    except SyntaxError as exc:
        location = f"line {exc.lineno}, column {exc.offset}" if exc.lineno is not None else "unknown location"
        raise ProbeError(f"syntax error at {location}: {exc.msg}") from exc
    try:
        node_count = sum(1 for _ in ast.walk(tree))
    except RecursionError as exc:
        raise ProbeError(f"AST traversal exceeded recursion limit: {relative}") from exc
    if node_count > limits.max_ast_nodes:
        raise ProbeError(f"AST node count exceeds max_ast_nodes ({node_count} > {limits.max_ast_nodes}): {relative}")

    collector = _FactCollector()
    try:
        collector.visit(tree)
    except RecursionError as exc:
        raise ProbeError(f"AST visitor exceeded recursion limit: {relative}") from exc
    facts = {
        "scopes": _sort_facts(collector.scopes),
        "symbols": _sort_facts(collector.symbols),
        "imports": _sort_facts(collector.imports),
        "bindings": _sort_facts(collector.bindings),
        "calls": _sort_facts(collector.calls),
    }
    source = build_source_record(
        source_type="test" if relative.startswith("tests/") or "/tests/" in relative else "code",
        locator=f"workspace:{relative}",
        content=content,
        trust_zone="artifact_content",
        taint_state="tainted",
        captured_at=captured_at,
        metadata={"language": "python", "parser": PROBE_TYPE, "relative_path": relative},
    )
    return {
        "path": relative,
        "language": "python",
        "source": source,
        "ast_digest": sha256_digest(_canonical_bytes(_structural_facts(facts))),
        "ast_nodes": node_count,
        **facts,
    }


def probe_workspace(
    root: str | Path,
    requested_paths: Sequence[str],
    *,
    captured_at: str | None = None,
    limits: ProbeLimits | None = None,
) -> dict[str, Any]:
    workspace = Path(root).resolve(strict=True)
    if not workspace.is_dir():
        raise ProbeError("root must be a directory")
    normalized_paths = sorted(set(_normalize_requested_path(value) for value in requested_paths))
    if not normalized_paths:
        raise ProbeError("at least one requested path is required")
    final_limits = limits or ProbeLimits()
    timestamp = _validate_timestamp(captured_at) if captured_at is not None else _utc_now()

    try:
        discovered, errors = _discover_python_files(workspace, normalized_paths, final_limits.max_files)
    except ProbeError as exc:
        discovered = []
        errors = [{"path": "<request>", "code": "limit_exceeded", "message": str(exc)}]

    if not discovered and not errors:
        errors.append({"path": "<request>", "code": "no_python_files", "message": "requested paths contain no Python files"})

    files: list[dict[str, Any]] = []
    for path in discovered:
        relative = path.relative_to(workspace).as_posix()
        try:
            files.append(_analyze_file(workspace, path, captured_at=timestamp, limits=final_limits))
        except ProbeError as exc:
            message = str(exc)
            code = "syntax_error" if message.startswith("syntax error") else "probe_error"
            errors.append({"path": relative, "code": code, "message": message})

    files.sort(key=lambda item: item["path"])
    errors.sort(key=lambda item: (item["path"], item["code"], item["message"]))
    summary = {
        "discovered_files": len(discovered),
        "parsed_files": len(files),
        "scopes": sum(len(item["scopes"]) for item in files),
        "symbols": sum(len(item["symbols"]) for item in files),
        "imports": sum(len(item["imports"]) for item in files),
        "bindings": sum(len(item["bindings"]) for item in files),
        "calls": sum(len(item["calls"]) for item in files),
        "errors": len(errors),
    }
    identity = {
        "probe_type": PROBE_TYPE,
        "workspace": "workspace:",
        "requested_paths": normalized_paths,
        "limits": final_limits.to_document(),
        "files": [
            {
                "path": item["path"],
                "source_id": item["source"]["id"],
                "ast_digest": item["ast_digest"],
            }
            for item in files
        ],
        "errors": errors,
    }
    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "probe_id": _content_id("PRB", identity),
        "probe_type": PROBE_TYPE,
        "workspace": "workspace:",
        "requested_paths": normalized_paths,
        "status": "blocked" if errors else "complete",
        "generated_at": timestamp,
        "limits": final_limits.to_document(),
        "summary": summary,
        "files": files,
        "errors": errors,
    }
    document["root_hash"] = sha256_digest(_canonical_bytes(document))
    verify_probe_bundle(document)
    return document


def _probe_identity(document: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "probe_type": document.get("probe_type"),
        "workspace": document.get("workspace"),
        "requested_paths": document.get("requested_paths"),
        "limits": document.get("limits"),
        "files": [
            {
                "path": item.get("path"),
                "source_id": item.get("source", {}).get("id"),
                "ast_digest": item.get("ast_digest"),
            }
            for item in document.get("files", [])
        ],
        "errors": document.get("errors"),
    }


def expected_probe_root_hash(document: Mapping[str, Any]) -> str:
    subject = {key: value for key, value in document.items() if key != "root_hash"}
    return sha256_digest(_canonical_bytes(subject))


def verify_probe_bundle(document: Mapping[str, Any]) -> None:
    if document.get("schema_version") != SCHEMA_VERSION or document.get("probe_type") != PROBE_TYPE:
        raise ProbeError("unsupported structural probe bundle")
    files = document.get("files")
    errors = document.get("errors")
    if not isinstance(files, list) or not isinstance(errors, list):
        raise ProbeError("probe files and errors must be arrays")
    if [item.get("path") for item in files] != sorted(item.get("path") for item in files):
        raise ProbeError("probe files must be sorted by path")
    if errors != sorted(errors, key=lambda item: (item.get("path"), item.get("code"), item.get("message"))):
        raise ProbeError("probe errors must be deterministically sorted")
    for item in files:
        source = item.get("source")
        if not isinstance(source, Mapping) or source.get("id") != expected_source_id(source):
            raise ProbeError(f"source id mismatch for {item.get('path', '<unknown>')}")
        facts = {category: item.get(category) for category in ("scopes", "symbols", "imports", "bindings", "calls")}
        if item.get("ast_digest") != sha256_digest(_canonical_bytes(_structural_facts(facts))):
            raise ProbeError(f"AST digest mismatch for {item.get('path', '<unknown>')}")
    expected_summary = {
        "discovered_files": len(files) + sum(1 for item in errors if item.get("path") not in {"<request>"} and item.get("code") in {"syntax_error", "probe_error"}),
        "parsed_files": len(files),
        "scopes": sum(len(item.get("scopes", [])) for item in files),
        "symbols": sum(len(item.get("symbols", [])) for item in files),
        "imports": sum(len(item.get("imports", [])) for item in files),
        "bindings": sum(len(item.get("bindings", [])) for item in files),
        "calls": sum(len(item.get("calls", [])) for item in files),
        "errors": len(errors),
    }
    summary = document.get("summary")
    if not isinstance(summary, Mapping):
        raise ProbeError("probe summary must be an object")
    for key in ("discovered_files", "parsed_files", "scopes", "symbols", "imports", "bindings", "calls", "errors"):
        if summary.get(key) != expected_summary[key]:
            raise ProbeError(f"probe summary mismatch for {key}")
    expected_status = "blocked" if errors else "complete"
    if document.get("status") != expected_status:
        raise ProbeError("probe status does not match errors")
    if document.get("probe_id") != _content_id("PRB", _probe_identity(document)):
        raise ProbeError("probe id mismatch")
    if document.get("root_hash") != expected_probe_root_hash(document):
        raise ProbeError("probe root_hash mismatch")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate read-only Python AST evidence without importing target code.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--path", action="append", required=True, dest="paths", help="Normalized workspace-relative file or directory; repeatable.")
    parser.add_argument("--captured-at", help="RFC 3339 timestamp; supply the audit timestamp for reproducible evidence records.")
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    parser.add_argument("--max-bytes-per-file", type=int, default=DEFAULT_MAX_BYTES_PER_FILE)
    parser.add_argument("--max-ast-nodes", type=int, default=DEFAULT_MAX_AST_NODES)
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()
    try:
        document = probe_workspace(
            args.root,
            args.paths,
            captured_at=args.captured_at,
            limits=ProbeLimits(args.max_files, args.max_bytes_per_file, args.max_ast_nodes),
        )
    except (OSError, ProbeError) as exc:
        print(json.dumps({"valid": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(document, sort_keys=True, separators=(",", ":") if args.compact else None, indent=None if args.compact else 2))
    return 2 if document["status"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
