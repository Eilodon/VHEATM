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
    digest = hashlib.sha256(_canonical_bytes(value)).hexdigest()[:16].upper()
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


class _FactCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.scope: list[str] = []
        self.class_depth = 0
        self.symbols: list[dict[str, Any]] = []
        self.imports: list[dict[str, Any]] = []
        self.calls: list[dict[str, Any]] = []

    def _qualified(self, name: str) -> str:
        return ".".join([*self.scope, name])

    def _decorators(self, nodes: Iterable[ast.expr]) -> list[str]:
        values: list[str] = []
        for node in nodes:
            target = node.func if isinstance(node, ast.Call) else node
            value = _expression_name(target) or _expression_text(target)
            if value:
                values.append(value)
        return values

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.symbols.append(
            {
                "kind": "class",
                "name": node.name,
                "qualified_name": self._qualified(node.name),
                "decorators": self._decorators(node.decorator_list),
                "bases": [value for base in node.bases if (value := _expression_text(base)) is not None],
                **_location(node),
            }
        )
        self.scope.append(node.name)
        self.class_depth += 1
        self.generic_visit(node)
        self.class_depth -= 1
        self.scope.pop()

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef, kind: str) -> None:
        self.symbols.append(
            {
                "kind": kind,
                "name": node.name,
                "qualified_name": self._qualified(node.name),
                "decorators": self._decorators(node.decorator_list),
                "parameters": _parameters(node),
                "returns": _expression_text(node.returns),
                **_location(node),
            }
        )
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self._visit_function(node, "method" if self.class_depth else "function")

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self._visit_function(node, "async_method" if self.class_depth else "async_function")

    def visit_Import(self, node: ast.Import) -> Any:
        for alias in node.names:
            self.imports.append({"kind": "import", "module": alias.name, "name": None, "alias": alias.asname, "level": 0, **_location(node)})

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        for alias in node.names:
            self.imports.append({"kind": "from", "module": node.module, "name": alias.name, "alias": alias.asname, "level": node.level, **_location(node)})

    def visit_Call(self, node: ast.Call) -> Any:
        callee = _expression_name(node.func)
        self.calls.append(
            {
                "callee": callee,
                "dynamic": callee is None,
                "caller": ".".join(self.scope) if self.scope else "<module>",
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
            str(item.get("kind", "")),
            str(item.get("qualified_name", item.get("module", item.get("callee", "")))),
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
        "symbols": _sort_facts(collector.symbols),
        "imports": _sort_facts(collector.imports),
        "calls": _sort_facts(collector.calls),
    }
    source = build_source_record(
        source_type="test" if relative.startswith("tests/") or "/tests/" in relative else "code",
        locator=f"workspace:{relative}",
        content=content,
        trust_zone="artifact_content",
        taint_state="validated",
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
        "symbols": sum(len(item["symbols"]) for item in files),
        "imports": sum(len(item["imports"]) for item in files),
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
        facts = {category: item.get(category) for category in ("symbols", "imports", "calls")}
        if item.get("ast_digest") != sha256_digest(_canonical_bytes(_structural_facts(facts))):
            raise ProbeError(f"AST digest mismatch for {item.get('path', '<unknown>')}")
    expected_summary = {
        "discovered_files": len(files) + sum(1 for item in errors if item.get("path") not in {"<request>"} and item.get("code") in {"syntax_error", "probe_error"}),
        "parsed_files": len(files),
        "symbols": sum(len(item.get("symbols", [])) for item in files),
        "imports": sum(len(item.get("imports", [])) for item in files),
        "calls": sum(len(item.get("calls", [])) for item in files),
        "errors": len(errors),
    }
    summary = document.get("summary")
    if not isinstance(summary, Mapping):
        raise ProbeError("probe summary must be an object")
    for key in ("discovered_files", "parsed_files", "symbols", "imports", "calls", "errors"):
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
