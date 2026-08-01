from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from .serialization import load_json


class BundleError(ValueError):
    """Raised when the canonical control bundle is incomplete or altered."""


_EXACT_PATHS = (
    "SKILL.md",
    "Makefile",
    "pyproject.toml",
    "setup.py",
    "MANIFEST.in",
    "manifests/vheatm-v17.yaml",
    "policies/runtime-boundaries.yaml",
    "policies/capability-ledger.yaml",
    "policies/standards-baseline.yaml",
    "policies/semantic-profiles.yaml",
    "uv.lock",
    "modules/registry.yaml",
)
_GLOB_PATHS = (
    "modules/*/module.yaml",
    "modules/*/instructions.md",
    "schemas/*.schema.json",
    "src/vheatm_control/*.py",
    "docs/VHEATM-bản gốc tham khảo/vheatm-ultimate/**/*",
    "evals/*.yaml",
)


def resolve_control_root(root: Path | None = None) -> Path:
    """Resolve a checkout root, falling back to bundled offline assets."""

    if root is not None:
        return root.resolve()
    checkout = Path.cwd().resolve()
    if (checkout / "manifests" / "vheatm-v17.yaml").is_file():
        return checkout
    packaged = Path(__file__).resolve().parent / "assets"
    if (packaged / "manifests" / "vheatm-v17.yaml").is_file():
        return packaged
    return checkout


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _relative_path(path: Path, root: Path) -> str:
    try:
        relative = path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise BundleError(f"bundle path escapes root: {path}") from exc
    value = PurePosixPath(relative.as_posix())
    if value.is_absolute() or ".." in value.parts or not value.parts:
        raise BundleError(f"unsafe bundle path: {path}")
    return value.as_posix()


def _canonical_paths(root: Path) -> list[tuple[str, Path]]:
    root = root.resolve()
    candidates: dict[str, Path] = {}
    for relative in _EXACT_PATHS:
        candidates[relative] = root / relative
    for pattern in _GLOB_PATHS:
        for path in root.glob(pattern):
            if not path.is_file():
                continue
            relative = _relative_path(path, root)
            candidates[relative] = path
    if not candidates:
        raise BundleError("control bundle has no canonical files")
    result: list[tuple[str, Path]] = []
    for relative in sorted(candidates):
        path = candidates[relative]
        if path.is_symlink():
            raise BundleError(f"canonical bundle file must not be a symlink: {relative}")
        if not path.is_file():
            raise BundleError(f"missing canonical bundle file: {relative}")
        result.append((relative, path))
    return result


def bundle_entries(root: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for relative, path in _canonical_paths(root):
        payload = path.read_bytes()
        entries.append({"path": relative, "sha256": _sha256(payload), "size": len(payload)})
    return entries


def canonical_bundle_root(entries: Sequence[Mapping[str, Any]]) -> str:
    normalized = [
        {"path": str(entry.get("path", "")), "sha256": str(entry.get("sha256", "")), "size": int(entry.get("size", -1))}
        for entry in entries
    ]
    normalized.sort(key=lambda entry: entry["path"])
    return _sha256(_canonical_bytes(normalized))


def build_bundle(root: Path) -> dict[str, Any]:
    entries = bundle_entries(root)
    return {"schema_version": "1.0.0", "bundle_root": canonical_bundle_root(entries), "entries": entries}


def validate_bundle(root: Path, bundle: Mapping[str, Any]) -> list[str]:
    if bundle.get("schema_version") != "1.0.0":
        raise BundleError("unsupported control bundle schema_version")
    expected_entries = bundle_entries(root)
    supplied_entries = bundle.get("entries")
    if supplied_entries != expected_entries:
        raise BundleError("bundle inventory does not match canonical bundle")
    expected_root = canonical_bundle_root(expected_entries)
    if bundle.get("bundle_root") != expected_root:
        raise BundleError("bundle root does not match canonical bundle")
    return []


def _load_document(path: Path) -> dict[str, Any]:
    value = load_json(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise BundleError(f"{path} must contain an object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the deterministic VHEATM control-bundle inventory.")
    parser.add_argument("--root", type=Path)
    parser.add_argument("--bundle", type=Path, help="Existing bundle inventory to validate")
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()
    root = resolve_control_root(args.root)
    try:
        bundle = build_bundle(root)
        if args.bundle is not None:
            validate_bundle(root, _load_document(args.bundle))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(bundle, indent=None if args.compact else 2, sort_keys=args.compact))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
