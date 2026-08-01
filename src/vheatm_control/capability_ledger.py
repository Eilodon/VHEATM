from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from .serialization import load_yaml


class CapabilityLedgerError(ValueError):
    """Raised when semantic migration coverage is malformed or unverifiable."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def corpus_digest(root: Path) -> str:
    entries = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            entries.append({"path": path.relative_to(root).as_posix(), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    return hashlib.sha256(_canonical(entries)).hexdigest()


def _has_symlink_tree(root: Path) -> bool:
    return any(path.is_symlink() for path in root.rglob("*"))


def expected_ledger_id(ledger: Mapping[str, Any]) -> str:
    identity = {key: value for key, value in ledger.items() if key != "ledger_id"}
    return "LED-" + hashlib.sha256(_canonical(identity)).hexdigest().upper()


def validate_capability_ledger(root: Path, ledger: Mapping[str, Any], schema: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    for error in sorted(Draft202012Validator(dict(schema)).iter_errors(ledger), key=lambda item: list(item.absolute_path)):
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        errors.append(f"{location}: {error.message}")
    if errors:
        return errors
    if ledger.get("ledger_id") != expected_ledger_id(ledger):
        errors.append("ledger_id does not match canonical ledger content")
    entries = ledger["entries"]
    if [item["capability_id"] for item in entries] != sorted(item["capability_id"] for item in entries):
        errors.append("capability entries must be sorted by capability_id")
    if len({item["source_file"] for item in entries}) != len(entries):
        errors.append("each legacy source file must have exactly one capability entry")
    corpus_root = (root / str(ledger["legacy_root"])).resolve()
    try:
        corpus_root.relative_to(root.resolve())
    except ValueError:
        errors.append("legacy_root escapes repository root")
        return errors
    if not corpus_root.is_dir():
        errors.append(f"legacy corpus is unavailable: {ledger['legacy_root']}")
        return errors
    if _has_symlink_tree(corpus_root):
        errors.append("legacy corpus must not contain symlinked files")
        return errors
    if corpus_digest(corpus_root) != ledger["corpus_digest"]:
        errors.append("legacy corpus digest does not match capability ledger")
    owners = _module_ids(root / "modules" / "registry.yaml")
    for entry in entries:
        source = (root / entry["source_file"]).resolve()
        try:
            source.relative_to(root.resolve())
        except ValueError:
            errors.append(f"source file escapes repository root: {entry['source_file']}")
            continue
        if not source.is_file() or source.is_symlink():
            errors.append(f"source file is unavailable or unsafe: {entry['source_file']}")
            continue
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        if digest != entry["source_digest"]:
            errors.append(f"source digest mismatch: {entry['source_file']}")
        unknown_owners = sorted(set(entry["module_owner"]) - owners)
        if unknown_owners:
            errors.append(f"unknown module owners for {entry['capability_id']}: {unknown_owners}")
        if entry["disposition"] == "missing" and entry["module_owner"]:
            errors.append(f"missing capability cannot have an owner: {entry['capability_id']}")
        if entry["disposition"] in {"corrected", "preserved"} and not entry["module_owner"]:
            errors.append(f"owned capability has no module owner: {entry['capability_id']}")
    return errors


def _module_ids(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    document = load_yaml(path.read_text(encoding="utf-8"))
    return {str(item["id"]) for item in document.get("modules", []) if isinstance(item, Mapping) and "id" in item}
