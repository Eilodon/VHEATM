"""Digest hygiene check/self-heal for the module registry (``vheatm-doctor``).

Scope is intentionally narrow: recompute the two digest chains declared in
``docs/module-system.md`` (registry -> module document, module document ->
instruction file) and, with ``--fix``, rewrite only the mismatched digest
value in place. This never reorders keys, reformats, or touches comments —
each fix is a single literal string replacement of an old 64-char hex digest
for a new one, so it stays safe next to unrelated in-flight edits to the same
YAML files. Structural/schema validation remains the job of ``vheatm-validate``.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class DigestIssue:
    path: str
    field: str
    expected: str
    found: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _replace_digest(raw_text: str, old: str, new: str) -> str:
    return raw_text.replace(old, new, 1)


def check_repository(root: Path, *, fix: bool = False) -> list[DigestIssue]:
    """Recompute registry and instruction digests; optionally rewrite mismatches in place."""
    issues: list[DigestIssue] = []
    registry_path = root / "modules" / "registry.yaml"
    if not registry_path.is_file():
        return [DigestIssue(str(registry_path), "registry", "<file present>", "missing")]

    registry_raw = registry_path.read_text(encoding="utf-8")
    registry = _load_yaml(registry_path) or {}

    for entry in registry.get("modules", []):
        module_rel = entry.get("path")
        recorded = entry.get("sha256")
        if not module_rel or not recorded:
            continue
        module_path = root / module_rel
        if not module_path.is_file():
            issues.append(DigestIssue(module_rel, "sha256", recorded, "missing file"))
            continue

        actual = _sha256(module_path.read_bytes())
        if actual != recorded:
            issues.append(DigestIssue(module_rel, "sha256", actual, recorded))
            if fix:
                registry_raw = _replace_digest(registry_raw, f"sha256: {recorded}", f"sha256: {actual}")

        module_raw = module_path.read_text(encoding="utf-8")
        module_doc = _load_yaml(module_path) or {}
        disclosure = module_doc.get("contract", {}).get("disclosure", {})
        instruction_rel = disclosure.get("instruction_path")
        recorded_instruction = disclosure.get("instruction_sha256")
        if not instruction_rel or not recorded_instruction:
            continue
        instruction_path = module_path.parent / instruction_rel
        if not instruction_path.is_file():
            issues.append(DigestIssue(f"{module_rel}#{instruction_rel}", "instruction_sha256", recorded_instruction, "missing file"))
            continue

        actual_instruction = _sha256(instruction_path.read_bytes())
        if actual_instruction != recorded_instruction:
            issues.append(
                DigestIssue(f"{module_rel}#{instruction_rel}", "instruction_sha256", actual_instruction, recorded_instruction)
            )
            if fix:
                module_raw = _replace_digest(
                    module_raw, f"instruction_sha256: {recorded_instruction}", f"instruction_sha256: {actual_instruction}"
                )
                module_path.write_text(module_raw, encoding="utf-8")

    if fix and registry_raw != registry_path.read_text(encoding="utf-8"):
        registry_path.write_text(registry_raw, encoding="utf-8")

    return issues


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check (and optionally fix) VHEATM module digest hygiene")
    parser.add_argument("--root", default=".", help="Repository root")
    parser.add_argument("--fix", action="store_true", help="Rewrite mismatched digests in place")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    issues = check_repository(root, fix=args.fix)

    if not issues:
        print("vheatm-doctor: all module digests match.")
        return 0

    verb = "fixed" if args.fix else "found"
    for issue in issues:
        print(f"vheatm-doctor: {verb} {issue.field} mismatch in {issue.path} (expected {issue.expected}, was {issue.found})", file=sys.stderr)

    return 0 if args.fix else 1


if __name__ == "__main__":
    raise SystemExit(main())
