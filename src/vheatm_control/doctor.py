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

from .bundle import resolve_control_root


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


def _replace_digest(raw_text: str, field: str, old: str, new: str) -> str:
    """Replace one digest value while preserving its YAML quoting style."""
    candidates = (
        (f'{field}: "{old}"', f'{field}: "{new}"'),
        (f"{field}: '{old}'", f"{field}: '{new}'"),
        (f"{field}: {old}", f"{field}: {new}"),
    )
    for rendered_old, rendered_new in candidates:
        if rendered_old in raw_text:
            return raw_text.replace(rendered_old, rendered_new, 1)
    return raw_text


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

        module_raw = module_path.read_text(encoding="utf-8")
        original_module_raw = module_raw
        actual = _sha256(module_raw.encode("utf-8"))
        if actual != recorded:
            issues.append(DigestIssue(module_rel, "sha256", actual, recorded))

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
                    module_raw, "instruction_sha256", recorded_instruction, actual_instruction
                )

        if fix and module_raw != original_module_raw:
            module_path.write_text(module_raw, encoding="utf-8")

        final_module_digest = _sha256(module_raw.encode("utf-8"))
        if fix and final_module_digest != recorded:
            registry_raw = _replace_digest(registry_raw, "sha256", recorded, final_module_digest)

    if fix and registry_raw != registry_path.read_text(encoding="utf-8"):
        registry_path.write_text(registry_raw, encoding="utf-8")

    return issues


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check (and optionally fix) VHEATM module digest hygiene")
    parser.add_argument("--root", type=Path, default=None, help="Control-plane root (defaults to the current checkout or bundled package data)")
    parser.add_argument("--fix", action="store_true", help="Rewrite mismatched digests in place")
    args = parser.parse_args(argv)

    root = resolve_control_root(args.root)
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
