from __future__ import annotations

import copy
import hashlib
import shutil
from pathlib import Path

import yaml

from vheatm_control.module_router import _load_document, _registry_root, validate_module_repository

ROOT = Path(__file__).resolve().parents[1]


def _copy_repo(tmp_path: Path) -> Path:
    for name in ["SKILL.md", "manifests", "schemas", "modules"]:
        source = ROOT / name
        target = tmp_path / name
        if source.is_dir():
            shutil.copytree(source, target)
        else:
            shutil.copy2(source, target)
    return tmp_path


def _validate(root: Path):
    return validate_module_repository(
        root,
        _load_document(root / "manifests" / "vheatm-v17.yaml"),
        module_schema=_load_document(root / "schemas" / "module-contract.schema.json"),
        registry_schema=_load_document(root / "schemas" / "module-registry.schema.json"),
    )[0]


def test_duplicate_gate_owner_is_rejected(tmp_path):
    root = _copy_repo(tmp_path)
    module_path = root / "modules" / "auditor-defense" / "module.yaml"
    document = yaml.safe_load(module_path.read_text())
    document["gate_coverage"] = ["HG-G"]
    module_path.write_text(yaml.safe_dump(document, sort_keys=False))

    registry_path = root / "modules" / "registry.yaml"
    registry = yaml.safe_load(registry_path.read_text())
    entry = next(item for item in registry["modules"] if item["id"] == "MOD-AUDITOR-DEFENSE")
    entry["sha256"] = hashlib.sha256(module_path.read_bytes()).hexdigest()
    registry_path.write_text(yaml.safe_dump(registry, sort_keys=False))

    issues = _validate(root)
    assert any(
        issue.source == "modules/registry.yaml"
        and "gate HG-G has multiple authoritative owners" in issue.message
        for issue in issues
    )


def test_registry_root_binds_legacy_source_fingerprint():
    registry = _load_document(ROOT / "modules" / "registry.yaml")
    baseline = _registry_root(registry)
    mutated = copy.deepcopy(registry)
    mutated["legacy_source"]["sha256"] = "0" * 64
    assert _registry_root(mutated) != baseline


def test_complete_registry_has_one_owner_for_every_manifest_gate():
    registry = _load_document(ROOT / "modules" / "registry.yaml")
    manifest = _load_document(ROOT / "manifests" / "vheatm-v17.yaml")
    assert registry["coverage_mode"] == "complete"
    issues, modules = validate_module_repository(
        ROOT, manifest,
        module_schema=_load_document(ROOT / "schemas" / "module-contract.schema.json"),
        registry_schema=_load_document(ROOT / "schemas" / "module-registry.schema.json"),
    )
    assert issues == []
    owners = {}
    for module in modules.values():
        for gate in module.document["gate_coverage"]:
            owners.setdefault(gate, []).append(module.id)
    assert set(owners) == {gate["id"] for gate in manifest["gates"]["items"]}
    assert all(len(values) == 1 for values in owners.values())
