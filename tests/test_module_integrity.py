from __future__ import annotations

import copy
import hashlib
from pathlib import Path

import yaml

from vheatm_control.module_router import _load_document, validate_module_repository

ROOT = Path(__file__).resolve().parents[1]


def _copy_repo(tmp_path: Path) -> Path:
    import shutil
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


def test_instruction_tamper_is_detected(tmp_path):
    root = _copy_repo(tmp_path)
    path = root / "modules" / "context-contract" / "instructions.md"
    path.write_text(path.read_text() + "\nTAMPER\n")
    assert any("instruction SHA-256" in issue.message for issue in _validate(root))


def test_module_tamper_is_detected_before_loading(tmp_path):
    root = _copy_repo(tmp_path)
    path = root / "modules" / "context-contract" / "module.yaml"
    path.write_text(path.read_text() + "\n# formatting mutation\n")
    assert any("module SHA-256" in issue.message for issue in _validate(root))


def test_unknown_gate_is_detected_after_digest_update(tmp_path):
    root = _copy_repo(tmp_path)
    module_path = root / "modules" / "context-contract" / "module.yaml"
    document = yaml.safe_load(module_path.read_text())
    document["gate_coverage"] = ["HG-FAKE"]
    module_path.write_text(yaml.safe_dump(document, sort_keys=False))
    registry_path = root / "modules" / "registry.yaml"
    registry = yaml.safe_load(registry_path.read_text())
    registry["modules"][0]["sha256"] = hashlib.sha256(module_path.read_bytes()).hexdigest()
    registry_path.write_text(yaml.safe_dump(registry, sort_keys=False))
    assert any("unknown gate coverage" in issue.message for issue in _validate(root))


def test_router_line_budget_is_enforced(tmp_path):
    root = _copy_repo(tmp_path)
    (root / "SKILL.md").write_text("\n".join(["line"] * 351))
    assert any("at most 350 lines" in issue.message for issue in _validate(root))
