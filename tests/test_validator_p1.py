import json
from pathlib import Path

import yaml

from vheatm_control.models import Manifest
from vheatm_control.validator import _validate_activations
from vheatm_control.validator import validate_repository

ROOT = Path(__file__).resolve().parents[1]


def test_manifest_activation_references_are_declared() -> None:
    manifest = Manifest.model_validate(yaml.safe_load((ROOT / "manifests" / "vheatm-v17.yaml").read_text()))
    context_schema = json.loads((ROOT / "schemas" / "audit-context.schema.json").read_text())
    assert _validate_activations(manifest, context_schema) == []


def test_qualification_method_policy_is_manifest_bound() -> None:
    manifest = yaml.safe_load((ROOT / "manifests" / "vheatm-v17.yaml").read_text())
    policy = yaml.safe_load((ROOT / "policies" / "qualification-methods.yaml").read_text())
    from vheatm_control.validator import _validate_qualification_methods

    assert _validate_qualification_methods(manifest, policy) == []
    policy["framework_version"] = "16.0.0"
    assert any("canonical manifest" in issue for issue in _validate_qualification_methods(manifest, policy))


def test_supply_chain_evidence_policy_is_manifest_bound() -> None:
    manifest = yaml.safe_load((ROOT / "manifests" / "vheatm-v17.yaml").read_text())
    policy = yaml.safe_load((ROOT / "policies" / "supply-chain-evidence.yaml").read_text())
    from vheatm_control.validator import _validate_supply_chain_evidence

    assert _validate_supply_chain_evidence(manifest, policy) == []
    policy["framework_version"] = "16.0.0"
    assert any("canonical manifest" in issue for issue in _validate_supply_chain_evidence(manifest, policy))
    policy["framework_version"] = manifest["framework"]["version"]
    policy["distinct_signing_key_roles"] = ["supply_chain", "vulnerability"]
    assert any("must cover" in issue for issue in _validate_supply_chain_evidence(manifest, policy))


def test_unknown_activation_identifier_is_rejected() -> None:
    raw = yaml.safe_load((ROOT / "manifests" / "vheatm-v17.yaml").read_text())
    raw["gates"]["items"][9]["activation"] = "typo_mode == full"
    manifest = Manifest.model_validate(raw)
    context_schema = json.loads((ROOT / "schemas" / "audit-context.schema.json").read_text())
    issues = _validate_activations(manifest, context_schema)
    assert any("absent from audit-context schema" in issue.message for issue in issues)


def test_validator_reports_duplicate_canonical_yaml_without_traceback(tmp_path):
    import shutil

    for name in ["SKILL.md", "Makefile", "pyproject.toml", "uv.lock", "manifests", "policies", "modules", "schemas", "src", "evals", "docs"]:
        source = ROOT / name
        target = tmp_path / name
        shutil.copytree(source, target) if source.is_dir() else shutil.copy2(source, target)
    manifest_path = tmp_path / "manifests" / "vheatm-v17.yaml"
    manifest_path.write_text(manifest_path.read_text() + "\nframework:\n  version: duplicate\n")
    issues = validate_repository(tmp_path)
    assert any(issue.source == "canonical" and "duplicate YAML" in issue.message for issue in issues)
