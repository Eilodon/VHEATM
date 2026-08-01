import json
from pathlib import Path

import yaml

from vheatm_control.models import Manifest
from vheatm_control.capability_ledger import corpus_digest
from vheatm_control.validator import _validate_activations
from vheatm_control.validator import _validate_provider_allowlist
from vheatm_control.validator import _validate_legacy_source, validate_repository

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


def test_provider_allowlist_is_manifest_bound() -> None:
    manifest = yaml.safe_load((ROOT / "manifests" / "vheatm-v17.yaml").read_text())
    policy = yaml.safe_load((ROOT / "policies" / "provider-allowlist.yaml").read_text())
    from vheatm_control.validator import _validate_provider_allowlist

    assert _validate_provider_allowlist(manifest, policy) == []
    policy["framework_version"] = "16.0.0"
    assert any("canonical manifest" in issue for issue in _validate_provider_allowlist(manifest, policy))


def test_provider_allowlist_cannot_mark_qualification_without_evidence() -> None:
    manifest = yaml.safe_load((ROOT / "manifests" / "vheatm-v17.yaml").read_text())
    policy = yaml.safe_load((ROOT / "policies" / "provider-allowlist.yaml").read_text())
    policy["providers"][0]["qualification_state"] = "qualified"
    assert any("qualification evidence refs" in issue for issue in _validate_provider_allowlist(manifest, policy))


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


def test_legacy_archive_rebaseline_is_explicit_and_content_bound(tmp_path):
    import shutil

    for name in ["SKILL.md", "Makefile", "pyproject.toml", "uv.lock", "manifests", "policies", "modules", "schemas", "src", "evals", "docs"]:
        source = ROOT / name
        target = tmp_path / name
        shutil.copytree(source, target) if source.is_dir() else shutil.copy2(source, target)

    registry_path = tmp_path / "modules" / "registry.yaml"
    registry = yaml.safe_load(registry_path.read_text())
    registry["legacy_source"]["corpus_digest"] = "0" * 64
    registry_path.write_text(yaml.safe_dump(registry, sort_keys=False))

    issues = validate_repository(tmp_path)
    assert any("legacy extracted corpus digest" in issue.message for issue in issues)


def test_verified_legacy_archive_requires_an_available_archive(tmp_path):
    import shutil

    for name in ["SKILL.md", "Makefile", "pyproject.toml", "uv.lock", "manifests", "policies", "modules", "schemas", "src", "evals", "docs"]:
        source = ROOT / name
        target = tmp_path / name
        shutil.copytree(source, target) if source.is_dir() else shutil.copy2(source, target)

    registry_path = tmp_path / "modules" / "registry.yaml"
    registry = yaml.safe_load(registry_path.read_text())
    legacy = registry["legacy_source"]
    legacy.update({"archive_status": "verified", "source_basis": "original_archive", "archive_path": "docs/VHEATM-v16.1.1.skill", "sha256": "e" * 64, "size_bytes": 1})
    registry_path.write_text(yaml.safe_dump(registry, sort_keys=False))

    issues = validate_repository(tmp_path)
    assert any("legacy archive is declared verified but is unavailable" in issue.message for issue in issues)


def test_legacy_corpus_rejects_symlinked_content(tmp_path):
    root = tmp_path.resolve()
    corpus = root / "legacy"
    corpus.mkdir()
    (corpus / "owned.txt").write_text("owned", encoding="utf-8")
    outside = root / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    link = corpus / "linked.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")

    registry = {
        "legacy_source": {
            "archive_status": "unavailable",
            "source_basis": "extracted_corpus",
            "archive_path": None,
            "sha256": None,
            "size_bytes": None,
            "corpus_root": "legacy",
            "corpus_digest": corpus_digest(corpus),
        }
    }
    issues = _validate_legacy_source(root, registry)
    assert any("must not contain symlinked files" in issue.message for issue in issues)
