from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from vheatm_control.bundle import BundleError, build_bundle, canonical_bundle_root, validate_bundle
from vheatm_control.serialization import DuplicateKeyError, load_json, load_yaml


ROOT = Path(__file__).resolve().parents[1]


def test_control_bundle_is_complete_deterministic_and_schema_valid() -> None:
    bundle = build_bundle(ROOT)
    schema = json.loads((ROOT / "schemas" / "control-bundle.schema.json").read_text())

    Draft202012Validator(schema).validate(bundle)
    assert bundle["bundle_root"] == canonical_bundle_root(bundle["entries"])
    assert validate_bundle(ROOT, bundle) == []
    paths = {entry["path"] for entry in bundle["entries"]}
    assert "manifests/vheatm-v17.yaml" in paths
    assert "policies/runtime-boundaries.yaml" in paths
    assert "policies/standards-baseline.yaml" in paths
    assert "policies/qualification-methods.yaml" in paths
    assert "policies/supply-chain-evidence.yaml" in paths
    assert "policies/provider-allowlist.yaml" in paths
    assert "modules/registry.yaml" in paths
    assert "schemas/audit-context.schema.json" in paths
    assert "src/vheatm_control/evaluator.py" in paths
    assert sum(path.startswith("docs/VHEATM-bản gốc tham khảo/vheatm-ultimate/") for path in paths) == 33
    assert "evals/cases.yaml" in paths


def test_control_bundle_root_changes_on_canonical_byte_mutation() -> None:
    bundle = build_bundle(ROOT)
    mutated = copy.deepcopy(bundle["entries"])
    mutated[0]["sha256"] = "0" * 64 if mutated[0]["sha256"] != "0" * 64 else "1" * 64
    assert canonical_bundle_root(mutated) != bundle["bundle_root"]


def test_control_bundle_rejects_tampered_inventory() -> None:
    bundle = build_bundle(ROOT)
    bundle["entries"][0]["sha256"] = "0" * 64
    with pytest.raises(BundleError, match="does not match canonical bundle"):
        validate_bundle(ROOT, bundle)


def test_machine_loaders_reject_duplicate_yaml_and_json_keys() -> None:
    with pytest.raises(DuplicateKeyError, match="duplicate YAML"):
        load_yaml("mode: standard\nmode: full\n")
    with pytest.raises(DuplicateKeyError, match="duplicate JSON"):
        load_json('{"mode":"standard","mode":"full"}')


def test_non_finite_json_numbers_are_rejected() -> None:
    with pytest.raises(ValueError, match="non-finite"):
        load_json('{"measurement": NaN}')
