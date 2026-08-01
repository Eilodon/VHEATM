from __future__ import annotations

import hashlib
from pathlib import Path

from jsonschema import Draft202012Validator

from vheatm_control.serialization import load_yaml
from vheatm_control.supply_chain import build_supply_chain_attestation


ROOT = Path(__file__).resolve().parents[1]


def test_standards_baseline_is_present_and_schema_valid() -> None:
    policy_path = ROOT / "policies" / "standards-baseline.yaml"
    schema_path = ROOT / "schemas" / "standards-baseline.schema.json"
    assert policy_path.is_file()
    assert schema_path.is_file()

    policy = load_yaml(policy_path.read_text(encoding="utf-8"))
    schema = __import__("json").loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(policy)
    assert policy["framework_version"] == "17.0.0-dev.1"
    assert any(item["namespace"] == "normative" for item in policy["standards"])
    assert all(item["namespace"] in {"normative", "community", "draft", "experimental"} for item in policy["standards"])


def test_supply_chain_attestation_binds_verified_uv_lock() -> None:
    lock_path = ROOT / "uv.lock"
    assert lock_path.is_file()
    attestation = build_supply_chain_attestation(ROOT, generated_at="2026-08-01T00:00:00Z")
    assert attestation["dependency_lock_present"] is True
    assert attestation["dependency_lock_digest"] == hashlib.sha256(lock_path.read_bytes()).hexdigest()
    assert attestation["dependency_lock_path"] == "uv.lock"
