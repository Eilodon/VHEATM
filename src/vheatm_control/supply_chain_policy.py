from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from .bundle import resolve_control_root
from .serialization import load_json, load_yaml


class SupplyChainPolicyError(ValueError):
    """Raised when the canonical supply-chain evidence policy is unavailable or invalid."""


def _load_policy(root: Path | None = None) -> Mapping[str, Any]:
    control_root = resolve_control_root(root)
    policy_path = control_root / "policies" / "supply-chain-evidence.yaml"
    schema_path = control_root / "schemas" / "supply-chain-evidence.schema.json"
    try:
        policy = load_yaml(policy_path.read_text(encoding="utf-8"))
        schema = load_json(schema_path.read_text(encoding="utf-8"))
        manifest = load_yaml((control_root / "manifests" / "vheatm-v17.yaml").read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SupplyChainPolicyError(f"supply-chain evidence policy is unavailable: {exc}") from exc
    errors = sorted(Draft202012Validator(schema).iter_errors(policy), key=lambda error: list(error.absolute_path))
    if errors:
        raise SupplyChainPolicyError(f"supply-chain evidence policy is not schema-valid: {errors[0].message}")
    if policy.get("framework_version") != manifest.get("framework", {}).get("version"):
        raise SupplyChainPolicyError("supply-chain evidence policy framework_version must match the canonical manifest")
    return policy


def vulnerability_scan_policy(root: Path | None = None) -> Mapping[str, Any]:
    policy = _load_policy(root)
    section = policy.get("vulnerability_scan")
    if not isinstance(section, Mapping):
        raise SupplyChainPolicyError("vulnerability_scan policy section is missing")
    return section


def vulnerability_scan_max_age_seconds(root: Path | None = None) -> int:
    value = vulnerability_scan_policy(root).get("max_age_seconds")
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise SupplyChainPolicyError("vulnerability scan max_age_seconds is invalid")
    return value


def distinct_signing_key_roles(root: Path | None = None) -> tuple[str, ...]:
    policy = _load_policy(root)
    roles = policy.get("distinct_signing_key_roles")
    expected = {"supply_chain", "vulnerability", "provenance"}
    if not isinstance(roles, list) or set(roles) != expected or len(roles) != len(expected):
        raise SupplyChainPolicyError("distinct_signing_key_roles must cover supply_chain, vulnerability, and provenance exactly once")
    return tuple(str(role) for role in roles)
