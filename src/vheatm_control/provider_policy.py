from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from .bundle import resolve_control_root
from .serialization import load_json, load_yaml


class ProviderPolicyError(ValueError):
    """Raised when a provider is not authorized by the canonical allowlist."""


def _load_policy(root: Path | None = None) -> Mapping[str, Any]:
    control_root = resolve_control_root(root)
    policy_path = control_root / "policies" / "provider-allowlist.yaml"
    schema_path = control_root / "schemas" / "provider-allowlist.schema.json"
    try:
        policy = load_yaml(policy_path.read_text(encoding="utf-8"))
        schema = load_json(schema_path.read_text(encoding="utf-8"))
        manifest = load_yaml((control_root / "manifests" / "vheatm-v17.yaml").read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise ProviderPolicyError(f"provider allowlist policy is unavailable: {exc}") from exc
    errors = sorted(Draft202012Validator(schema).iter_errors(policy), key=lambda error: list(error.absolute_path))
    if errors:
        raise ProviderPolicyError(f"provider allowlist policy is not schema-valid: {errors[0].message}")
    if policy.get("framework_version") != manifest.get("framework", {}).get("version"):
        raise ProviderPolicyError("provider allowlist framework_version must match the canonical manifest")
    return policy


def provider_descriptor(provider_id: str, provider_version: str, root: Path | None = None) -> Mapping[str, Any]:
    policy = _load_policy(root)
    for entry in policy.get("providers", []):
        if entry.get("provider_id") == provider_id and provider_version in entry.get("provider_versions", []):
            if entry.get("qualification_state") == "revoked":
                raise ProviderPolicyError(f"provider {provider_id}@{provider_version} is revoked")
            return entry
    raise ProviderPolicyError(f"provider {provider_id}@{provider_version} is not allowlisted")
