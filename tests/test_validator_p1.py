import json
from pathlib import Path

import yaml

from vheatm_control.models import Manifest
from vheatm_control.validator import _validate_activations

ROOT = Path(__file__).resolve().parents[1]


def test_manifest_activation_references_are_declared() -> None:
    manifest = Manifest.model_validate(yaml.safe_load((ROOT / "manifests" / "vheatm-v17.yaml").read_text()))
    context_schema = json.loads((ROOT / "schemas" / "audit-context.schema.json").read_text())
    assert _validate_activations(manifest, context_schema) == []


def test_unknown_activation_identifier_is_rejected() -> None:
    raw = yaml.safe_load((ROOT / "manifests" / "vheatm-v17.yaml").read_text())
    raw["gates"]["items"][9]["activation"] = "typo_mode == full"
    manifest = Manifest.model_validate(raw)
    context_schema = json.loads((ROOT / "schemas" / "audit-context.schema.json").read_text())
    issues = _validate_activations(manifest, context_schema)
    assert any("absent from audit-context schema" in issue.message for issue in issues)
