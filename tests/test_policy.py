from pathlib import Path

import pytest

import vheatm_control.policy as compatibility
from vheatm_control.tool_broker import ToolBroker


ROOT = Path(__file__).resolve().parents[1]


def test_policy_module_is_only_a_canonical_broker_compatibility_surface() -> None:
    assert compatibility.ToolBroker is ToolBroker
    assert not hasattr(compatibility, "PolicyEngine")
    with pytest.raises(AttributeError, match="retired"):
        compatibility.PolicyEngine


def test_legacy_policy_material_is_not_runtime_importable() -> None:
    archive = ROOT / "docs" / "migration" / "legacy-policy.py.txt"
    assert archive.is_file()
    assert "NON-AUTHORITATIVE MIGRATION ARCHIVE" in archive.read_text(encoding="utf-8")
