from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from vheatm_control.semantic_profiles import (
    SemanticProfileError,
    calculate_brs,
    calculate_qbr,
    calculate_rpn,
    load_semantic_profile,
    map_fmea_to_qbr,
)
import vheatm_control.semantic_profiles as semantic_profiles
from vheatm_control.serialization import load_json


ROOT = Path(__file__).resolve().parents[1]


def test_canonical_semantic_policy_is_schema_valid() -> None:
    policy = load_semantic_profile(ROOT)
    schema = load_json((ROOT / "schemas" / "semantic-profiles.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(policy)


def test_invalid_semantic_profile_blocks_calculation(tmp_path: Path) -> None:
    (tmp_path / "policies").mkdir()
    (tmp_path / "schemas").mkdir()
    (tmp_path / "manifests").mkdir()
    (tmp_path / "policies" / "semantic-profiles.yaml").write_text("schema_version: '1.0.0'\n", encoding="utf-8")
    shutil.copy2(ROOT / "schemas" / "semantic-profiles.schema.json", tmp_path / "schemas" / "semantic-profiles.schema.json")
    shutil.copy2(ROOT / "manifests" / "vheatm-v17.yaml", tmp_path / "manifests" / "vheatm-v17.yaml")
    with pytest.raises(SemanticProfileError, match="canonical semantic profile is invalid"):
        calculate_rpn(1, 1, 1, root=tmp_path)


def test_semantic_profile_framework_must_match_manifest(tmp_path: Path) -> None:
    (tmp_path / "policies").mkdir()
    (tmp_path / "schemas").mkdir()
    (tmp_path / "manifests").mkdir()
    policy = (ROOT / "policies" / "semantic-profiles.yaml").read_text(encoding="utf-8").replace("17.0.0-dev.1", "16.0.0")
    (tmp_path / "policies" / "semantic-profiles.yaml").write_text(policy, encoding="utf-8")
    shutil.copy2(ROOT / "schemas" / "semantic-profiles.schema.json", tmp_path / "schemas" / "semantic-profiles.schema.json")
    shutil.copy2(ROOT / "manifests" / "vheatm-v17.yaml", tmp_path / "manifests" / "vheatm-v17.yaml")
    with pytest.raises(SemanticProfileError, match="framework_version"):
        calculate_rpn(1, 1, 1, root=tmp_path)


def test_fmea_mapping_keeps_detectability_out_of_blast_radius() -> None:
    low_detection = map_fmea_to_qbr(severity=8, detectability=10, system_effect="corruption", cause_class="auth_bypass_injection", downstream_count=1)
    wide_impact = map_fmea_to_qbr(severity=8, detectability=1, system_effect="corruption", cause_class="auth_bypass_injection", downstream_count=5)
    assert low_detection["blast_radius"] == 1
    assert wide_impact["blast_radius"] == 3
    assert low_detection["data_integrity_risk"] == 3
    assert low_detection["security_risk"] == 3


def test_rpn_priority_and_qbr_adjustments_are_deterministic() -> None:
    rpn = calculate_rpn(5, 5, 5)
    assert rpn.score == 125
    assert rpn.priority == "mandatory"
    qbr = calculate_qbr({"user_facing_impact": 2, "data_integrity_risk": 2, "security_risk": 1, "blast_radius": 2}, context_mode="DESIGN", self_audit=True, brs=8)
    assert qbr["base_score"] == 25
    assert qbr["dimensions"]["blast_radius"] == 3
    assert qbr["score"] == 36
    assert qbr["priority"] == "mandatory"


def test_brs_preserves_unknown_instead_of_treating_it_as_zero() -> None:
    unknown = calculate_brs(teams_directly_affected=2, sla_chains_at_risk=None, regulatory_obligations=1)
    assert unknown["status"] == "unknown"
    assert unknown["score"] is None
    assert unknown["lower_bound"] == 6
    with pytest.raises(SemanticProfileError):
        calculate_qbr({"user_facing_impact": 4, "data_integrity_risk": 0, "security_risk": 0, "blast_radius": 0}, context_mode="CODE")


def test_calculators_consume_loaded_profile_values(monkeypatch: pytest.MonkeyPatch) -> None:
    profile = {
        "rpn": {"thresholds": {"mandatory": 200, "required": 80, "recommended": 70}},
        "qbr": {
            "dimensions": {"user_facing_impact": 1, "data_integrity_risk": 1, "security_risk": 1, "blast_radius": 1},
            "max_score": 10,
            "dimension_max": 5,
            "fmea_risk_max": 10,
            "mandatory_threshold": 3,
            "required_threshold": 2,
            "adjustments": {"design": 2.0, "self_audit": 1.0, "org_capture": 1.0},
            "brs_blast_radius_floor": 5,
            "fmea_mapping": {
                "severity_to_user_facing": [{"max": 10, "value": 1}],
                "system_effect_to_integrity": {"corruption": 9},
                "cause_to_security": {"auth_bypass_injection": 9},
                "blast_radius_scope": {"local": 1, "multi_component": 2, "widespread": 7},
                "blast_radius_boundaries": {"local_max": 0, "multi_component_max": 0},
                "undetectable_floor": 10,
            },
        },
        "brs": {
            "weights": {"teams_directly_affected": 10, "sla_chains_at_risk": 20, "regulatory_obligations": 30},
            "thresholds": {"contained": 30, "elevated": 70, "high": 120},
            "unknown_sla_floor": 7,
            "escalation_threshold": 100,
        },
    }
    monkeypatch.setattr(semantic_profiles, "load_semantic_profile", lambda root=None: profile)

    assert semantic_profiles.calculate_rpn(4, 4, 4).priority == "optional"
    brs = semantic_profiles.calculate_brs(teams_directly_affected=1, sla_chains_at_risk=1, regulatory_obligations=1)
    assert brs["tier"] == "elevated"
    assert brs["escalation_required"] is False
    assert semantic_profiles.map_fmea_to_qbr(
        severity=10,
        detectability=1,
        system_effect="corruption",
        cause_class="auth_bypass_injection",
        downstream_count=1,
    ) == {"user_facing_impact": 1, "data_integrity_risk": 9, "security_risk": 9, "blast_radius": 7}
    qbr = semantic_profiles.calculate_qbr(
        {"user_facing_impact": 4, "data_integrity_risk": 4, "security_risk": 4, "blast_radius": 1},
        context_mode="DESIGN",
        brs=5,
    )
    assert qbr["dimensions"]["blast_radius"] == 5
    assert qbr["priority"] == "mandatory"
