from __future__ import annotations

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
from vheatm_control.serialization import load_json


ROOT = Path(__file__).resolve().parents[1]


def test_canonical_semantic_policy_is_schema_valid() -> None:
    policy = load_semantic_profile(ROOT)
    schema = load_json((ROOT / "schemas" / "semantic-profiles.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(policy)


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
