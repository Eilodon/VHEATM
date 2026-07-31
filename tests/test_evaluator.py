from pathlib import Path

import yaml

from vheatm_control.evaluator import evaluate_manifest


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = yaml.safe_load((ROOT / "manifests" / "vheatm-v17.yaml").read_text())


def test_default_context_blocks_on_unknown_activation() -> None:
    plan = evaluate_manifest(MANIFEST)
    assert plan["summary"]["total"] == 22
    assert plan["summary"]["completion_blocked"] is True
    assert plan["summary"]["unknown"] > 0


def test_explicit_low_risk_context_is_deterministic() -> None:
    plan = evaluate_manifest(
        MANIFEST,
        {
            "mode": "standard",
            "target_tier": 2,
            "context_mode": "single",
            "mandatory_findings": 0,
            "blast_radius": 1,
            "write_chain_components": 1,
            "declarations": {
                "self_audit": "no",
                "ai_executor": "no",
                "async_worker": "no",
                "safety_critical": "no",
                "financial_path": "no",
            },
        },
    )
    assert plan["summary"] == {
        "active": 15,
        "inactive": 7,
        "unknown": 0,
        "total": 22,
        "completion_blocked": False,
    }


def test_full_enterprise_context_activates_all_gates() -> None:
    plan = evaluate_manifest(
        MANIFEST,
        {
            "mode": "full",
            "target_tier": 3,
            "context_mode": "enterprise",
            "mandatory_findings": 2,
            "blast_radius": 5,
            "write_chain_components": 4,
            "declarations": {
                "self_audit": "yes",
                "ai_executor": "yes",
                "async_worker": "yes",
                "safety_critical": "yes",
                "financial_path": "yes",
            },
        },
    )
    assert plan["summary"]["active"] == 22
    assert plan["summary"]["unknown"] == 0
