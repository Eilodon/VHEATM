from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from vheatm_control.module_router import (
    _load_document,
    _route_modules_unchecked,
    load_and_route,
    route_modules,
    validate_module_repository,
)

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MODULES = {
    "MOD-CONTEXT-CONTRACT",
    "MOD-SYSTEM-MAPS",
    "MOD-ARCHITECTURE-SMELLS",
    "MOD-COMPOUND-DECOMPOSITION",
    "MOD-HYPOTHESIS-GENERATION",
    "MOD-PATTERN-GLOBALIZATION",
    "MOD-AUDITOR-DEFENSE",
    "MOD-EVIDENCE-ANCHORS",
    "MOD-HYBRID-VERIFICATION",
    "MOD-ARCHITECTURE-DECISIONS",
    "MOD-TRANSFORMATION-VERIFICATION",
    "MOD-FIX-VERIFICATION",
    "MOD-ADVERSARIAL-PASS",
    "MOD-EXECUTION-FIDELITY",
    "MOD-UTILITY-TREE",
    "MOD-FMEA-LITE",
    "MOD-INCENTIVE-MISALIGNMENT",
    "MOD-ORG-BLAST-RADIUS",
    "MOD-CODE-PATH-TRACE",
    "MOD-INDEPENDENT-JUDGE",
    "MOD-CLOSURE-METRICS",
    "MOD-KNOWLEDGE-BASE",
}


def _manifest():
    return _load_document(ROOT / "manifests" / "vheatm-v17.yaml")


def _plan(states: dict[str, str] | None = None):
    states = states or {}
    manifest = _manifest()
    return {
        "schema_version": "1.0.0",
        "framework_version": manifest["framework"]["version"],
        "context": {},
        "summary": {},
        "gates": [
            {
                "id": gate["id"],
                "layer": gate["layer"],
                "phase": gate["phase"],
                "activation": gate["activation"],
                "activation_state": states.get(gate["id"], "inactive"),
                "unknown_references": [],
                "reason": "fixture",
            }
            for gate in manifest["gates"]["items"]
        ],
    }


def _route_fixture(plan, *, include_instructions: bool = False):
    manifest = _manifest()
    registry = _load_document(ROOT / "modules" / "registry.yaml")
    issues, modules = validate_module_repository(
        ROOT,
        manifest,
        module_schema=_load_document(ROOT / "schemas" / "module-contract.schema.json"),
        registry_schema=_load_document(ROOT / "schemas" / "module-registry.schema.json"),
    )
    assert issues == []
    return _route_modules_unchecked(
        manifest,
        registry,
        modules,
        plan,
        include_instructions=include_instructions,
    )


def test_repository_module_contracts_validate():
    manifest = _manifest()
    issues, loaded = validate_module_repository(
        ROOT,
        manifest,
        module_schema=_load_document(ROOT / "schemas" / "module-contract.schema.json"),
        registry_schema=_load_document(ROOT / "schemas" / "module-registry.schema.json"),
    )
    assert issues == []
    assert set(loaded) == EXPECTED_MODULES


def test_router_selects_active_modules_and_dependency_order():
    result = _route_fixture(_plan({"HG-P": "active", "HG-AS": "active", "HG-EF": "active"}))
    ids = [item["id"] for item in result["selected_modules"]]
    assert ids == [
        "MOD-CONTEXT-CONTRACT",
        "MOD-SYSTEM-MAPS",
        "MOD-ARCHITECTURE-SMELLS",
        "MOD-EXECUTION-FIDELITY",
    ]
    assert result["summary"]["completion_blocked"] is False
    assert all(not item["instruction_path"].startswith("/") for item in result["selected_modules"])


def test_evidence_gate_closes_the_core_dependency_chain():
    result = _route_fixture(_plan({"HG-E": "active"}))
    assert [item["id"] for item in result["selected_modules"]] == [
        "MOD-CONTEXT-CONTRACT",
        "MOD-SYSTEM-MAPS",
        "MOD-COMPOUND-DECOMPOSITION",
        "MOD-HYPOTHESIS-GENERATION",
        "MOD-PATTERN-GLOBALIZATION",
        "MOD-EVIDENCE-ANCHORS",
    ]


def test_auditor_defense_depends_on_hypothesis_generation():
    result = _route_fixture(_plan({"HG-AD": "active"}))
    ids = [item["id"] for item in result["selected_modules"]]
    assert ids == [
        "MOD-CONTEXT-CONTRACT",
        "MOD-SYSTEM-MAPS",
        "MOD-COMPOUND-DECOMPOSITION",
        "MOD-HYPOTHESIS-GENERATION",
        "MOD-AUDITOR-DEFENSE",
    ]


def test_unknown_covered_gate_is_not_silently_skipped():
    result = _route_fixture(_plan({"HG-P": "active", "HG-AD": "unknown", "HG-EF": "active"}))
    assert result["summary"]["completion_blocked"] is True
    assert {item["id"] for item in result["unresolved_modules"]} == {"MOD-AUDITOR-DEFENSE"}
    assert "HG-AD" in result["unknown_gates"]


def test_instruction_disclosure_is_opt_in():
    hidden = _route_fixture(_plan({"HG-P": "active"}))
    expanded = _route_fixture(_plan({"HG-P": "active"}), include_instructions=True)
    assert "instructions" not in hidden["selected_modules"][0]
    assert expanded["selected_modules"][0]["instructions"].startswith("# Context contract")
    assert len(hidden["selected_modules"][0]["module_sha256"]) == 64


def test_output_matches_module_selection_schema():
    result = _route_fixture(_plan({"HG-P": "active"}))
    schema = json.loads((ROOT / "schemas" / "module-selection.schema.json").read_text())
    Draft202012Validator(schema).validate(result)


def test_budget_overflow_blocks():
    manifest = _manifest()
    registry = _load_document(ROOT / "modules" / "registry.yaml")
    issues, modules = validate_module_repository(
        ROOT,
        manifest,
        module_schema=_load_document(ROOT / "schemas" / "module-contract.schema.json"),
        registry_schema=_load_document(ROOT / "schemas" / "module-registry.schema.json"),
    )
    assert not issues
    registry = copy.deepcopy(registry)
    registry["hard_token_budget"] = 1
    result = _route_modules_unchecked(manifest, registry, modules, _plan({"HG-E": "active"}))
    assert result["summary"]["budget_exceeded"] is True
    assert result["summary"]["completion_blocked"] is True


def test_dependency_selected_module_is_removed_from_unselected():
    result = _route_fixture(_plan({"HG-EF": "active"}))
    selected = {item["id"] for item in result["selected_modules"]}
    unselected = {item["id"] for item in result["unselected_modules"]}
    assert "MOD-CONTEXT-CONTRACT" in selected
    assert "MOD-CONTEXT-CONTRACT" not in unselected


def test_invalid_activation_state_fails_closed():
    from vheatm_control.module_router import ModuleRoutingError

    plan = _plan({"HG-P": "banana"})
    with pytest.raises(ModuleRoutingError, match="invalid activation_state"):
        _route_fixture(plan)


def test_mutated_evaluated_plan_is_rejected_by_router():
    from vheatm_control.evaluator import evaluate_manifest
    from vheatm_control.module_router import ModuleRoutingError

    manifest = _manifest()
    plan = evaluate_manifest(
        manifest,
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
    tampered = copy.deepcopy(plan)
    tampered["gates"] = [
        {**gate, "activation_state": "inactive"} if gate["id"] == "HG-IJ" else gate
        for gate in tampered["gates"]
    ]

    with pytest.raises(ModuleRoutingError, match="recomputed"):
        load_and_route(ROOT, tampered)


def test_public_router_rejects_unbound_fixture_plan():
    from vheatm_control.module_router import ModuleRoutingError

    manifest = _manifest()
    registry = _load_document(ROOT / "modules" / "registry.yaml")
    issues, modules = validate_module_repository(
        ROOT,
        manifest,
        module_schema=_load_document(ROOT / "schemas" / "module-contract.schema.json"),
        registry_schema=_load_document(ROOT / "schemas" / "module-registry.schema.json"),
    )
    assert issues == []
    with pytest.raises(ModuleRoutingError, match="binding|context"):
        route_modules(manifest, registry, modules, _plan({"HG-P": "active"}))


def test_fix_verification_closes_the_decision_chain():
    result = _route_fixture(_plan({"HG-FV": "active"}))
    assert [item["id"] for item in result["selected_modules"]] == [
        "MOD-CONTEXT-CONTRACT",
        "MOD-SYSTEM-MAPS",
        "MOD-COMPOUND-DECOMPOSITION",
        "MOD-HYPOTHESIS-GENERATION",
        "MOD-PATTERN-GLOBALIZATION",
        "MOD-EVIDENCE-ANCHORS",
        "MOD-ARCHITECTURE-DECISIONS",
        "MOD-TRANSFORMATION-VERIFICATION",
        "MOD-FIX-VERIFICATION",
    ]


def test_hybrid_verification_branches_from_evidence():
    result = _route_fixture(_plan({"HG-HV": "active"}))
    ids = [item["id"] for item in result["selected_modules"]]
    assert ids[:6] == [
        "MOD-CONTEXT-CONTRACT",
        "MOD-SYSTEM-MAPS",
        "MOD-COMPOUND-DECOMPOSITION",
        "MOD-HYPOTHESIS-GENERATION",
        "MOD-PATTERN-GLOBALIZATION",
        "MOD-EVIDENCE-ANCHORS",
    ]
    assert ids[-1] == "MOD-HYBRID-VERIFICATION"


def test_adversarial_pass_depends_on_verified_fixes():
    result = _route_fixture(_plan({"HG-AP": "active"}))
    ids = [item["id"] for item in result["selected_modules"]]
    assert ids[-5:] == [
        "MOD-EVIDENCE-ANCHORS",
        "MOD-ARCHITECTURE-DECISIONS",
        "MOD-TRANSFORMATION-VERIFICATION",
        "MOD-FIX-VERIFICATION",
        "MOD-ADVERSARIAL-PASS",
    ]


def test_complete_registry_routes_all_twenty_two_gate_owners():
    result = _route_fixture(_plan({gate["id"]: "active" for gate in _manifest()["gates"]["items"]}))
    ids = [item["id"] for item in result["selected_modules"]]
    assert len(ids) == 22
    assert len(set(ids)) == 22
    assert result["summary"]["budget_exceeded"] is False
    assert result["summary"]["completion_blocked"] is False


def test_triggered_and_meta_completion_dependencies():
    utility = _route_fixture(_plan({"HG-UT": "active"}))
    assert [item["id"] for item in utility["selected_modules"]] == [
        "MOD-CONTEXT-CONTRACT", "MOD-SYSTEM-MAPS", "MOD-UTILITY-TREE"
    ]
    kb = _route_fixture(_plan({"HG-KB": "active"}))
    ids = [item["id"] for item in kb["selected_modules"]]
    assert ids[-2:] == ["MOD-CLOSURE-METRICS", "MOD-KNOWLEDGE-BASE"]
    assert "MOD-ADVERSARIAL-PASS" in ids
    assert "MOD-EXECUTION-FIDELITY" in ids
