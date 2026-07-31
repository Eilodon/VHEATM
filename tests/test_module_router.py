from __future__ import annotations

import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from vheatm_control.module_router import (
    _load_document,
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
    "MOD-EXECUTION-FIDELITY",
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
    result = load_and_route(
        ROOT,
        _plan({"HG-P": "active", "HG-AS": "active", "HG-EF": "active"}),
    )
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
    result = load_and_route(ROOT, _plan({"HG-E": "active"}))
    assert [item["id"] for item in result["selected_modules"]] == [
        "MOD-CONTEXT-CONTRACT",
        "MOD-SYSTEM-MAPS",
        "MOD-COMPOUND-DECOMPOSITION",
        "MOD-HYPOTHESIS-GENERATION",
        "MOD-PATTERN-GLOBALIZATION",
        "MOD-EVIDENCE-ANCHORS",
    ]


def test_auditor_defense_depends_on_hypothesis_generation():
    result = load_and_route(ROOT, _plan({"HG-AD": "active"}))
    ids = [item["id"] for item in result["selected_modules"]]
    assert ids == [
        "MOD-CONTEXT-CONTRACT",
        "MOD-SYSTEM-MAPS",
        "MOD-COMPOUND-DECOMPOSITION",
        "MOD-HYPOTHESIS-GENERATION",
        "MOD-AUDITOR-DEFENSE",
    ]


def test_unknown_covered_gate_is_not_silently_skipped():
    result = load_and_route(ROOT, _plan({"HG-P": "active", "HG-AD": "unknown", "HG-EF": "active"}))
    assert result["summary"]["completion_blocked"] is True
    assert {item["id"] for item in result["unresolved_modules"]} == {"MOD-AUDITOR-DEFENSE"}
    assert "HG-AD" in result["unknown_gates"]


def test_instruction_disclosure_is_opt_in():
    hidden = load_and_route(ROOT, _plan({"HG-P": "active"}))
    expanded = load_and_route(ROOT, _plan({"HG-P": "active"}), include_instructions=True)
    assert "instructions" not in hidden["selected_modules"][0]
    assert expanded["selected_modules"][0]["instructions"].startswith("# Context contract")


def test_output_matches_module_selection_schema():
    result = load_and_route(ROOT, _plan({"HG-P": "active"}))
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
    result = route_modules(manifest, registry, modules, _plan({"HG-E": "active"}))
    assert result["summary"]["budget_exceeded"] is True
    assert result["summary"]["completion_blocked"] is True


def test_dependency_selected_module_is_removed_from_unselected():
    result = load_and_route(ROOT, _plan({"HG-EF": "active"}))
    selected = {item["id"] for item in result["selected_modules"]}
    unselected = {item["id"] for item in result["unselected_modules"]}
    assert "MOD-CONTEXT-CONTRACT" in selected
    assert "MOD-CONTEXT-CONTRACT" not in unselected


def test_invalid_activation_state_fails_closed():
    import pytest
    from vheatm_control.module_router import ModuleRoutingError

    plan = _plan({"HG-P": "banana"})
    with pytest.raises(ModuleRoutingError, match="invalid activation_state"):
        load_and_route(ROOT, plan)
