from __future__ import annotations

import copy
from pathlib import Path

import pytest

from vheatm_control.evaluator import evaluate_manifest
from vheatm_control.bundle import build_bundle
from vheatm_control.execution import (
    ExecutionError,
    build_artifact_envelope,
    derive_gate_results,
    expected_module_run_id,
    run_module,
    validate_module_run,
)
from vheatm_control.module_router import _load_document, load_and_route, validate_module_repository
from vheatm_control.provenance import build_source_record, build_validation_receipt

ROOT = Path(__file__).resolve().parents[1]


def _context() -> dict:
    return {
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
    }


def _fixture() -> tuple[dict, dict, dict, dict, dict]:
    manifest = _load_document(ROOT / "manifests" / "vheatm-v17.yaml")
    plan = evaluate_manifest(manifest, _context(), bundle_root=build_bundle(ROOT)["bundle_root"])
    selection = load_and_route(ROOT, plan)
    _, modules = validate_module_repository(
        ROOT,
        manifest,
        module_schema=_load_document(ROOT / "schemas" / "module-contract.schema.json"),
        registry_schema=_load_document(ROOT / "schemas" / "module-registry.schema.json"),
    )
    module = modules["MOD-CONTEXT-CONTRACT"]
    run_id = "RUN-pending"
    source = build_source_record(
        source_type="test",
        locator="tests/test_execution.py::evidence",
        content="evidence",
        trust_zone="artifact_content",
        captured_at="2026-08-01T03:00:00Z",
    )
    receipt = build_validation_receipt(
        source_refs=[source["id"]],
        validator="test-validator",
        method="fixture-review",
        input_digest=source["digest"]["value"],
        validated_at="2026-08-01T03:00:00Z",
    )
    decision = {
        "module_id": module.id,
        "module_run_id": run_id,
        "gate_trace": ["HG-P"],
        "state": "pass",
        "evidence_refs": [],
    }
    artifact = build_artifact_envelope(
        producer_module_id=module.id,
        producer_run_id=run_id,
        output_id="module_decision",
        schema_ref="https://vheatm.dev/schemas/module-decision.schema.json",
        payload=decision,
        validation_receipt_refs=[receipt["id"]],
        taint_state="validated",
    )
    decision["evidence_refs"] = [receipt["id"]]
    provisional_run = {
        "id": "",
        "module_id": module.id,
        "module_digest": module.digest,
        "instruction_digest": module.instruction_digest,
        "status": "completed",
        "started_at": "2026-08-01T03:00:00Z",
        "finished_at": "2026-08-01T03:00:01Z",
        "input_artifact_refs": [],
        "output_artifact_refs": [],
        "validation_receipt_refs": [receipt["id"]],
        "result": decision,
    }
    run_id = expected_module_run_id(provisional_run)
    decision["module_run_id"] = run_id
    artifact = build_artifact_envelope(
        producer_module_id=module.id,
        producer_run_id=run_id,
        output_id="module_decision",
        schema_ref="https://vheatm.dev/schemas/module-decision.schema.json",
        payload=decision,
        validation_receipt_refs=[receipt["id"]],
        taint_state="validated",
    )
    run = {
        "id": run_id,
        "module_id": module.id,
        "module_digest": module.digest,
        "instruction_digest": module.instruction_digest,
        "status": "completed",
        "started_at": "2026-08-01T03:00:00Z",
        "finished_at": "2026-08-01T03:00:01Z",
        "input_artifact_refs": [],
        "output_artifact_refs": [artifact["id"]],
        "validation_receipt_refs": [receipt["id"]],
        "result": decision,
    }
    return manifest, plan, selection, module.document, {"run": run, "artifact": artifact, "receipt": receipt, "source": source}


def test_completed_module_run_requires_bound_typed_output() -> None:
    _, _, _, contract, value = _fixture()
    validate_module_run(
        value["run"],
        contract,
        {value["artifact"]["id"]: value["artifact"]},
        {value["receipt"]["id"]: value["receipt"]},
    )

    forged_run = copy.deepcopy(value["run"])
    forged_run["id"] = "RUN-" + "B" * 64
    with pytest.raises(ExecutionError, match="run id"):
        validate_module_run(
            forged_run,
            contract,
            {value["artifact"]["id"]: value["artifact"]},
            {value["receipt"]["id"]: value["receipt"]},
        )

    forged = copy.deepcopy(value["artifact"])
    forged["payload"]["module_id"] = "MOD-OTHER"
    with pytest.raises(ExecutionError, match="id|producer|payload"):
        validate_module_run(
            value["run"],
            contract,
            {forged["id"]: forged},
            {value["receipt"]["id"]: value["receipt"]},
        )


def test_gate_pass_is_derived_from_runs_outputs_and_receipts() -> None:
    manifest, plan, selection, _, value = _fixture()
    results = derive_gate_results(
        manifest,
        plan,
        selection,
        [value["run"]],
        [value["artifact"]],
        [value["receipt"]],
    )
    by_gate = {item["gate"]: item for item in results}
    assert by_gate["HG-P"]["state"] == "pass"
    assert by_gate["HG-V"]["state"] == "unknown"


def test_missing_validation_receipt_cannot_produce_pass() -> None:
    manifest, plan, selection, _, value = _fixture()
    run = copy.deepcopy(value["run"])
    run["validation_receipt_refs"] = []
    results = derive_gate_results(manifest, plan, selection, [run], [value["artifact"]], [])
    assert next(item for item in results if item["gate"] == "HG-P")["state"] == "unknown"


def test_gate_aggregator_rejects_tampered_activation_plan() -> None:
    manifest, plan, selection, _, value = _fixture()
    tampered = copy.deepcopy(plan)
    tampered["gates"] = [
        {**gate, "activation_state": "inactive"} if gate["id"] == "HG-P" else gate
        for gate in tampered["gates"]
    ]
    with pytest.raises(ExecutionError, match="canonical activation plan"):
        derive_gate_results(manifest, tampered, selection, [value["run"]], [value["artifact"]], [value["receipt"]])


def test_provider_bound_runner_emits_and_validates_typed_module_run() -> None:
    _, _, _, contract, value = _fixture()

    def provider(invocation):
        assert invocation["module_id"] == contract["id"]
        return {
            "status": "completed",
            "result": {
                "gate_trace": ["HG-P"],
                "state": "pass",
                "evidence_refs": [value["receipt"]["id"]],
            },
            "outputs": [
                {
                    "output_id": "module_decision",
                    "schema_ref": "https://vheatm.dev/schemas/module-decision.schema.json",
                    "payload": {
                        "module_id": contract["id"],
                        "module_run_id": "provider-filled",
                        "gate_trace": ["HG-P"],
                        "state": "pass",
                        "evidence_refs": [value["receipt"]["id"]],
                    },
                    "taint_state": "validated",
                }
            ],
        }

    result = run_module(
        contract,
        module_digest="a" * 64,
        instruction_digest=contract["contract"]["disclosure"]["instruction_sha256"],
        context={"mode": "standard"},
        validation_receipts={value["receipt"]["id"]: value["receipt"]},
        provider=provider,
        started_at="2026-08-01T03:00:00Z",
        finished_at="2026-08-01T03:00:01Z",
    )
    assert result["run"]["id"].startswith("RUN-")
    assert len(result["run"]["id"].split("-", 1)[1]) == 64
    assert len(result["artifacts"]) == 1
