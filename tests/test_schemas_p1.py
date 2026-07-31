import json
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from vheatm_control.evaluator import evaluate_manifest
from vheatm_control.provenance import (
    ProvenanceRegistry,
    build_claim_record,
    build_source_record,
    sha256_digest,
)

ROOT = Path(__file__).resolve().parents[1]


def registry() -> Registry:
    value = Registry()
    for path in sorted((ROOT / "schemas").glob("*.schema.json")):
        schema = json.loads(path.read_text())
        value = value.with_resource(schema["$id"], Resource.from_contents(schema))
    return value


def validate(instance: object, schema_name: str) -> None:
    schema = json.loads((ROOT / "schemas" / schema_name).read_text())
    errors = list(Draft202012Validator(schema, registry=registry()).iter_errors(instance))
    assert errors == []


def test_gate_plan_matches_schema() -> None:
    manifest = yaml.safe_load((ROOT / "manifests" / "vheatm-v17.yaml").read_text())
    plan = evaluate_manifest(
        manifest,
        {
            "context_mode": "single",
            "mandatory_findings": 0,
            "blast_radius": 1,
            "write_chain_components": 1,
            "declarations": {
                "self_audit": "no",
                "ai_executor": "no",
                "async_worker": "no",
                "safety_critical": "no",
                "financial_path": "no"
            }
        },
    )
    validate(plan, "gate-plan.schema.json")


def test_registry_matches_schema() -> None:
    source = build_source_record(
        source_type="document",
        locator="docs/architecture.md#authority-boundaries",
        digest=sha256_digest("authority boundaries"),
        trust_zone="artifact_content",
        captured_at="2026-07-31T00:00:00Z",
    )
    claim = build_claim_record(
        text="Executable policy overrides prose.",
        epistemic_status="verified",
        confidence=1.0,
        source_refs=[source["id"]],
        evidence_kind="document",
    )
    value = ProvenanceRegistry()
    value.add_source(source)
    value.add_claim(claim)
    validate(value.to_document(), "provenance-registry.schema.json")
