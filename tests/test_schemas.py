import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).parents[1]
SCHEMAS = ROOT / "schemas"


def load_json(path: Path):
    return json.loads(path.read_text())


def registry() -> Registry:
    result = Registry()
    for path in SCHEMAS.glob("*.schema.json"):
        schema = load_json(path)
        result = result.with_resource(schema["$id"], Resource.from_contents(schema))
    return result


@pytest.mark.parametrize("name", ["vheatm-manifest", "runtime-policy", "finding", "audit-report"])
def test_schemas_are_valid_draft_2020_12(name: str) -> None:
    Draft202012Validator.check_schema(load_json(SCHEMAS / f"{name}.schema.json"))


def test_valid_finding_parses() -> None:
    schema = load_json(SCHEMAS / "finding.schema.json")
    Draft202012Validator(schema, registry=registry()).validate(load_json(ROOT / "tests/fixtures/valid-finding.json"))


def test_unknown_epistemic_status_cannot_claim_confidence() -> None:
    schema = load_json(SCHEMAS / "finding.schema.json")
    instance = load_json(ROOT / "tests/fixtures/valid-finding.json")
    instance["epistemic_status"] = "unknown"
    instance["confidence"] = 0.8
    errors = list(Draft202012Validator(schema, registry=registry()).iter_errors(instance))
    assert errors


def test_valid_report_resolves_cross_schema_reference() -> None:
    schema = load_json(SCHEMAS / "audit-report.schema.json")
    Draft202012Validator(schema, registry=registry()).validate(load_json(ROOT / "tests/fixtures/valid-report.json"))
