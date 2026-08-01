import json
import hmac
from datetime import UTC, datetime
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from vheatm_control.lifecycle import AuditLifecycle
from vheatm_control.provenance import ProvenanceRegistry, build_claim_record, build_source_record
from vheatm_control.tool_broker import (
    BrokerCapabilities,
    InMemoryTokenLedger,
    ToolBroker,
    approval_signing_payload,
    expected_approval_token_id,
    request_digest,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"


def schema_registry() -> Registry:
    value = Registry()
    for path in sorted(SCHEMAS.glob("*.schema.json")):
        schema = json.loads(path.read_text())
        Draft202012Validator.check_schema(schema)
        value = value.with_resource(schema["$id"], Resource.from_contents(schema))
    return value


def validate(document: object, name: str) -> None:
    schema = json.loads((SCHEMAS / name).read_text())
    errors = list(Draft202012Validator(schema, registry=schema_registry()).iter_errors(document))
    assert errors == []


def test_all_p15_schemas_are_valid() -> None:
    assert len(list(SCHEMAS.glob("*.schema.json"))) >= 4
    schema_registry()


def test_lifecycle_document_matches_contract() -> None:
    lifecycle = AuditLifecycle("AUD-CONTRACT")
    lifecycle.transition("context_validated", actor="human", reason="context checked", occurred_at="2026-07-31T00:00:00Z")
    validate(lifecycle.to_document(), "audit-lifecycle.schema.json")


def test_approval_and_decision_match_contracts() -> None:
    key = b"test-key"
    request = {
        "schema_version": "1.0.0",
        "request_id": "REQ-1",
        "requester": "agent",
        "tool_class": "write",
        "scope": "workspace:repo",
        "diff_paths": ["repo/file"],
        "rollback_plan": "restore file",
    }
    token = {
        "token_id": "APR-" + "0" * 64,
        "schema_version": "1.0.0",
        "requester": "agent",
        "tool_class": "write",
        "exact_scope": request["scope"],
        "request_digest": request_digest(request),
        "issued_at": "2026-07-31T00:00:00Z",
        "expires_at": "2026-08-01T00:00:00Z",
        "approved_by": "human",
        "nonce": "one",
        "single_use": True,
        "signature": {"algorithm": "hmac-sha256", "key_id": "key-1", "value": "0" * 64},
    }
    token["token_id"] = expected_approval_token_id(token)
    token["signature"]["value"] = hmac.new(key, approval_signing_payload(token), "sha256").hexdigest()
    broker = ToolBroker.from_root(
        ROOT,
        keyring={"key-1": key},
        capabilities=BrokerCapabilities(),
        token_ledger=InMemoryTokenLedger(),
        clock=lambda: datetime(2026, 7, 31, 1, tzinfo=UTC),
    )
    decision = broker.evaluate(request, token)
    validate(request, "tool-request.schema.json")
    validate(token, "approval-token.schema.json")
    validate(decision, "policy-decision.schema.json")


def test_hardened_registry_matches_contract() -> None:
    source = build_source_record(
        source_type="document", locator="docs/x", content="x", trust_zone="artifact_content", captured_at="2026-07-31T00:00:00Z"
    )
    claim = build_claim_record(
        text="x is present", epistemic_status="verified", confidence=1.0, source_refs=[source["id"]], evidence_kind="document"
    )
    registry = ProvenanceRegistry()
    registry.add_source(source)
    registry.add_claim(claim)
    validate(registry.to_document(), "provenance-registry.schema.json")
