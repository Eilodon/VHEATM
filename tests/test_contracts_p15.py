import json
from datetime import UTC, datetime
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from vheatm_control.lifecycle import AuditLifecycle
from vheatm_control.policy import ApprovalVerifier, PolicyEngine, request_digest, sign_approval_token
from vheatm_control.provenance import ProvenanceRegistry, build_claim_record, build_source_record

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
        "request_id": "REQ-1",
        "requester": "agent",
        "tool_class": "write",
        "scope": "workspace:/repo:file",
        "diff_paths": ["file"],
        "rollback_plan": "restore file",
    }
    token = sign_approval_token(
        {
            "requester": "agent",
            "tool_class": "write",
            "exact_scope": "workspace:/repo:file",
            "request_digest": request_digest(request),
            "issued_at": "2026-07-31T00:00:00Z",
            "expires_at": "2026-08-01T00:00:00Z",
            "approved_by": "human",
            "nonce": "one",
        },
        key=key,
        key_id="key-1",
    )
    policy = {"tools": {"classes": {name: {} for name in ["read", "execute", "write", "network", "secrets"]}}, "egress": {}}
    decision = PolicyEngine(policy, approval_verifier=ApprovalVerifier({"key-1": key})).authorize(
        request, approval_token=token, now=datetime(2026, 7, 31, 1, tzinfo=UTC)
    )
    validate(request, "tool-request.schema.json")
    validate(token, "approval-token.schema.json")
    validate(decision.to_document(), "policy-decision.schema.json")


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
