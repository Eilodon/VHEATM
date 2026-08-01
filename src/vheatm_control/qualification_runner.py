from __future__ import annotations

import argparse
import copy
import hashlib
import hmac
import json
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping

import yaml
from jsonschema import Draft202012Validator

from .bundle import build_bundle, resolve_control_root
from .evaluator import PlanIntegrityError, assert_plan_matches, evaluate_manifest
from .evaluation import validate_eval_corpus
from .execution import ExecutionError, run_module, selection_digest, validate_module_run
from .module_router import load_and_route, validate_module_repository
from .migration_capabilities import build_stakeholder_record, evaluate_signal_noise, migrate_legacy_output
from .overlay_capabilities import build_ai_rmf_overlay, build_assurance_maturity_delta, build_cross_cutting_scan, build_temporal_scan
from .provenance import ProvenanceError, ProvenanceRegistry, build_claim_record, build_source_record, build_validation_receipt
from .serialization import load_json, load_yaml
from .session_store import SessionStore
from .supply_chain import build_supply_chain_attestation
from .tool_broker import (
    BrokerCapabilities,
    InMemoryTokenLedger,
    ToolBroker,
    approval_signing_payload,
    expected_approval_token_id,
    request_digest,
)


class QualificationRunnerError(ValueError):
    """Raised when a seeded qualification run cannot be produced safely."""


RUNNER_ID = "vheatm.public-seeded-qualification"
RUNNER_VERSION = "1.0.0"
RUN_SCHEMA_VERSION = "1.0.0"
DEFAULT_OBSERVED_AT = "2026-08-01T00:00:00Z"
_LOW_RISK_CONTEXT = {
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
_POLICY_KEY = b"vheatm-public-seeded-runner-key"


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _method_digest(label: str) -> str:
    return _digest({"runner_id": RUNNER_ID, "runner_version": RUNNER_VERSION, "method": label})


def expected_qualification_run_id(run: Mapping[str, Any]) -> str:
    identity = {key: value for key, value in run.items() if key != "run_id"}
    return "QRL-" + _digest(identity).upper()


def _timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise QualificationRunnerError("qualification run timestamp must be RFC 3339") from exc
    if parsed.tzinfo is None:
        raise QualificationRunnerError("qualification run timestamp must include a timezone")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _load_yaml_object(path: Path) -> dict[str, Any]:
    try:
        value = load_yaml(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise QualificationRunnerError(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise QualificationRunnerError(f"{path} must contain an object")
    return value


def _case_result(
    case: Mapping[str, Any],
    *,
    observed: str,
    details: Mapping[str, Any],
    method: str,
    evidence_refs: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    expected = str(case["expected"])
    outcome = "pass" if observed == expected else "fail"
    return {
        "case_id": str(case["case_id"]),
        "family": str(case["family"]),
        "expected": expected,
        "observed": observed,
        "outcome": outcome,
        "details": dict(details),
        "method_digest": _method_digest(method),
        "evidence_refs": list(evidence_refs or (str(case["case_id"]),)),
    }


def _new_broker(root: Path, observed_at: str, *, commands: set[str] | None = None) -> ToolBroker:
    observed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    return ToolBroker.from_root(
        root,
        keyring={"runner-key": _POLICY_KEY},
        capabilities=BrokerCapabilities(exact_command_allowlist=frozenset(commands or set())),
        token_ledger=InMemoryTokenLedger(),
        clock=lambda: observed,
    )


def _build_approval_token(request: Mapping[str, Any], observed_at: str) -> dict[str, Any]:
    issued = datetime.fromisoformat(observed_at.replace("Z", "+00:00")) - timedelta(minutes=1)
    expires = issued + timedelta(minutes=10)
    token: dict[str, Any] = {
        "token_id": "APR-" + "0" * 64,
        "schema_version": "1.0.0",
        "requester": request["requester"],
        "tool_class": request["tool_class"],
        "exact_scope": request["scope"],
        "request_digest": request_digest(request),
        "issued_at": issued.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "expires_at": expires.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "approved_by": "operator:public-seeded-runner",
        "nonce": "public-seeded-runner-once",
        "single_use": True,
        "signature": {"algorithm": "hmac-sha256", "key_id": "runner-key", "value": "0" * 64},
    }
    token["token_id"] = expected_approval_token_id(token)
    token["signature"]["value"] = hmac.new(_POLICY_KEY, approval_signing_payload(token), hashlib.sha256).hexdigest()
    return token


def _authority_case(root: Path, manifest: Mapping[str, Any], case: Mapping[str, Any], observed_at: str, bundle_root: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    plan = evaluate_manifest(manifest, _LOW_RISK_CONTEXT, bundle_root=bundle_root)
    route_a = load_and_route(root, plan)
    route_b = load_and_route(root, plan)
    tampered = copy.deepcopy(plan)
    tampered["summary"]["active"] += 1
    try:
        assert_plan_matches(manifest, tampered, require_binding=True, bundle_root=bundle_root)
    except PlanIntegrityError as exc:
        rejected = True
        reason = str(exc)
    else:
        rejected = False
        reason = "tampered plan was accepted"
    result = _case_result(
        case,
        observed="reject" if rejected else "pass",
        details={
            "mutation_rejected": rejected,
            "rejection_reason": reason,
            "route_equivalent": selection_digest(route_a) == selection_digest(route_b),
        },
        method="authority-plan-integrity-and-route-equivalence-v1",
    )
    measurements = [
        {"metric": "mutation_rejection_rate", "value": 1 if rejected else 0, "sample_count": 1, "confidence_lower": 0, "method_digest": result["method_digest"], "evidence_refs": [case["case_id"]]},
        {"metric": "route_equivalence_rate", "value": 1 if selection_digest(route_a) == selection_digest(route_b) else 0, "sample_count": 1, "confidence_lower": 0, "method_digest": result["method_digest"], "evidence_refs": [case["case_id"]]},
    ]
    return result, measurements


def _context_case(manifest: Mapping[str, Any], case: Mapping[str, Any], bundle_root: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    incomplete = copy.deepcopy(_LOW_RISK_CONTEXT)
    incomplete["declarations"].pop("self_audit")
    plan = evaluate_manifest(manifest, incomplete, bundle_root=bundle_root)
    unknown = [gate for gate in plan["gates"] if gate["activation_state"] == "unknown"]
    diagnostic = any(gate.get("unknown_references") for gate in unknown)
    result = _case_result(
        case,
        observed="unknown" if unknown else "pass",
        details={"unknown_gate_count": len(unknown), "diagnostic_reference_present": diagnostic},
        method="context-unknown-not-false-v1",
    )
    return result, [
        {"metric": "false_inactive_count", "value": 0 if unknown else 1, "sample_count": 1, "confidence_lower": 0, "method_digest": result["method_digest"], "evidence_refs": [case["case_id"]]},
        {"metric": "unknown_diagnostic_rate", "value": 1 if diagnostic else 0, "sample_count": 1, "confidence_lower": 0, "method_digest": result["method_digest"], "evidence_refs": [case["case_id"]]},
    ]


def _determinism_case(root: Path, manifest: Mapping[str, Any], case: Mapping[str, Any], bundle_root: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    requested_runs = int(case.get("metrics", {}).get("runs", 0))
    if requested_runs < 1:
        raise QualificationRunnerError("determinism case must request at least one run")
    plan_digests: list[str] = []
    for _ in range(requested_runs):
        plan_digests.append(evaluate_manifest(manifest, _LOW_RISK_CONTEXT, bundle_root=bundle_root)["plan_digest"])
    first_plan = evaluate_manifest(manifest, _LOW_RISK_CONTEXT, bundle_root=bundle_root)
    selections = [selection_digest(load_and_route(root, first_plan)) for _ in range(2)]
    plan_stable = len(set(plan_digests)) == 1
    selection_stable = len(set(selections)) == 1
    result = _case_result(
        case,
        observed="pass" if plan_stable and selection_stable else "fail",
        details={"evaluation_runs": requested_runs, "unique_plan_digests": len(set(plan_digests)), "route_runs": len(selections), "unique_selection_digests": len(set(selections))},
        method="deterministic-plan-and-router-replay-v1",
    )
    method = result["method_digest"]
    return result, [
        {"metric": "determinism_runs", "value": requested_runs, "sample_count": requested_runs, "confidence_lower": 0, "method_digest": method, "evidence_refs": [case["case_id"]]},
        {"metric": "plan_digest_stability_rate", "value": 1 if plan_stable else 0, "sample_count": requested_runs, "confidence_lower": 0, "method_digest": method, "evidence_refs": [case["case_id"]]},
        {"metric": "selection_digest_stability_rate", "value": 1 if selection_stable else 0, "sample_count": len(selections), "confidence_lower": 0, "method_digest": method, "evidence_refs": [case["case_id"]]},
    ]


def _typed_execution_case(root: Path, manifest: Mapping[str, Any], case: Mapping[str, Any], observed_at: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    plan = evaluate_manifest(manifest, _LOW_RISK_CONTEXT, bundle_root=build_bundle(root)["bundle_root"])
    selection = load_and_route(root, plan)
    module_issues, modules = validate_module_repository(root, manifest, module_schema=load_json((root / "schemas" / "module-contract.schema.json").read_text()), registry_schema=load_json((root / "schemas" / "module-registry.schema.json").read_text()))
    if module_issues or not selection.get("selected_modules"):
        raise QualificationRunnerError("typed execution case has no validated selected module")
    selected = selection["selected_modules"][0]
    module = modules[str(selected["id"])]
    source = build_source_record(source_type="seeded_case", locator=str(case["case_id"]), content="typed-execution-evidence", trust_zone="artifact_content", captured_at=observed_at)
    receipt = build_validation_receipt(source_refs=[source["id"]], validator=RUNNER_ID, method="typed-execution-fixture-v1", input_digest=source["digest"]["value"], validated_at=observed_at)

    def provider(invocation: Mapping[str, Any]) -> Mapping[str, Any]:
        return {"status": "completed", "result": {"gate_trace": [str(module.document["gate_coverage"][0])], "state": "pass", "evidence_refs": [receipt["id"]]}, "outputs": [{"output_id": "module_decision", "schema_ref": "https://vheatm.dev/schemas/module-decision.schema.json", "payload": {"module_id": module.id, "module_run_id": "provider-filled", "gate_trace": [str(module.document["gate_coverage"][0])], "state": "pass", "evidence_refs": [receipt["id"]]}, "taint_state": "validated"}]}

    execution = run_module(module.document, module_digest=module.digest, instruction_digest=module.instruction_digest, context=_LOW_RISK_CONTEXT, validation_receipts={receipt["id"]: receipt}, provider=provider, started_at=observed_at, finished_at=observed_at)
    forged = copy.deepcopy(execution["run"])
    forged["id"] = "RUN-" + "0" * 64
    try:
        validate_module_run(forged, module.document, {item["id"]: item for item in execution["artifacts"]}, {receipt["id"]: receipt})
    except ExecutionError as exc:
        rejected = True
        reason = str(exc)
    else:
        rejected = False
        reason = "forged module run was accepted"
    result = _case_result(case, observed="reject" if rejected else "pass", details={"forgery_rejected": rejected, "rejection_reason": reason, "run_id": execution["run"]["id"]}, method="typed-module-run-identity-v1")
    return result, [
        {"metric": "forgery_rejection_rate", "value": 1 if rejected else 0, "sample_count": 1, "confidence_lower": 0, "method_digest": result["method_digest"], "evidence_refs": [case["case_id"]]},
        {"metric": "unrelated_pass_claims", "value": 0 if rejected else 1, "sample_count": 1, "confidence_lower": 0, "method_digest": result["method_digest"], "evidence_refs": [case["case_id"]]},
    ]


def _evidence_case(case: Mapping[str, Any], observed_at: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    source = build_source_record(source_type="seeded_case", locator=str(case["case_id"]), content="lineage-source", trust_zone="artifact_content", captured_at=observed_at)
    registry = ProvenanceRegistry()
    registry.add_source(source, actor=RUNNER_ID, occurred_at=observed_at)
    parent = build_claim_record(text="parent evidence", epistemic_status="candidate", confidence=0.5, source_refs=[source["id"]], evidence_kind="seeded")
    registry.add_claim(parent, actor=RUNNER_ID, occurred_at=observed_at)
    child = build_claim_record(text="child evidence", epistemic_status="candidate", confidence=0.5, source_refs=[source["id"]], evidence_kind="seeded", lineage_refs=[parent["id"]])
    registry.add_claim(child, actor=RUNNER_ID, occurred_at=observed_at)
    forged = copy.deepcopy(child)
    forged["lineage_refs"] = []
    try:
        registry.add_claim(forged, actor=RUNNER_ID, occurred_at=observed_at)
    except ProvenanceError as exc:
        blocked = True
        reason = str(exc)
    else:
        blocked = False
        reason = "lineage removal was accepted"
    result = _case_result(case, observed="block" if blocked else "pass", details={"lineage_removal_blocked": blocked, "rejection_reason": reason}, method="provenance-lineage-integrity-v1")
    return result, [{"metric": "high_critical_lineage_rate", "value": 1 if blocked else 0, "sample_count": 1, "confidence_lower": 0, "method_digest": result["method_digest"], "evidence_refs": [case["case_id"]]}]


def _security_case(root: Path, case: Mapping[str, Any], observed_at: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    broker = _new_broker(root, observed_at)
    request = {"schema_version": "1.0.0", "request_id": "REQ-UNAUTHORIZED-SEEDED", "requester": RUNNER_ID, "tool_class": "admin", "scope": "workspace:"}
    decision = broker.evaluate(request)
    rejected = decision["decision"] == "deny"
    result = _case_result(case, observed="reject" if rejected else "pass", details={"decision": decision["decision"], "controls": decision.get("controls", [])}, method="broker-unauthorized-tool-class-v1")
    return result, [{"metric": "unauthorized_block_rate", "value": 1 if rejected else 0, "sample_count": 1, "confidence_lower": 0, "method_digest": result["method_digest"], "evidence_refs": [case["case_id"]]}]


def _policy_case(root: Path, case: Mapping[str, Any], observed_at: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    broker = _new_broker(root, observed_at, commands={"true"})
    request = {"schema_version": "1.0.0", "request_id": "REQ-APPROVAL-SEEDED", "requester": RUNNER_ID, "tool_class": "execute", "scope": "workspace:", "workspace_path": str(root), "sandboxed": True, "command": "true", "network_enabled": False, "inherit_secrets": False}
    token = _build_approval_token(request, observed_at)
    first = broker.evaluate(request, token)
    second = broker.evaluate(request, token)
    replay_rejected = first["decision"] == "allow" and second["decision"] == "deny"
    result = _case_result(case, observed="reject" if replay_rejected else "pass", details={"first_decision": first["decision"], "replay_decision": second["decision"], "replay_blocked": replay_rejected}, method="single-use-approval-replay-v1")
    return result, []


def _recovery_case(case: Mapping[str, Any], observed_at: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    with tempfile.TemporaryDirectory(prefix="vheatm-seeded-recovery-") as directory:
        store = SessionStore(Path(directory))
        session_id = store.create_session(context_digest="a" * 64, bundle_root="b" * 64, session_root="c" * 64, created_at=observed_at)
        first = store.append_event(session_id, event_type="module_started", actor=RUNNER_ID, data={"case_id": case["case_id"]}, idempotency_key="seeded:module-start", occurred_at=observed_at)
        duplicate = store.append_event(session_id, event_type="module_started", actor=RUNNER_ID, data={"case_id": case["case_id"]}, idempotency_key="seeded:module-start", occurred_at=observed_at)
        resumed = store.resume(session_id, expected_session_root="c" * 64)
        duplicate_effects = 0 if duplicate == first and len(resumed["events"]) == 2 else 1
        digest_match = resumed["last_event_hash"] == duplicate["event_hash"] and resumed["events"][-1]["event_hash"] == duplicate["event_hash"]
    result = _case_result(case, observed="pass" if duplicate_effects == 0 and digest_match else "fail", details={"duplicate_effects": duplicate_effects, "resume_digest_match": digest_match, "journal_events": 2}, method="session-journal-idempotent-recovery-v1")
    return result, [
        {"metric": "duplicate_effect_count", "value": duplicate_effects, "sample_count": 1, "confidence_lower": 0, "method_digest": result["method_digest"], "evidence_refs": [case["case_id"]]},
        {"metric": "resume_digest_match_rate", "value": 1 if digest_match else 0, "sample_count": 1, "confidence_lower": 0, "method_digest": result["method_digest"], "evidence_refs": [case["case_id"]]},
    ]


def _privacy_case(root: Path, case: Mapping[str, Any], observed_at: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    broker = _new_broker(root, observed_at)
    request = {"schema_version": "1.0.0", "request_id": "REQ-SECRET-CANARY-SEEDED", "requester": RUNNER_ID, "tool_class": "read", "scope": "workspace:", "workspace_path": str(root), "secret_expansion": False, "contains_secrets": True}
    decision = broker.evaluate(request)
    blocked = decision["decision"] == "deny"
    result = _case_result(case, observed="block" if blocked else "pass", details={"secret_canary_blocked": blocked, "decision": decision["decision"], "secret_output_emitted": False}, method="secret-canary-broker-boundary-v1")
    return result, [{"metric": "secret_pii_leakage_count", "value": 0 if blocked else 1, "sample_count": 1, "confidence_lower": 0, "method_digest": result["method_digest"], "evidence_refs": [case["case_id"]]}]


def _supply_chain_case(root: Path, case: Mapping[str, Any], observed_at: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    attestation = build_supply_chain_attestation(root, generated_at=observed_at)
    blocked = attestation.get("signed_release") is False and attestation.get("verification_state") == "partial"
    result = _case_result(case, observed="block" if blocked else "pass", details={"signed_release": attestation.get("signed_release"), "verification_state": attestation.get("verification_state"), "unsigned_release_blocked": blocked}, method="unsigned-supply-chain-release-boundary-v1")
    return result, []


def _migration_case(root: Path, case: Mapping[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    case_id = str(case["case_id"])
    if case_id == "EVC-SIGNAL-NOISE-UNKNOWN":
        decision = evaluate_signal_noise(
            {
                "hypothesis_id": case_id,
                "original_priority": "required",
                "worst_case": {"description": "unknown migration signal", "probability": "unknown"},
                "security_implication": None,
                "monitorable": None,
                "time_to_detect_hours": None,
                "time_to_fix_hours": None,
            },
            mode="standard",
            root=root,
        )
        observed = "unknown" if decision["status"] == "unknown" and decision["verdict"] is None else "pass"
        details = {"status": decision["status"], "verdict": decision["verdict"], "diagnostics": decision["diagnostics"]}
        method = "signal-noise-unknown-preservation-v1"
    elif case_id == "EVC-LEGACY-OUTPUT-TAINT":
        migrated = migrate_legacy_output({"context": {"mode": "DESIGN"}}, mode="FAST", root=root)
        observed = "block" if migrated["status"] == "unknown" and not migrated["authority_eligible"] and migrated["taint_state"] == "tainted" else "pass"
        details = {"status": migrated["status"], "missing_sections": migrated["missing_sections"], "authority_eligible": migrated["authority_eligible"], "taint_state": migrated["taint_state"]}
        method = "legacy-output-taint-boundary-v1"
    elif case_id == "EVC-STAKEHOLDER-OWNER-BLOCK":
        record = build_stakeholder_record({"context_mode": "enterprise", "goal": "seeded release", "stakeholder": "security"}, primary_role="security", root=root)
        observed = "block" if record["status"] == "unknown" and "ownership_map" in record["missing_requirements"] else "pass"
        details = {"status": record["status"], "missing_requirements": record["missing_requirements"], "authority_eligible": record["authority_eligible"]}
        method = "stakeholder-owner-map-boundary-v1"
    elif case_id == "EVC-CROSS-CUTTING-ENTERPRISE":
        record = build_cross_cutting_scan({"context_mode": "enterprise"}, active_subcategories=("L7.1", "L7.4"), root=root)
        obligation_ids = {item["id"] for item in record["obligations"]}
        observed = "pass" if record["status"] == "complete" and "L7.11" in obligation_ids else "fail"
        details = {"status": record["status"], "obligation_ids": sorted(obligation_ids), "authority_eligible": record["authority_eligible"]}
        method = "enterprise-cross-cutting-obligation-map-v1"
    elif case_id == "EVC-TEMPORAL-ORDER":
        record = build_temporal_scan(
            [
                {"snapshot_id": "SNAP-001", "captured_at": "2026-08-01T00:00:00Z", "digest": "a" * 64},
                {"snapshot_id": "SNAP-002", "captured_at": "2026-08-01T01:00:00Z", "digest": "b" * 64},
            ],
            mode="standard",
            root=root,
        )
        observed = "pass" if record["status"] == "complete" and len(record["sublayers"]) == 6 else "fail"
        details = {"status": record["status"], "snapshot_count": len(record["snapshots"]), "sublayer_count": len(record["sublayers"]), "authority_eligible": record["authority_eligible"]}
        method = "temporal-ordered-snapshot-boundary-v1"
    elif case_id == "EVC-AI-RMF-UNKNOWN":
        record = build_ai_rmf_overlay(
            {"declarations": {"ai_integrated": "yes"}},
            model=None,
            ai_inputs=(),
            ai_outputs=(),
            human_oversight_points=0,
            governance={},
            monitoring_coverage=None,
            root=root,
        )
        observed = "unknown" if record["status"] == "unknown" and not record["authority_eligible"] else "pass"
        details = {"status": record["status"], "missing_requirements": record["missing_requirements"], "authority_eligible": record["authority_eligible"]}
        method = "ai-rmf-unknown-preservation-v1"
    elif case_id == "EVC-ASSURANCE-DELTA":
        record = build_assurance_maturity_delta(
            [
                {
                    "finding_id": "FND-ASSURANCE-001",
                    "priority": "mandatory",
                    "finding_type": "MISSING_CONTROL",
                    "samm_function": "GOVERNANCE",
                    "samm_practice": "policy",
                    "ssdf_mapping": "PO.1",
                    "bsimm_baseline": False,
                    "improvement_recommendation": "assign an owner",
                    "priority_action": "IMMEDIATE",
                }
            ],
            root=root,
        )
        observed = "pass" if record["status"] == "complete" and record["claim_type"] == "delta_only" and not record["authority_eligible"] else "fail"
        details = {"status": record["status"], "claim_type": record["claim_type"], "delta_count": len(record["maturity_deltas"]), "authority_eligible": record["authority_eligible"]}
        method = "assurance-delta-only-boundary-v1"
    else:
        raise QualificationRunnerError(f"unknown migration case: {case_id}")
    result = _case_result(case, observed=observed, details=details, method=method)
    return result, []


def _run_case(root: Path, manifest: Mapping[str, Any], case: Mapping[str, Any], observed_at: str, bundle_root: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    family = str(case["family"])
    handlers = {
        "authority": lambda: _authority_case(root, manifest, case, observed_at, bundle_root),
        "context": lambda: _context_case(manifest, case, bundle_root),
        "determinism": lambda: _determinism_case(root, manifest, case, bundle_root),
        "typed_execution": lambda: _typed_execution_case(root, manifest, case, observed_at),
        "evidence": lambda: _evidence_case(case, observed_at),
        "security": lambda: _security_case(root, case, observed_at),
        "policy": lambda: _policy_case(root, case, observed_at),
        "recovery": lambda: _recovery_case(case, observed_at),
        "privacy": lambda: _privacy_case(root, case, observed_at),
        "supply_chain": lambda: _supply_chain_case(root, case, observed_at),
        "migration": lambda: _migration_case(root, case),
    }
    handler = handlers.get(family)
    if handler is None:
        raise QualificationRunnerError(f"no static handler is registered for eval family: {family}")
    return handler()


def run_seeded_corpus(root: Path, *, observed_at: str = DEFAULT_OBSERVED_AT) -> dict[str, Any]:
    root = resolve_control_root(root)
    observed_at = _timestamp(observed_at)
    manifest = _load_yaml_object(root / "manifests" / "vheatm-v17.yaml")
    corpus = _load_yaml_object(root / "evals" / "cases.yaml")
    schema = load_json((root / "schemas" / "eval-corpus.schema.json").read_text(encoding="utf-8"))
    issues = validate_eval_corpus(corpus, schema)
    if issues:
        raise QualificationRunnerError("seeded evaluation corpus is invalid: " + "; ".join(issues))
    case_ids = [str(case.get("case_id", "")) for case in corpus.get("cases", []) if isinstance(case, Mapping)]
    if len(case_ids) != len(set(case_ids)):
        raise QualificationRunnerError("seeded evaluation corpus contains duplicate case IDs")
    bundle_root = build_bundle(root)["bundle_root"]
    results: list[dict[str, Any]] = []
    measurements: list[dict[str, Any]] = []
    for case in corpus["cases"]:
        result, case_measurements = _run_case(root, manifest, case, observed_at, bundle_root)
        results.append(result)
        measurements.extend(case_measurements)
    if len(results) != len(corpus["cases"]):
        raise QualificationRunnerError("runner did not produce one result for every seeded case")
    if any(result["outcome"] != "pass" for result in results):
        status = "partial"
    else:
        status = "complete"
    run: dict[str, Any] = {
        "schema_version": RUN_SCHEMA_VERSION,
        "framework_version": str(manifest["framework"]["version"]),
        "bundle_root": bundle_root,
        "corpus_id": str(corpus["corpus_id"]),
        "corpus_version": str(corpus["corpus_version"]),
        "visibility": "public_seeded",
        "runner_id": RUNNER_ID,
        "runner_version": RUNNER_VERSION,
        "status": status,
        "evidence_state": "unverified",
        "case_results": results,
        "measurements": measurements,
        "generated_at": observed_at,
    }
    run["run_id"] = expected_qualification_run_id(run)
    run_schema = load_json((root / "schemas" / "qualification-run.schema.json").read_text(encoding="utf-8"))
    issues = validate_qualification_run(run, run_schema)
    if issues:
        raise QualificationRunnerError("runner emitted invalid typed evidence: " + "; ".join(issues))
    return run


def validate_qualification_run(run: Mapping[str, Any], schema: Mapping[str, Any]) -> list[str]:
    if not isinstance(run, Mapping):
        return ["run must be an object"]
    issues: list[str] = []
    for error in sorted(Draft202012Validator(dict(schema)).iter_errors(run), key=lambda item: list(item.absolute_path)):
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        issues.append(f"{location}: {error.message}")
    if not issues and run.get("run_id") != expected_qualification_run_id(run):
        issues.append("run_id does not match canonical run content")
    if not issues:
        case_ids = [str(item.get("case_id", "")) for item in run.get("case_results", []) if isinstance(item, Mapping)]
        metric_names = [str(item.get("metric", "")) for item in run.get("measurements", []) if isinstance(item, Mapping)]
        if len(case_ids) != len(set(case_ids)):
            issues.append("case_results contain duplicate case IDs")
        elif len(metric_names) != len(set(metric_names)):
            issues.append("measurements contain duplicate metric names")
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description="Execute the public seeded VHEATM qualification corpus without minting GA evidence.")
    parser.add_argument("--root", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--observed-at", default=DEFAULT_OBSERVED_AT)
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()
    try:
        run = run_seeded_corpus(resolve_control_root(args.root), observed_at=args.observed_at)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    rendered = json.dumps(run, indent=None if args.compact else 2, sort_keys=args.compact, ensure_ascii=False)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
