from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from .lifecycle import AuditLifecycle, LifecycleError
from .module_router import ModuleRoutingError, load_and_route
from .bundle import build_bundle, resolve_control_root
from .provenance import ProvenanceError, ProvenanceRegistry
from .evaluator import PlanIntegrityError, assert_plan_matches
from .execution import ExecutionError, derive_gate_results, expected_artifact_id, selection_digest
from .serialization import load_document


@dataclass(frozen=True)
class ReportIssue:
    source: str
    message: str


def canonical_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def report_subject_digest(report: Mapping[str, Any]) -> str:
    return canonical_digest({key: value for key, value in report.items() if key != "attestation"})


def record_collection_digest(records: Any) -> str:
    """Digest a typed record collection in deterministic ID order."""

    if not isinstance(records, list):
        raise ValueError("record collection must be an array")
    if not all(isinstance(record, Mapping) for record in records):
        raise ValueError("record collection entries must be objects")
    normalized = sorted(
        (dict(record) for record in records if isinstance(record, Mapping)),
        key=lambda record: str(record.get("id", "")),
    )
    return canonical_digest(normalized)


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid RFC3339 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed.astimezone(UTC)


def _normalize_text(value: str) -> str:
    return " ".join(value.split())


def derive_cycle_status(plan: Mapping[str, Any], gate_results: Mapping[str, str], findings: list[Mapping[str, Any]]) -> str:
    plan_gates = {str(gate["id"]): str(gate["activation_state"]) for gate in plan.get("gates", [])}
    if any(state == "unknown" for state in plan_gates.values()):
        return "blocked"
    for gate_id, activation_state in plan_gates.items():
        result = gate_results.get(gate_id)
        if activation_state == "active" and result in {None, "fail", "unknown", "not_applicable"}:
            return "blocked"
        if activation_state == "inactive" and result != "not_applicable":
            return "blocked"
    for finding in findings:
        if finding.get("priority") != "mandatory":
            continue
        disposition = finding.get("disposition", {}).get("state")
        epistemic = finding.get("epistemic_status")
        if disposition == "remediated" and epistemic != "verified":
            return "partial"
        if disposition == "false_positive" and epistemic not in {"verified", "contradicted"}:
            return "partial"
        if disposition not in {"remediated", "false_positive"}:
            return "partial"
    return "complete"


def validate_report_semantics(
    *,
    manifest: Mapping[str, Any],
    policy: Mapping[str, Any],
    report: Mapping[str, Any],
    now: datetime | None = None,
    canonical_selection: Mapping[str, Any] | None = None,
    bundle_root: str | None = None,
) -> list[ReportIssue]:
    issues: list[ReportIssue] = []
    manifest_version = manifest.get("framework", {}).get("version")
    if report.get("framework_version") != manifest_version:
        issues.append(ReportIssue("framework_version", "report version must equal canonical manifest version"))

    plan = report.get("activation_plan")
    if not isinstance(plan, Mapping):
        issues.append(ReportIssue("activation_plan", "final reports require an activation plan"))
        return issues
    if plan.get("framework_version") != manifest_version:
        issues.append(ReportIssue("activation_plan", "plan framework version must equal canonical manifest version"))
    try:
        recomputed_plan = assert_plan_matches(manifest, plan, require_binding=True, bundle_root=bundle_root)
    except PlanIntegrityError as exc:
        recomputed_plan = None
        issues.append(ReportIssue("activation_plan", str(exc)))

    manifest_gates = {str(gate["id"]): gate for gate in manifest.get("gates", {}).get("items", [])}
    plan_entries = plan.get("gates", [])
    if not isinstance(plan_entries, list):
        issues.append(ReportIssue("activation_plan.gates", "plan gates must be an array"))
        return issues
    plan_by_id: dict[str, Mapping[str, Any]] = {}
    for entry in plan_entries:
        if not isinstance(entry, Mapping):
            issues.append(ReportIssue("activation_plan.gates", "every plan gate must be an object"))
            continue
        gate_id = str(entry.get("id", ""))
        if gate_id in plan_by_id:
            issues.append(ReportIssue("activation_plan.gates", f"duplicate gate: {gate_id}"))
        plan_by_id[gate_id] = entry
    if set(plan_by_id) != set(manifest_gates):
        issues.append(
            ReportIssue(
                "activation_plan.gates",
                f"plan gate set mismatch: missing={sorted(set(manifest_gates) - set(plan_by_id))} extra={sorted(set(plan_by_id) - set(manifest_gates))}",
            )
        )
    for gate_id, entry in plan_by_id.items():
        canonical = manifest_gates.get(gate_id)
        if canonical is None:
            continue
        for field in ("layer", "phase", "activation"):
            if entry.get(field) != canonical.get(field):
                issues.append(ReportIssue(f"activation_plan.{gate_id}", f"{field} does not match manifest"))
        if recomputed_plan is not None:
            expected_entry = next(item for item in recomputed_plan["gates"] if item["id"] == gate_id)
            if entry.get("activation_state") != expected_entry.get("activation_state"):
                issues.append(ReportIssue(f"activation_plan.{gate_id}", "activation_state does not match recomputed plan"))

    counts = {"active": 0, "inactive": 0, "unknown": 0}
    for entry in plan_by_id.values():
        state = entry.get("activation_state")
        if state in counts:
            counts[str(state)] += 1
    summary = plan.get("summary", {})
    for key, value in counts.items():
        if summary.get(key) != value:
            issues.append(ReportIssue("activation_plan.summary", f"{key} must be derived as {value}"))
    if summary.get("total") != len(plan_by_id):
        issues.append(ReportIssue("activation_plan.summary", "total must equal plan gate count"))
    if summary.get("completion_blocked") is not (counts["unknown"] > 0):
        issues.append(ReportIssue("activation_plan.summary", "completion_blocked must equal unknown > 0"))

    context = plan.get("context", {})
    if report.get("mode") != context.get("mode"):
        issues.append(ReportIssue("mode", "report mode must match activation context"))
    if report.get("target_tier") != context.get("target_tier"):
        issues.append(ReportIssue("target_tier", "report tier must match activation context"))
    if report.get("declarations") != context.get("declarations"):
        issues.append(ReportIssue("declarations", "report declarations must match activation context"))

    raw_results = report.get("gate_results", [])
    results: dict[str, str] = {}
    result_documents: dict[str, Mapping[str, Any]] = {}
    if not isinstance(raw_results, list):
        issues.append(ReportIssue("gate_results", "gate_results must be an array"))
        raw_results = []
    for result in raw_results:
        if not isinstance(result, Mapping):
            issues.append(ReportIssue("gate_results", "every gate result must be an object"))
            continue
        gate_id = str(result.get("gate", ""))
        if gate_id in results:
            issues.append(ReportIssue("gate_results", f"duplicate gate result: {gate_id}"))
        results[gate_id] = str(result.get("state", ""))
        result_documents[gate_id] = result
    if set(results) != set(manifest_gates):
        issues.append(
            ReportIssue(
                "gate_results",
                f"result gate set mismatch: missing={sorted(set(manifest_gates) - set(results))} extra={sorted(set(results) - set(manifest_gates))}",
            )
        )
    for gate_id, entry in plan_by_id.items():
        activation = entry.get("activation_state")
        result = results.get(gate_id)
        if activation == "inactive" and result != "not_applicable":
            issues.append(ReportIssue(f"gate_results.{gate_id}", "inactive gates must be not_applicable"))
        elif activation == "unknown" and result != "unknown":
            issues.append(ReportIssue(f"gate_results.{gate_id}", "unknown activation must produce unknown result"))
        elif activation == "active" and result not in {"pass", "fail", "unknown"}:
            issues.append(ReportIssue(f"gate_results.{gate_id}", "active gates require pass/fail/unknown result"))

    execution = report.get("execution")
    derived_execution_results: list[Mapping[str, Any]] | None = None
    execution_artifact_records: dict[str, Mapping[str, Any]] = {}
    execution_receipt_records: dict[str, Mapping[str, Any]] = {}
    if not isinstance(execution, Mapping):
        issues.append(ReportIssue("execution", "reports require typed module execution records"))
    else:
        module_selection = execution.get("module_selection")
        if execution.get("plan_id") != plan.get("plan_id"):
            issues.append(ReportIssue("execution.plan_id", "execution must bind to activation_plan.plan_id"))
        if not isinstance(module_selection, Mapping):
            issues.append(ReportIssue("execution.module_selection", "execution requires a module selection"))
        elif execution.get("selection_digest") != selection_digest(module_selection):
            issues.append(ReportIssue("execution.selection_digest", "selection_digest does not match module selection"))
        if canonical_selection is not None and isinstance(module_selection, Mapping):
            if selection_digest(module_selection) != selection_digest(canonical_selection):
                issues.append(ReportIssue("execution.module_selection", "module selection does not match canonical routing"))
        raw_execution_artifacts = execution.get("artifacts", [])
        if isinstance(raw_execution_artifacts, list):
            execution_artifact_records = {str(item.get("id")): item for item in raw_execution_artifacts if isinstance(item, Mapping)}
        raw_execution_receipts = execution.get("validation_receipts", [])
        if isinstance(raw_execution_receipts, list):
            execution_receipt_records = {str(item.get("id")): item for item in raw_execution_receipts if isinstance(item, Mapping)}
        for field, digest_field in (
            ("module_runs", "module_runs_digest"),
            ("artifacts", "artifacts_digest"),
            ("validation_receipts", "validation_receipts_digest"),
        ):
            try:
                expected_digest = record_collection_digest(execution.get(field))
            except ValueError as exc:
                issues.append(ReportIssue(f"execution.{field}", str(exc)))
            else:
                if execution.get(digest_field) != expected_digest:
                    issues.append(ReportIssue(f"execution.{digest_field}", f"{digest_field} does not match typed records"))
        try:
            derived_execution_results = derive_gate_results(
                manifest,
                plan,
                module_selection if isinstance(module_selection, Mapping) else {},
                execution.get("module_runs", []),
                execution.get("artifacts", []),
                execution.get("validation_receipts", []),
            )
        except (ExecutionError, TypeError, AttributeError) as exc:
            issues.append(ReportIssue("execution", str(exc)))

    if derived_execution_results is not None:
        derived_by_gate = {str(item["gate"]): item for item in derived_execution_results}
        for gate_id, declared_state in results.items():
            derived = derived_by_gate.get(gate_id)
            if derived is None:
                issues.append(ReportIssue(f"gate_results.{gate_id}", "gate has no derived execution result"))
                continue
            if declared_state != derived.get("state"):
                issues.append(
                    ReportIssue(
                        f"gate_results.{gate_id}",
                        f"declared gate state {declared_state!r} does not match derived execution state {derived.get('state')!r}",
                    )
                )
            if declared_state == "pass" and set(result_documents[gate_id].get("evidence_refs", [])) != set(derived.get("evidence_refs", [])):
                issues.append(ReportIssue(f"gate_results.{gate_id}", "passing evidence_refs must be derived from module output"))

    provenance_document = report.get("provenance")
    registry: ProvenanceRegistry | None = None
    if not isinstance(provenance_document, Mapping):
        issues.append(ReportIssue("provenance", "final reports require a provenance registry"))
    else:
        try:
            registry = ProvenanceRegistry(provenance_document)
        except ProvenanceError as exc:
            issues.append(ReportIssue("provenance", str(exc)))

    source_ids = set()
    source_records: dict[str, Mapping[str, Any]] = {}
    validation_receipt_records: dict[str, Mapping[str, Any]] = {}
    claim_records: dict[str, Mapping[str, Any]] = {}
    if registry is not None:
        normalized = registry.to_document()
        source_records = {str(source["id"]): source for source in normalized["sources"]}
        source_ids = set(source_records)
        validation_receipt_records = {
            str(receipt["id"]): receipt for receipt in normalized.get("validation_receipts", [])
        }
        claim_records = {str(claim["id"]): claim for claim in normalized["claims"]}

    def validate_claim_trust(claim: Mapping[str, Any], source: str) -> None:
        claim_source_refs = set(str(ref) for ref in claim.get("source_refs", []))
        tainted_sources = {
            ref for ref in claim_source_refs if source_records.get(ref, {}).get("taint_state") == "tainted"
        }
        if not tainted_sources:
            return
        receipt_refs = set(str(ref) for ref in claim.get("validation_receipt_refs", []))
        if not receipt_refs:
            issues.append(ReportIssue(source, "verified evidence over tainted sources requires a validation receipt"))
            return
        valid_receipts: set[str] = set()
        for receipt_ref in sorted(receipt_refs):
            receipt = validation_receipt_records.get(receipt_ref)
            if receipt is None:
                issues.append(ReportIssue(source, f"unknown validation receipt: {receipt_ref}"))
                continue
            if receipt.get("result") != "validated":
                issues.append(ReportIssue(source, f"validation receipt is not successful: {receipt_ref}"))
                continue
            receipt_sources = set(str(ref) for ref in receipt.get("source_refs", []))
            if not tainted_sources.issubset(receipt_sources):
                issues.append(ReportIssue(source, f"validation receipt does not cover tainted sources: {receipt_ref}"))
                continue
            valid_receipts.add(receipt_ref)
        if not valid_receipts:
            issues.append(ReportIssue(source, "verified evidence has no successful validation receipt"))

    for gate_id, state in results.items():
        if state != "pass":
            continue
        refs = set(result_documents.get(gate_id, {}).get("evidence_refs", []))
        if not refs:
            issues.append(ReportIssue(f"gate_results.{gate_id}", "passing active gates require evidence_refs"))
            continue
        unknown_refs = sorted(
            ref
            for ref in refs
            if ref not in source_records
            and ref not in claim_records
            and ref not in execution_receipt_records
            and ref not in execution_artifact_records
        )
        if unknown_refs:
            issues.append(ReportIssue(f"gate_results.{gate_id}", f"unknown evidence refs: {unknown_refs}"))
        for ref in refs:
            if ref in source_records and source_records[ref].get("taint_state") == "tainted":
                issues.append(ReportIssue(f"gate_results.{gate_id}", f"passing gate references tainted source: {ref}"))
            claim = claim_records.get(ref)
            if claim is not None and claim.get("epistemic_status") != "verified":
                issues.append(ReportIssue(f"gate_results.{gate_id}", f"passing gate references non-verified claim: {ref}"))
            if claim is not None and claim.get("epistemic_status") == "verified":
                validate_claim_trust(claim, f"gate_results.{gate_id}")
            receipt = execution_receipt_records.get(ref)
            if receipt is not None and receipt.get("result") != "validated":
                issues.append(ReportIssue(f"gate_results.{gate_id}", f"passing gate references unsuccessful validation receipt: {ref}"))
            artifact = execution_artifact_records.get(ref)
            if artifact is not None:
                if artifact.get("id") != expected_artifact_id(artifact):
                    issues.append(ReportIssue(f"gate_results.{gate_id}", f"artifact evidence id does not match content: {ref}"))
                if artifact.get("taint_state") not in {"validated", "human_approved"}:
                    issues.append(ReportIssue(f"gate_results.{gate_id}", f"passing gate references tainted artifact: {ref}"))
                artifact_receipts = set(str(item) for item in artifact.get("validation_receipt_refs", []))
                if not artifact_receipts or not any(
                    execution_receipt_records.get(receipt_ref, {}).get("result") == "validated"
                    for receipt_ref in artifact_receipts
                ):
                    issues.append(ReportIssue(f"gate_results.{gate_id}", f"artifact evidence lacks a successful validation receipt: {ref}"))

    findings = report.get("findings", [])
    if not isinstance(findings, list):
        issues.append(ReportIssue("findings", "findings must be an array"))
        findings = []
    for finding in findings:
        if not isinstance(finding, Mapping):
            issues.append(ReportIssue("findings", "every finding must be an object"))
            continue
        finding_id = str(finding.get("id", "<unknown>"))
        unknown_trace = sorted(set(finding.get("gate_trace", [])) - set(manifest_gates))
        if unknown_trace:
            issues.append(ReportIssue(f"finding.{finding_id}", f"gate_trace references unknown gates: {unknown_trace}"))
        evidence_items = finding.get("evidence", [])
        for index, evidence in enumerate(evidence_items if isinstance(evidence_items, list) else []):
            if not isinstance(evidence, Mapping):
                continue
            needs_provenance = finding.get("priority") == "mandatory" or finding.get("epistemic_status") == "verified" or evidence.get("verified") is True
            claim_id = evidence.get("claim_id")
            refs = set(evidence.get("source_refs", []))
            if needs_provenance and (not claim_id or not refs):
                issues.append(ReportIssue(f"finding.{finding_id}.evidence.{index}", "verified or mandatory evidence requires claim_id and source_refs"))
                continue
            if claim_id:
                claim_record = claim_records.get(str(claim_id))
                if claim_record is None:
                    issues.append(ReportIssue(f"finding.{finding_id}.evidence.{index}", f"unknown claim_id: {claim_id}"))
                else:
                    if _normalize_text(str(evidence.get("claim", ""))) != _normalize_text(str(claim_record.get("text", ""))):
                        issues.append(ReportIssue(f"finding.{finding_id}.evidence.{index}", "evidence claim text does not match claim registry"))
                    claim_refs = set(claim_record.get("source_refs", []))
                    if not claim_refs.issubset(refs):
                        issues.append(ReportIssue(f"finding.{finding_id}.evidence.{index}", "evidence source_refs do not cover claim source_refs"))
                    requires_verified_claim = finding.get("epistemic_status") == "verified" or evidence.get("verified") is True
                    if requires_verified_claim and claim_record.get("epistemic_status") != "verified":
                        issues.append(ReportIssue(f"finding.{finding_id}.evidence.{index}", "verified evidence requires a verified claim record"))
                    if requires_verified_claim:
                        validate_claim_trust(claim_record, f"finding.{finding_id}.evidence.{index}")
            missing_sources = sorted(refs - source_ids)
            if missing_sources:
                issues.append(ReportIssue(f"finding.{finding_id}.evidence.{index}", f"unknown source refs: {missing_sources}"))

    derived_status = derive_cycle_status(plan, results, findings)
    if report.get("cycle_status") != derived_status:
        issues.append(ReportIssue("cycle_status", f"declared status must equal derived status {derived_status!r}"))
    lifecycle_state = report.get("lifecycle_state")
    lifecycle_document = report.get("lifecycle")
    lifecycle: AuditLifecycle | None = None
    if not isinstance(lifecycle_document, Mapping):
        issues.append(ReportIssue("lifecycle", "final reports require a replayable lifecycle event log"))
    else:
        try:
            lifecycle = AuditLifecycle.from_document(lifecycle_document)
        except LifecycleError as exc:
            issues.append(ReportIssue("lifecycle", str(exc)))
    if lifecycle is not None and lifecycle_state != lifecycle.state:
        issues.append(ReportIssue("lifecycle_state", "lifecycle_state must equal replayed lifecycle state"))
    expected_states = {derived_status}
    if derived_status == "complete":
        expected_states = {"complete", "attested"}
    if lifecycle_state not in expected_states:
        issues.append(ReportIssue("lifecycle_state", f"lifecycle state is inconsistent with derived status {derived_status!r}"))

    attestation = report.get("attestation")
    if not isinstance(attestation, Mapping):
        issues.append(ReportIssue("attestation", "final report requires attestation"))
    else:
        try:
            validated_at = _parse_time(str(attestation.get("validated_at", "")))
            expires_at = _parse_time(str(attestation.get("expires_at", "")))
            if expires_at <= validated_at:
                issues.append(ReportIssue("attestation", "expires_at must be after validated_at"))
            if (now or datetime.now(UTC)).astimezone(UTC) >= expires_at:
                issues.append(ReportIssue("attestation", "attestation has expired"))
        except ValueError as exc:
            issues.append(ReportIssue("attestation", str(exc)))
        if attestation.get("manifest_digest") != canonical_digest(manifest):
            issues.append(ReportIssue("attestation", "manifest_digest does not match canonical manifest"))
        if attestation.get("policy_digest") != canonical_digest(policy):
            issues.append(ReportIssue("attestation", "policy_digest does not match runtime policy"))
        if attestation.get("subject_digest") != report_subject_digest(report):
            issues.append(ReportIssue("attestation", "subject_digest does not match report content"))
        if lifecycle_state == "attested" and derived_status != "complete":
            issues.append(ReportIssue("attestation", "only complete reports may be attested"))

    return issues


def _load_document(path: Path) -> dict[str, Any]:
    value = load_document(path)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain an object")
    return value


def _schema_registry(schema_dir: Path) -> Registry:
    registry = Registry()
    for path in sorted(schema_dir.glob("*.schema.json")):
        schema = _load_document(path)
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    return registry


def validate_report_file(root: Path, report_path: Path, *, now: datetime | None = None) -> list[ReportIssue]:
    manifest = _load_document(root / "manifests" / "vheatm-v17.yaml")
    policy = _load_document(root / "policies" / "runtime-boundaries.yaml")
    report = _load_document(report_path)
    schema = _load_document(root / "schemas" / "audit-report.schema.json")
    validator = Draft202012Validator(schema, registry=_schema_registry(root / "schemas"))
    issues: list[ReportIssue] = []
    for error in sorted(validator.iter_errors(report), key=lambda item: list(item.absolute_path)):
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        issues.append(ReportIssue("schema", f"{location}: {error.message}"))
    if not issues:
        canonical_selection: Mapping[str, Any] | None = None
        bundle_root = build_bundle(root)["bundle_root"]
        activation_plan = report.get("activation_plan")
        if isinstance(activation_plan, Mapping):
            try:
                canonical_selection = load_and_route(root, activation_plan)
            except (ModuleRoutingError, OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as exc:
                issues.append(ReportIssue("execution.module_selection", f"canonical routing failed: {exc}"))
        issues.extend(
            validate_report_semantics(
                manifest=manifest,
                policy=policy,
                report=report,
                now=now,
                canonical_selection=canonical_selection,
                bundle_root=bundle_root,
            )
        )
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a VHEATM report against canonical manifest, policy, plan, and provenance.")
    parser.add_argument("--root", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()
    try:
        issues = validate_report_file(resolve_control_root(args.root), args.report.resolve())
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as exc:
        issues = [ReportIssue("runtime", str(exc))]
    if args.as_json:
        print(json.dumps({"valid": not issues, "issues": [issue.__dict__ for issue in issues]}, indent=2))
    elif issues:
        for issue in issues:
            print(f"ERROR [{issue.source}] {issue.message}")
    else:
        print("VHEATM audit report validation passed.")
    return 1 if issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
