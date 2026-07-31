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
from .provenance import ProvenanceError, ProvenanceRegistry


@dataclass(frozen=True)
class ReportIssue:
    source: str
    message: str


def canonical_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def report_subject_digest(report: Mapping[str, Any]) -> str:
    return canonical_digest({key: value for key, value in report.items() if key != "attestation"})


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
    claim_records: dict[str, Mapping[str, Any]] = {}
    if registry is not None:
        normalized = registry.to_document()
        source_records = {str(source["id"]): source for source in normalized["sources"]}
        source_ids = set(source_records)
        claim_records = {str(claim["id"]): claim for claim in normalized["claims"]}

    for gate_id, state in results.items():
        if state != "pass":
            continue
        refs = set(result_documents.get(gate_id, {}).get("evidence_refs", []))
        if not refs:
            issues.append(ReportIssue(f"gate_results.{gate_id}", "passing active gates require evidence_refs"))
            continue
        unknown_refs = sorted(ref for ref in refs if ref not in source_records and ref not in claim_records)
        if unknown_refs:
            issues.append(ReportIssue(f"gate_results.{gate_id}", f"unknown evidence refs: {unknown_refs}"))
        for ref in refs:
            if ref in source_records and source_records[ref].get("taint_state") == "tainted":
                issues.append(ReportIssue(f"gate_results.{gate_id}", f"passing gate references tainted source: {ref}"))
            claim = claim_records.get(ref)
            if claim is not None and claim.get("epistemic_status") != "verified":
                issues.append(ReportIssue(f"gate_results.{gate_id}", f"passing gate references non-verified claim: {ref}"))

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
                        tainted = sorted(ref for ref in claim_refs if source_records.get(ref, {}).get("taint_state") == "tainted")
                        if tainted:
                            issues.append(ReportIssue(f"finding.{finding_id}.evidence.{index}", f"verified evidence references tainted sources: {tainted}"))
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
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle) if path.suffix.lower() == ".json" else yaml.safe_load(handle)
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
        issues.extend(validate_report_semantics(manifest=manifest, policy=policy, report=report, now=now))
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a VHEATM report against canonical manifest, policy, plan, and provenance.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()
    try:
        issues = validate_report_file(args.root.resolve(), args.report.resolve())
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
