from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any, Callable, Mapping, Sequence


class ExecutionError(ValueError):
    """Raised when typed module execution evidence is incomplete or forged."""


ModuleProvider = Callable[[Mapping[str, Any]], Mapping[str, Any]]


def _canonical_digest(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _content_id(prefix: str, value: Mapping[str, Any]) -> str:
    return f"{prefix}-{_canonical_digest(value).upper()}"


def _module_run_identity(run: Mapping[str, Any]) -> dict[str, Any]:
    """Return the non-circular invocation identity for a ModuleRun."""

    return {
        "module_id": run.get("module_id"),
        "module_digest": run.get("module_digest"),
        "instruction_digest": run.get("instruction_digest"),
        "status": run.get("status"),
        "started_at": run.get("started_at"),
        "input_artifact_refs": list(run.get("input_artifact_refs", [])),
        "validation_receipt_refs": list(run.get("validation_receipt_refs", [])),
    }


def expected_module_run_id(run: Mapping[str, Any]) -> str:
    return _content_id("RUN", _module_run_identity(run))


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _validate_run_times(run: Mapping[str, Any]) -> None:
    try:
        started = datetime.fromisoformat(str(run.get("started_at", "")).replace("Z", "+00:00"))
        finished = datetime.fromisoformat(str(run.get("finished_at", "")).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ExecutionError("module run timestamps must be RFC 3339 date-times") from exc
    if started.tzinfo is None or finished.tzinfo is None:
        raise ExecutionError("module run timestamps must include a timezone")
    if finished < started:
        raise ExecutionError("module run finished_at cannot precede started_at")


def run_module(
    contract: Mapping[str, Any],
    *,
    module_digest: str,
    instruction_digest: str,
    context: Mapping[str, Any],
    input_artifacts: Mapping[str, Mapping[str, Any]] | None = None,
    validation_receipts: Mapping[str, Mapping[str, Any]] | None = None,
    provider: ModuleProvider,
    started_at: str | None = None,
    finished_at: str | None = None,
) -> dict[str, Any]:
    """Run one typed provider boundary and validate its complete evidence envelope.

    The provider is deliberately injected by the caller. This function never
    interprets instruction text, invokes a shell, accesses a network, or writes
    files; those capabilities belong behind an independently governed adapter.
    """

    if not callable(provider):
        raise ExecutionError("module provider must be callable")
    module_id = str(contract.get("id", ""))
    if not module_id:
        raise ExecutionError("module contract requires an id")
    input_map = {str(key): deepcopy(dict(value)) for key, value in (input_artifacts or {}).items()}
    receipt_map = {str(key): deepcopy(dict(value)) for key, value in (validation_receipts or {}).items()}
    input_refs = sorted(input_map)
    receipt_refs = sorted(receipt_map)
    started = started_at or _utc_now()
    invocation = {
        "module_id": module_id,
        "module_digest": module_digest,
        "instruction_digest": instruction_digest,
        "context": deepcopy(dict(context)),
        "input_artifacts": deepcopy(input_map),
        "validation_receipts": deepcopy(receipt_map),
    }
    try:
        outcome = provider(invocation)
    except Exception as exc:  # provider failures become explicit typed failures
        outcome = {
            "status": "failed",
            "failure": {
                "code": "provider_error",
                "message": str(exc) or exc.__class__.__name__,
                "retryable": True,
            },
            "outputs": [],
        }
    if not isinstance(outcome, Mapping):
        raise ExecutionError("module provider must return an object")
    status = outcome.get("status")
    if status not in {"completed", "failed", "blocked"}:
        raise ExecutionError("module provider returned an invalid status")
    provisional_run: dict[str, Any] = {
        "id": "",
        "module_id": module_id,
        "module_digest": module_digest,
        "instruction_digest": instruction_digest,
        "status": status,
        "started_at": started,
        "finished_at": finished_at or _utc_now(),
        "input_artifact_refs": input_refs,
        "output_artifact_refs": [],
        "validation_receipt_refs": receipt_refs,
    }
    run_id = expected_module_run_id(provisional_run)
    provisional_run["id"] = run_id
    output_artifacts: list[dict[str, Any]] = []
    if status == "completed":
        result = outcome.get("result")
        if not isinstance(result, Mapping):
            raise ExecutionError("completed module provider output requires result")
        result = deepcopy(dict(result))
        result["module_id"] = module_id
        result["module_run_id"] = run_id
        provisional_run["result"] = result
        outputs = outcome.get("outputs", [])
        if not isinstance(outputs, list):
            raise ExecutionError("module provider outputs must be an array")
        for output in outputs:
            if not isinstance(output, Mapping):
                raise ExecutionError("module provider output descriptors must be objects")
            output_id = str(output.get("output_id", ""))
            schema_ref = str(output.get("schema_ref", ""))
            payload = output.get("payload")
            if not output_id or not isinstance(payload, Mapping):
                raise ExecutionError("module provider outputs require output_id and object payload")
            if output_id == "module_decision":
                comparable_payload = dict(payload)
                comparable_result = dict(result)
                comparable_payload.pop("module_id", None)
                comparable_payload.pop("module_run_id", None)
                comparable_result.pop("module_id", None)
                comparable_result.pop("module_run_id", None)
                if comparable_payload != comparable_result:
                    raise ExecutionError("module_decision output does not match provider result")
                payload = result
            output_artifacts.append(
                build_artifact_envelope(
                    producer_module_id=module_id,
                    producer_run_id=run_id,
                    output_id=output_id,
                    schema_ref=schema_ref,
                    payload=payload,
                    taint_state=str(output.get("taint_state", "tainted")),
                    source_refs=tuple(str(ref) for ref in output.get("source_refs", [])),
                    validation_receipt_refs=tuple(str(ref) for ref in output.get("validation_receipt_refs", receipt_refs)),
                )
            )
        provisional_run["output_artifact_refs"] = [artifact["id"] for artifact in output_artifacts]
    else:
        failure = outcome.get("failure")
        if not isinstance(failure, Mapping):
            raise ExecutionError("failed or blocked module provider output requires failure")
        provisional_run["failure"] = {
            "module_id": module_id,
            "module_run_id": run_id,
            "code": str(failure.get("code", "provider_failure")),
            "message": str(failure.get("message", "module provider did not complete")),
            "retryable": bool(failure.get("retryable", False)),
        }
    validate_module_run(
        provisional_run,
        contract,
        {artifact["id"]: artifact for artifact in output_artifacts} | input_map,
        receipt_map,
        expected_module_digest=module_digest,
        expected_instruction_digest=instruction_digest,
    )
    return {"run": provisional_run, "artifacts": output_artifacts}


def _artifact_subject(envelope: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in envelope.items() if key != "id"}


def expected_artifact_id(envelope: Mapping[str, Any]) -> str:
    return _content_id("ART", _artifact_subject(envelope))


def selection_digest(selection: Mapping[str, Any]) -> str:
    subject = {key: value for key, value in selection.items() if key != "selection_digest"}
    return _canonical_digest(subject)


def build_artifact_envelope(
    *,
    producer_module_id: str,
    producer_run_id: str,
    output_id: str,
    schema_ref: str,
    payload: Mapping[str, Any],
    taint_state: str = "tainted",
    source_refs: Sequence[str] = (),
    validation_receipt_refs: Sequence[str] = (),
) -> dict[str, Any]:
    if any(not isinstance(ref, str) or not re.fullmatch(r"SRC-[A-F0-9]{64}", ref) for ref in source_refs):
        raise ExecutionError("artifact source_refs must be content-addressed source IDs")
    if any(not isinstance(ref, str) or not re.fullmatch(r"VRF-[A-F0-9]{64}", ref) for ref in validation_receipt_refs):
        raise ExecutionError("artifact validation_receipt_refs must be content-addressed validation receipt IDs")
    envelope: dict[str, Any] = {
        "schema_ref": schema_ref,
        "producer_module_id": producer_module_id,
        "producer_run_id": producer_run_id,
        "output_id": output_id,
        "payload": deepcopy(dict(payload)),
        "taint_state": taint_state,
    }
    if source_refs:
        envelope["source_refs"] = sorted(set(source_refs))
    if validation_receipt_refs:
        envelope["validation_receipt_refs"] = sorted(set(validation_receipt_refs))
    return {"id": expected_artifact_id(envelope), **envelope}


def _output_contracts(contract: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    outputs = contract.get("contract", {}).get("outputs", [])
    if not isinstance(outputs, list):
        raise ExecutionError("module contract outputs must be an array")
    result: dict[str, Mapping[str, Any]] = {}
    for output in outputs:
        if not isinstance(output, Mapping) or not isinstance(output.get("id"), str):
            raise ExecutionError("module contract contains an invalid output descriptor")
        output_id = str(output["id"])
        if output_id in result:
            raise ExecutionError(f"module contract contains duplicate output: {output_id}")
        result[output_id] = output
    return result


def _validate_receipts(receipt_refs: Sequence[str], receipts: Mapping[str, Mapping[str, Any]]) -> None:
    for receipt_ref in receipt_refs:
        receipt = receipts.get(str(receipt_ref))
        if receipt is None:
            raise ExecutionError(f"module execution references unknown validation receipt: {receipt_ref}")
        if receipt.get("result") != "validated":
            raise ExecutionError(f"module execution references unsuccessful validation receipt: {receipt_ref}")


def _validate_artifact(artifact: Mapping[str, Any], receipts: Mapping[str, Mapping[str, Any]]) -> None:
    supplied_id = str(artifact.get("id", ""))
    if supplied_id != expected_artifact_id(artifact):
        raise ExecutionError(f"artifact id does not match its content: {supplied_id}")
    if not isinstance(artifact.get("payload"), Mapping):
        raise ExecutionError("artifact payload must be an object")
    for field, pattern in (
        ("source_refs", r"SRC-[A-F0-9]{64}"),
        ("validation_receipt_refs", r"VRF-[A-F0-9]{64}"),
    ):
        refs = artifact.get(field, [])
        if (
            not isinstance(refs, list)
            or any(not isinstance(ref, str) or not re.fullmatch(pattern, ref) for ref in refs)
            or len(refs) != len(set(refs))
        ):
            raise ExecutionError(f"artifact {field} must contain typed unique references")
    receipt_refs = artifact.get("validation_receipt_refs", [])
    if artifact.get("taint_state") in {"validated", "human_approved"} and not receipt_refs:
        raise ExecutionError("validated or human-approved artifact outputs require a validation receipt")
    _validate_receipts(receipt_refs, receipts)


def validate_module_run(
    run: Mapping[str, Any],
    contract: Mapping[str, Any],
    artifacts: Mapping[str, Mapping[str, Any]],
    validation_receipts: Mapping[str, Mapping[str, Any]],
    *,
    expected_module_digest: str | None = None,
    expected_instruction_digest: str | None = None,
) -> None:
    supplied_run_id = str(run.get("id", ""))
    if supplied_run_id != expected_module_run_id(run):
        raise ExecutionError(f"module run id does not match its invocation content: {supplied_run_id}")
    module_id = str(contract.get("id", ""))
    if run.get("module_id") != module_id:
        raise ExecutionError("module run module_id does not match module contract")
    contract_instruction_digest = contract.get("contract", {}).get("disclosure", {}).get("instruction_sha256")
    if contract_instruction_digest is not None and run.get("instruction_digest") != contract_instruction_digest:
        raise ExecutionError("module run instruction digest does not match module contract")
    if expected_module_digest is not None and run.get("module_digest") != expected_module_digest:
        raise ExecutionError("module run digest does not match module contract binding")
    if expected_instruction_digest is not None and run.get("instruction_digest") != expected_instruction_digest:
        raise ExecutionError("module run instruction digest does not match module contract binding")
    if run.get("status") not in {"completed", "failed", "blocked"}:
        raise ExecutionError("module run has an invalid status")
    _validate_run_times(run)
    for field in ("input_artifact_refs", "output_artifact_refs", "validation_receipt_refs"):
        if not isinstance(run.get(field), list):
            raise ExecutionError(f"module run {field} must be an array")
    _validate_receipts(run.get("validation_receipt_refs", []), validation_receipts)

    output_contracts = _output_contracts(contract)
    input_refs = [str(ref) for ref in run.get("input_artifact_refs", [])]
    if len(input_refs) != len(set(input_refs)):
        raise ExecutionError("module run input_artifact_refs must be unique")
    artifact_inputs = contract.get("contract", {}).get("inputs", {}).get("artifact_inputs", [])
    input_by_output = {
        str(artifact.get("output_id")): artifact
        for artifact in (artifacts.get(ref) for ref in input_refs)
        if isinstance(artifact, Mapping)
    }
    for descriptor in artifact_inputs:
        if not isinstance(descriptor, Mapping):
            continue
        output_id = str(descriptor.get("output_id", ""))
        artifact = input_by_output.get(output_id)
        if descriptor.get("required") is True and artifact is None:
            raise ExecutionError(f"module run is missing required artifact input: {output_id}")
        if artifact is not None and artifact.get("schema_ref") != descriptor.get("schema_ref"):
            raise ExecutionError(f"module run input schema_ref mismatch for {output_id}")
    for ref in input_refs:
        input_artifact = artifacts.get(ref)
        if input_artifact is None:
            raise ExecutionError(f"module run references unknown input artifact: {ref}")
        _validate_artifact(input_artifact, validation_receipts)
    output_refs = [str(ref) for ref in run.get("output_artifact_refs", [])]
    if len(output_refs) != len(set(output_refs)):
        raise ExecutionError("module run output_artifact_refs must be unique")
    output_artifacts: dict[str, list[Mapping[str, Any]]] = {}
    for ref in output_refs:
        artifact = artifacts.get(ref)
        if artifact is None:
            raise ExecutionError(f"module run references unknown output artifact: {ref}")
        _validate_artifact(artifact, validation_receipts)
        if artifact.get("producer_run_id") != run.get("id"):
            raise ExecutionError(f"artifact producer_run_id does not match module run: {ref}")
        if artifact.get("producer_module_id") != module_id:
            raise ExecutionError(f"artifact producer_module_id does not match module contract: {ref}")
        output_id = str(artifact.get("output_id", ""))
        descriptor = output_contracts.get(output_id)
        if descriptor is None:
            raise ExecutionError(f"module run produced undeclared output: {output_id}")
        if output_id in output_artifacts and descriptor.get("cardinality") == "one":
            raise ExecutionError(f"module run has duplicate output cardinality one: {output_id}")
        output_artifacts.setdefault(output_id, []).append(artifact)

    for output_id, descriptor in output_contracts.items():
        if descriptor.get("required_when") == "completed" and run.get("status") == "completed" and output_id not in output_artifacts:
            raise ExecutionError(f"completed module run is missing required output: {output_id}")
        output_items = output_artifacts.get(output_id, [])
        if not output_items:
            continue
        if any(item.get("schema_ref") != descriptor.get("schema_ref") for item in output_items):
            raise ExecutionError(f"output schema_ref mismatch for {output_id}")

    if run.get("status") == "completed":
        result = run.get("result")
        if not isinstance(result, Mapping):
            raise ExecutionError("completed module run requires a typed result")
        if result.get("module_id") != module_id or result.get("module_run_id") != run.get("id"):
            raise ExecutionError("module result is not bound to its module run")
        if not isinstance(result.get("gate_trace"), list) or not result.get("gate_trace"):
            raise ExecutionError("module result requires a non-empty gate_trace")
        if not all(isinstance(gate_id, str) and gate_id.startswith("HG-") for gate_id in result["gate_trace"]):
            raise ExecutionError("module result gate_trace contains an invalid gate id")
        evidence_refs = result.get("evidence_refs")
        if (
            not isinstance(evidence_refs, list)
            or any(not isinstance(ref, str) or not re.fullmatch(r"(?:SRC|CLM|VRF|ART)-[A-F0-9]{64}", ref) for ref in evidence_refs)
            or len(evidence_refs) != len(set(evidence_refs))
        ):
            raise ExecutionError("module result evidence_refs must be a unique array")
        if result.get("state") not in {"pass", "fail", "unknown"}:
            raise ExecutionError("module result has an invalid state")
        decision_artifacts = output_artifacts.get("module_decision", [])
        if len(decision_artifacts) != 1:
            raise ExecutionError("completed module run requires module_decision output")
        decision_artifact = decision_artifacts[0]
        if decision_artifact.get("payload") != result:
            raise ExecutionError("module_decision artifact payload does not match module result")
        if result.get("state") == "pass":
            if not result.get("evidence_refs"):
                raise ExecutionError("passing module result requires evidence_refs")
            if not run.get("validation_receipt_refs"):
                raise ExecutionError("passing module result requires validation receipts")
            unresolved_artifacts = [
                ref for ref in result.get("evidence_refs", []) if str(ref).startswith("ART-") and str(ref) not in artifacts
            ]
            if unresolved_artifacts:
                raise ExecutionError(f"passing module result references unknown artifacts: {unresolved_artifacts}")
    else:
        failure = run.get("failure")
        if not isinstance(failure, Mapping):
            raise ExecutionError("failed or blocked module run requires a typed failure result")
        if failure.get("module_id") != module_id or failure.get("module_run_id") != run.get("id"):
            raise ExecutionError("module failure result is not bound to its module run")
        if not isinstance(failure.get("code"), str) or not failure.get("code"):
            raise ExecutionError("module failure result requires a code")
        if not isinstance(failure.get("message"), str) or not failure.get("message"):
            raise ExecutionError("module failure result requires a message")


def derive_gate_results(
    manifest: Mapping[str, Any],
    plan: Mapping[str, Any],
    selection: Mapping[str, Any],
    module_runs: Sequence[Mapping[str, Any]],
    artifacts: Sequence[Mapping[str, Any]],
    validation_receipts: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Derive gate states only from canonical activation and typed execution records."""

    from .evaluator import PlanIntegrityError, assert_plan_matches

    try:
        assert_plan_matches(manifest, plan, require_binding=True)
    except PlanIntegrityError as exc:
        raise ExecutionError(f"gate aggregation requires a canonical activation plan: {exc}") from exc

    run_by_module: dict[str, Mapping[str, Any]] = {}
    for run in module_runs:
        module_id = str(run.get("module_id", ""))
        if module_id in run_by_module:
            raise ExecutionError(f"duplicate module run for module: {module_id}")
        run_by_module[module_id] = run
    artifact_map: dict[str, Mapping[str, Any]] = {}
    for artifact in artifacts:
        artifact_id = str(artifact.get("id"))
        if artifact_id in artifact_map:
            raise ExecutionError(f"duplicate artifact id: {artifact_id}")
        artifact_map[artifact_id] = artifact
    receipt_map: dict[str, Mapping[str, Any]] = {}
    for receipt in validation_receipts:
        receipt_id = str(receipt.get("id"))
        if receipt_id in receipt_map:
            raise ExecutionError(f"duplicate validation receipt id: {receipt_id}")
        receipt_map[receipt_id] = receipt
    selected = {str(module.get("id")): module for module in selection.get("selected_modules", [])}
    plan_by_gate = {str(gate.get("id")): gate for gate in plan.get("gates", [])}
    owners: dict[str, list[Mapping[str, Any]]] = {}
    for module in selected.values():
        for gate_id in module.get("gate_coverage", []):
            owners.setdefault(str(gate_id), []).append(module)

    module_states: dict[str, Mapping[str, Any] | None] = {}
    module_errors: dict[str, str] = {}
    for module_id, module in selected.items():
        run = run_by_module.get(module_id)
        if run is None:
            module_states[module_id] = None
            module_errors[module_id] = "required module run is missing"
            continue
        if run.get("module_digest") != module.get("module_sha256"):
            module_states[module_id] = None
            module_errors[module_id] = "module run digest does not match module selection"
            continue
        if run.get("instruction_digest") != module.get("instruction_sha256"):
            module_states[module_id] = None
            module_errors[module_id] = "module run instruction digest does not match module selection"
            continue
        contract = {"id": module_id, "contract": {"outputs": module.get("output_contracts", [])}}
        try:
            validate_module_run(
                run,
                contract,
                artifact_map,
                receipt_map,
                expected_module_digest=str(module.get("module_sha256", "")),
                expected_instruction_digest=str(module.get("instruction_sha256", "")),
            )
        except ExecutionError as exc:
            module_states[module_id] = None
            module_errors[module_id] = str(exc)
            continue
        module_states[module_id] = run.get("result") if run.get("status") == "completed" else None
        if run.get("status") != "completed":
            module_errors[module_id] = "module run did not complete successfully"

    results: list[dict[str, Any]] = []
    for gate in manifest.get("gates", {}).get("items", []):
        gate_id = str(gate["id"])
        activation = plan_by_gate.get(gate_id, {}).get("activation_state")
        if activation == "inactive":
            results.append({"gate": gate_id, "state": "not_applicable", "reason": "activation is inactive"})
            continue
        if activation != "active":
            results.append({"gate": gate_id, "state": "unknown", "reason": "activation is unknown"})
            continue
        gate_owners = owners.get(gate_id, [])
        if len(gate_owners) != 1:
            results.append({"gate": gate_id, "state": "unknown", "reason": "active gate does not have exactly one selected owner"})
            continue
        module = gate_owners[0]
        module_id = str(module["id"])
        result = module_states.get(module_id)
        if result is None:
            results.append({"gate": gate_id, "state": "unknown", "reason": module_errors.get(module_id, "module result unavailable")})
            continue
        if gate_id not in result.get("gate_trace", []):
            results.append({"gate": gate_id, "state": "unknown", "reason": "module result omits active gate from gate_trace"})
            continue
        results.append(
            {
                "gate": gate_id,
                "state": result.get("state"),
                "reason": f"derived from completed module run {run_by_module[module_id]['id']}",
                "evidence_refs": list(result.get("evidence_refs", [])),
            }
        )
    return results
