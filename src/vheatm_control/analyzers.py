from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from .python_linker import LinkerError, link_probe_bundle, verify_linkage_bundle
from .provenance import ProvenanceError, build_validation_receipt
from .serialization import load_json
from .structural_probe import ProbeError, ProbeLimits, probe_workspace, verify_probe_bundle
from .tool_broker import ToolBroker, build_tool_receipt, request_digest


class AnalyzerError(ValueError):
    """Raised when a brokered analyzer request or result is not trustworthy."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _content_id(prefix: str, value: Any) -> str:
    return f"{prefix}-{_digest(value).upper()}"


def _timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AnalyzerError("captured_at/generated_at must be RFC 3339") from exc
    if parsed.tzinfo is None:
        raise AnalyzerError("analyzer timestamps must include a timezone")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def snapshot_digest(source_snapshot: Sequence[Mapping[str, Any]]) -> str:
    normalized = sorted(
        [{"path": str(item.get("path", "")), "sha256": str(item.get("sha256", ""))} for item in source_snapshot],
        key=lambda item: item["path"],
    )
    if not normalized or any(not item["path"] for item in normalized):
        raise AnalyzerError("source_snapshot must contain at least one normalized path")
    return _digest(normalized)


def snapshot_from_probe(probe: Mapping[str, Any]) -> list[dict[str, str]]:
    try:
        verify_probe_bundle(probe)
    except ProbeError as exc:
        raise AnalyzerError(f"cannot derive a source snapshot from an invalid probe: {exc}") from exc
    entries = [
        {"path": str(item["path"]), "sha256": str(item["source"]["digest"]["value"])}
        for item in probe.get("files", [])
    ]
    if not entries:
        raise AnalyzerError("a source snapshot requires at least one parsed source file")
    return entries


def build_analyzer_request(
    *,
    analyzer_id: str,
    provider_id: str,
    provider_version: str,
    operation: str,
    workspace_path: str | Path,
    requested_paths: Sequence[str],
    source_snapshot: Sequence[Mapping[str, Any]],
    session_root: str,
    captured_at: str,
    source_roots: Sequence[str] = (),
) -> dict[str, Any]:
    if operation not in {"probe", "link"}:
        raise AnalyzerError("operation must be probe or link")
    if not isinstance(session_root, str) or len(session_root) != 64 or any(char not in "0123456789abcdef" for char in session_root):
        raise AnalyzerError("session_root must be a lowercase SHA-256 digest")
    paths = sorted(set(str(path) for path in requested_paths))
    if not paths or any(not path or "\x00" in path for path in paths):
        raise AnalyzerError("requested_paths must be non-empty and normalized")
    snapshot = sorted(
        [{"path": str(item.get("path", "")), "sha256": str(item.get("sha256", ""))} for item in source_snapshot],
        key=lambda item: item["path"],
    )
    snap_digest = snapshot_digest(snapshot)
    tool_request = {
        "schema_version": "1.0.0",
        "request_id": "pending",
        "requester": provider_id,
        "tool_class": "read",
        "scope": "workspace:",
        "secret_expansion": False,
        "contains_secrets": False,
    }
    identity = {
        "analyzer_id": analyzer_id,
        "provider_id": provider_id,
        "provider_version": provider_version,
        "operation": operation,
        "workspace_path": str(Path(workspace_path).resolve()),
        "requested_paths": paths,
        "source_snapshot": snapshot,
        "snapshot_digest": snap_digest,
        "source_roots": sorted(set(str(root) for root in source_roots)),
        "session_root": session_root,
        "captured_at": _timestamp(captured_at),
    }
    request_id = _content_id("ANR", identity)
    tool_request["request_id"] = request_id
    return {"schema_version": "1.0.0", "request_id": request_id, **identity, "tool_request": tool_request}


@dataclass(frozen=True)
class LocalAnalyzerProvider:
    """Read-only Python probe/link adapter behind the unified broker."""

    broker: ToolBroker
    analyzer_id: str = "python.structural"
    provider_id: str = "local.python"
    provider_version: str = "1.0.0"

    def run(
        self,
        request: Mapping[str, Any],
        *,
        input_probe: Mapping[str, Any] | None = None,
        limits: ProbeLimits | None = None,
    ) -> dict[str, Any]:
        _validate_request(request)
        if request.get("analyzer_id") != self.analyzer_id or request.get("provider_id") != self.provider_id:
            raise AnalyzerError("request provider descriptor does not match this adapter")
        decision = self.broker.evaluate(request["tool_request"])
        receipt = build_tool_receipt(request["tool_request"], decision, recorded_at=str(decision["evaluated_at"]))
        if decision.get("decision") != "allow":
            return _build_result(request, status="blocked", output=None, source_refs=[], receipt=receipt)
        try:
            if request["operation"] == "probe":
                output = probe_workspace(
                    request["workspace_path"], request["requested_paths"], captured_at=request["captured_at"], limits=limits
                )
                verify_probe_bundle(output)
                source_refs = [str(item["source"]["id"]) for item in output.get("files", [])]
            else:
                if input_probe is None:
                    raise AnalyzerError("link operation requires an input probe")
                verify_probe_bundle(input_probe)
                expected = snapshot_from_probe(input_probe)
                if snapshot_digest(expected) != request["snapshot_digest"]:
                    raise AnalyzerError("input probe is not bound to the request source snapshot")
                output = link_probe_bundle(input_probe, request.get("source_roots", []), generated_at=request["captured_at"])
                verify_linkage_bundle(output, input_probe)
                source_refs = sorted({str(item["source_id"]) for item in output.get("modules", [])})
        except (AnalyzerError, ProbeError, LinkerError, OSError, ValueError) as exc:
            return _build_result(request, status="unknown", output=None, source_refs=[], receipt=receipt, error=str(exc))
        actual_snapshot = snapshot_from_probe(output) if request["operation"] == "probe" else snapshot_from_probe(input_probe or {})
        if snapshot_digest(actual_snapshot) != request["snapshot_digest"]:
            return _build_result(
                request, status="blocked", output=None, source_refs=[], receipt=receipt,
                error="workspace changed during analyzer execution; source snapshot mismatch",
            )
        return _build_result(request, status="complete", output=output, source_refs=source_refs, receipt=receipt)


def _validate_request(request: Mapping[str, Any]) -> None:
    required = {"schema_version", "request_id", "analyzer_id", "provider_id", "provider_version", "operation", "workspace_path", "requested_paths", "source_snapshot", "snapshot_digest", "session_root", "captured_at", "tool_request"}
    if not isinstance(request, Mapping) or request.get("schema_version") != "1.0.0" or not required.issubset(request):
        raise AnalyzerError("analyzer request is incomplete")
    if request.get("request_id") != request.get("tool_request", {}).get("request_id"):
        raise AnalyzerError("analyzer request and tool request ids differ")
    if snapshot_digest(request["source_snapshot"]) != request["snapshot_digest"]:
        raise AnalyzerError("analyzer request snapshot_digest is invalid")
    if request["tool_request"].get("tool_class") != "read":
        raise AnalyzerError("analyzer adapters may only use the read tool class")
    if request["tool_request"].get("secret_expansion") is not False or request["tool_request"].get("contains_secrets") is not False:
        raise AnalyzerError("analyzer read requests must disable secret expansion and secret content")
    _timestamp(str(request["captured_at"]))


def _build_result(
    request: Mapping[str, Any], *, status: str, output: Mapping[str, Any] | None, source_refs: Sequence[str],
    receipt: Mapping[str, Any], error: str | None = None,
) -> dict[str, Any]:
    if status not in {"complete", "blocked", "unknown"}:
        raise AnalyzerError("invalid analyzer result status")
    result_output = deepcopy(dict(output)) if isinstance(output, Mapping) else None
    result_identity = {
        "request_id": request["request_id"], "analyzer_id": request["analyzer_id"], "provider_id": request["provider_id"],
        "provider_version": request["provider_version"], "operation": request["operation"], "session_root": request["session_root"],
        "input_snapshot_digest": request["snapshot_digest"], "status": status, "epistemic_status": "candidate" if status == "complete" else "unknown",
        "output_digest": _digest(result_output), "source_refs": sorted(set(str(ref) for ref in source_refs)),
        # Broker timestamps are audit metadata, not analyzer content identity;
        # excluding them keeps the same immutable snapshot deterministic.
        "tool_receipt": {key: value for key, value in receipt.items() if key != "recorded_at"}, "output": result_output,
    }
    if error:
        result_identity["error"] = error
    return {
        "schema_version": "1.0.0", "result_id": _content_id("ANZ", result_identity), **result_identity,
        "tool_receipt": dict(receipt), "generated_at": str(request["captured_at"]),
    }


def verify_analyzer_result(result: Mapping[str, Any], *, verifier_id: str = "vheatm.analyzer-verifier") -> dict[str, Any] | None:
    """Verify candidate output and issue a separate receipt; never clear source taint."""

    if result.get("status") != "complete" or result.get("epistemic_status") != "candidate":
        return None
    output = result.get("output")
    if not isinstance(output, Mapping) or _digest(output) != result.get("output_digest"):
        raise AnalyzerError("analyzer output digest mismatch")
    if result.get("operation") == "probe":
        verify_probe_bundle(output)
    elif result.get("operation") == "link":
        verify_linkage_bundle(output)
    else:
        raise AnalyzerError("unknown analyzer operation")
    return build_validation_receipt(
        source_refs=result.get("source_refs", []), validator=verifier_id,
        method=f"deterministic:{result['operation']}:bundle-integrity-v1", result="validated",
        input_digest=str(result["output_digest"]), validated_at=str(result["generated_at"]),
    )
