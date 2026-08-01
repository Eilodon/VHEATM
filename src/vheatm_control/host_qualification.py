from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import shutil
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker

from .bundle import build_bundle, resolve_control_root
from .qualification_methods import QualificationMethodError, expected_method_digest, validate_method_digest
from .qualification_runner import _POLICY_KEY, _build_approval_token
from .sandbox import SandboxConfigurationError, SandboxExecutor
from .serialization import load_json, load_yaml
from .tool_broker import BrokerCapabilities, InMemoryTokenLedger, ToolBroker


class HostQualificationError(ValueError):
    """Raised when host qualification cannot emit a typed record safely."""


RUN_SCHEMA_VERSION = "1.0.0"
RUNNER_ID = "vheatm.host-qualification"
RUNNER_VERSION = "1.0.0"
DEFAULT_TIMEOUT_SECONDS = 0.25
MAX_SAMPLE_COUNT = 32


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HostQualificationError("host qualification timestamps must be RFC 3339") from exc
    if parsed.tzinfo is None:
        raise HostQualificationError("host qualification timestamps must include a timezone")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def expected_host_qualification_run_id(run: Mapping[str, Any]) -> str:
    identity = {key: value for key, value in run.items() if key != "run_id"}
    return "HQR-" + _digest(identity).upper()


def _host_identity_digest() -> str:
    # Deliberately exclude hostname, usernames, and other directly identifying
    # host values. The digest is only an evidence binding, not a fingerprint API.
    identity = {
        "os_name": os.name,
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python_implementation": platform.python_implementation(),
    }
    return _digest(identity)


def _backend_details(backend_path: str | Path | None) -> tuple[Path | None, str | None, str | None]:
    selected_value = str(backend_path) if backend_path is not None else shutil.which("bwrap")
    if not selected_value:
        return None, None, "bubblewrap executable is unavailable"
    selected = Path(selected_value)
    try:
        resolved = selected.resolve(strict=True)
    except OSError:
        return None, None, "bubblewrap executable is unavailable"
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        return None, None, "bubblewrap backend is not an executable file"
    if resolved.name not in {"bwrap", "bubblewrap"}:
        return None, None, "bubblewrap backend filename is not canonical"
    try:
        digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
    except OSError:
        return None, None, "bubblewrap backend cannot be read"
    return resolved, digest, None


def _new_broker(root: Path, observed_at: str) -> ToolBroker:
    observed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    if observed.tzinfo is None:
        raise HostQualificationError("host qualification timestamps must include a timezone")
    return ToolBroker.from_root(
        root,
        keyring={"runner-key": _POLICY_KEY},
        capabilities=BrokerCapabilities(exact_command_allowlist=frozenset({"sleep 60"})),
        token_ledger=InMemoryTokenLedger(),
        clock=lambda: observed,
    )


def _request(root: Path, backend_digest: str, index: int) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "request_id": f"REQ-HOST-HARDSTOP-{index:04d}",
        "requester": RUNNER_ID,
        "tool_class": "execute",
        "scope": "workspace:",
        "workspace_path": str(root),
        "sandboxed": True,
        "command": "sleep 60",
        "executable_digest": backend_digest,
        "network_enabled": False,
        "inherit_secrets": False,
    }


def _observation(
    *,
    index: int,
    status: str,
    elapsed_seconds: float,
    sandbox_run_id: str | None,
    controls: list[str],
    details: Mapping[str, Any],
) -> dict[str, Any]:
    identity = {
        "sample_index": index,
        "kind": "hard_stop_timeout",
        "status": status,
        "elapsed_seconds": elapsed_seconds,
        "sandbox_run_id": sandbox_run_id,
        "controls": list(dict.fromkeys(controls)) or ["host:qualification"],
        "details": dict(details),
    }
    return {"observation_id": "HOB-" + _digest(identity).upper(), **identity}


def _percentile_99(values: list[float]) -> float:
    if not values:
        raise HostQualificationError("cannot calculate a percentile without observations")
    rank = max(1, math.ceil(0.99 * len(values)))
    return round(sorted(values)[rank - 1], 9)


def run_host_qualification(
    root: Path,
    *,
    backend_path: str | Path | None = None,
    sample_count: int = 5,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    observed_at: str,
) -> dict[str, Any]:
    """Run real host probes without converting local observations into GA evidence.

    Each sample invokes the configured bubblewrap backend through
    ``SandboxExecutor``. A hard-stop sample is valid only when the executor
    reports its own timeout-enforced process-group kill. Namespace preflight
    failure remains an explicit unavailable observation.
    """

    if not isinstance(sample_count, int) or not 1 <= sample_count <= MAX_SAMPLE_COUNT:
        raise HostQualificationError(f"sample_count must be between 1 and {MAX_SAMPLE_COUNT}")
    if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool) or not 0 < timeout_seconds <= 5:
        raise HostQualificationError("timeout_seconds must be greater than 0 and at most 5")
    generated_at = _timestamp(observed_at)
    schema_root = resolve_control_root(root)
    manifest = load_yaml((schema_root / "manifests" / "vheatm-v17.yaml").read_text(encoding="utf-8"))
    framework_version = str(manifest["framework"]["version"])
    bundle_root = build_bundle(schema_root)["bundle_root"]
    selected, backend_digest, backend_issue = _backend_details(backend_path)
    observations: list[dict[str, Any]] = []
    hard_stop_seconds: list[float] = []

    if selected is None or backend_digest is None:
        for index in range(1, sample_count + 1):
            observations.append(
                _observation(
                    index=index,
                    status="unavailable",
                    elapsed_seconds=0.0,
                    sandbox_run_id=None,
                    controls=["reference-monitor:unavailable", "fail-closed"],
                    details={"reason": backend_issue or "bubblewrap backend is unavailable"},
                )
            )
        effective_backend_digest: str | None = None
    else:
        effective_backend_digest = backend_digest
        broker = _new_broker(schema_root, generated_at)
        try:
            executor = SandboxExecutor(
                backend_path=selected,
                backend_sha256=backend_digest,
                broker=broker,
                timeout_seconds=float(timeout_seconds),
            )
        except SandboxConfigurationError as exc:
            for index in range(1, sample_count + 1):
                observations.append(
                    _observation(
                        index=index,
                        status="unavailable",
                        elapsed_seconds=0.0,
                        sandbox_run_id=None,
                        controls=["reference-monitor:unavailable", "fail-closed"],
                        details={"reason": str(exc)},
                    )
                )
        else:
            for index in range(1, sample_count + 1):
                request = _request(schema_root, backend_digest, index)
                approval = _build_approval_token(request, generated_at)
                started = time.perf_counter()
                sandbox_run = executor.run(request, approval)
                elapsed = round(max(0.0, time.perf_counter() - started), 9)
                controls = [str(item) for item in sandbox_run.get("sandbox_controls", [])]
                if sandbox_run.get("status") == "blocked" and "timeout:enforced" in controls:
                    observation_status = "observed"
                    hard_stop_seconds.append(elapsed)
                elif "backend:preflight-failed" in controls or "backend:unavailable" in controls:
                    observation_status = "unavailable"
                else:
                    observation_status = "failed"
                if observation_status == "observed":
                    observation_reason = "timeout enforcement observed"
                elif observation_status == "unavailable":
                    observation_reason = "reference monitor preflight was unavailable"
                else:
                    observation_reason = "sandbox observation did not establish hard-stop enforcement"
                observations.append(
                    _observation(
                        index=index,
                        status=observation_status,
                        elapsed_seconds=elapsed,
                        sandbox_run_id=str(sandbox_run.get("run_id")) if sandbox_run.get("run_id") else None,
                        controls=controls,
                        details={
                            "reason": observation_reason,
                            "sandbox_status": sandbox_run.get("status"),
                            "exit_code": sandbox_run.get("exit_code"),
                            "stderr_digest": sandbox_run.get("stderr_digest"),
                            "timeout_budget_seconds": float(timeout_seconds),
                        },
                    )
                )

    observed = [item for item in observations if item["status"] == "observed"]
    if len(observed) == sample_count:
        status = "complete"
    elif not observed and all(item["status"] == "unavailable" for item in observations):
        status = "blocked"
    else:
        status = "partial"
    if all(item["status"] == "observed" for item in observations):
        reference_monitor_status = "observed"
    elif not observed and all(item["status"] == "unavailable" for item in observations):
        reference_monitor_status = "unavailable"
    elif observed:
        reference_monitor_status = "partial"
    else:
        reference_monitor_status = "failed"

    measurements: list[dict[str, Any]] = []
    if len(observed) == sample_count:
        try:
            method_digest = expected_method_digest("hard_stop_p99_seconds", root=schema_root)
        except QualificationMethodError as exc:
            raise HostQualificationError(f"hard-stop measurement method is unavailable: {exc}") from exc
        measurements.append(
            {
                "metric": "hard_stop_p99_seconds",
                "value": _percentile_99(hard_stop_seconds),
                "sample_count": len(hard_stop_seconds),
                "confidence_lower": 0,
                "method_digest": method_digest,
                "evidence_refs": [str(item["observation_id"]) for item in observed],
            }
        )

    run: dict[str, Any] = {
        "schema_version": RUN_SCHEMA_VERSION,
        "framework_version": framework_version,
        "bundle_root": bundle_root,
        "runner_id": RUNNER_ID,
        "runner_version": RUNNER_VERSION,
        "backend": "bubblewrap",
        "backend_digest": effective_backend_digest,
        "host_identity_digest": _host_identity_digest(),
        "reference_monitor_status": reference_monitor_status,
        "status": status,
        "evidence_state": "unverified",
        "observations": observations,
        "measurements": measurements,
        "generated_at": generated_at,
    }
    run["run_id"] = expected_host_qualification_run_id(run)
    schema = load_json((schema_root / "schemas" / "host-qualification-run.schema.json").read_text(encoding="utf-8"))
    issues = validate_host_qualification_run(run, schema, root=schema_root)
    if issues:
        raise HostQualificationError("host qualification emitted invalid typed evidence: " + "; ".join(issues))
    return run


def validate_host_qualification_run(
    run: Mapping[str, Any], schema: Mapping[str, Any], *, root: Path | None = None
) -> list[str]:
    if not isinstance(run, Mapping):
        return ["run must be an object"]
    issues: list[str] = []
    validator = Draft202012Validator(dict(schema), format_checker=FormatChecker())
    for error in sorted(validator.iter_errors(run), key=lambda item: list(item.absolute_path)):
        location = ".".join(str(part) for part in error.absolute_path) or "<root>"
        issues.append(f"{location}: {error.message}")
    if issues:
        return issues
    if run.get("run_id") != expected_host_qualification_run_id(run):
        issues.append("run_id does not match canonical host qualification content")
    observations = [item for item in run.get("observations", []) if isinstance(item, Mapping)]
    observation_ids = [str(item.get("observation_id", "")) for item in observations]
    if len(observation_ids) != len(set(observation_ids)):
        issues.append("observations contain duplicate IDs")
    sample_indices = [int(item.get("sample_index", 0)) for item in observations]
    if sorted(sample_indices) != list(range(1, len(observations) + 1)):
        issues.append("observation sample_index values must be contiguous and unique")
    observed = [item for item in observations if item.get("status") == "observed"]
    if len(observed) == len(observations):
        expected_status = "complete"
        expected_reference_monitor_status = "observed"
    elif not observed and all(item.get("status") == "unavailable" for item in observations):
        expected_status = "blocked"
        expected_reference_monitor_status = "unavailable"
    elif observed:
        expected_status = "partial"
        expected_reference_monitor_status = "partial"
    else:
        expected_status = "partial"
        expected_reference_monitor_status = "failed"
    if run.get("status") != expected_status:
        issues.append("status must be derived from observation statuses")
    if run.get("reference_monitor_status") != expected_reference_monitor_status:
        issues.append("reference_monitor_status must be derived from observation statuses")
    measurements = [item for item in run.get("measurements", []) if isinstance(item, Mapping)]
    if run.get("status") == "complete" and not observed:
        issues.append("complete host qualification requires observed hard-stop samples")
    if run.get("status") == "complete" and len(observed) != len(observations):
        issues.append("complete host qualification cannot contain unavailable or failed samples")
    if run.get("status") == "blocked" and observed:
        issues.append("blocked host qualification cannot contain observed hard-stop samples")
    if measurements:
        measurement = measurements[0]
        if len(measurements) != 1 or measurement.get("metric") != "hard_stop_p99_seconds":
            issues.append("host qualification measurements must contain only hard_stop_p99_seconds")
        refs = measurement.get("evidence_refs")
        if refs != [str(item.get("observation_id")) for item in observed]:
            issues.append("hard-stop measurement must cover exactly the observed samples")
        if measurement.get("sample_count") != len(observed):
            issues.append("hard-stop measurement sample_count is not bound to observed samples")
        try:
            validate_method_digest(
                "hard_stop_p99_seconds", str(measurement.get("method_digest", "")), root=resolve_control_root(root)
            )
        except QualificationMethodError as exc:
            issues.append(str(exc))
    elif run.get("status") == "complete":
        issues.append("complete host qualification requires a hard-stop measurement")
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description="Run real VHEATM host sandbox qualification without minting GA evidence.")
    parser.add_argument("--root", type=Path)
    parser.add_argument("--backend", type=Path)
    parser.add_argument("--sample-count", type=int, default=5)
    parser.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--compact", action="store_true")
    args = parser.parse_args()
    try:
        run = run_host_qualification(
            resolve_control_root(args.root),
            backend_path=args.backend,
            sample_count=args.sample_count,
            timeout_seconds=args.timeout_seconds,
            observed_at=args.observed_at,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    rendered = json.dumps(run, indent=None if args.compact else 2, sort_keys=args.compact, ensure_ascii=False)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0 if run["status"] == "complete" else 2


if __name__ == "__main__":
    raise SystemExit(main())
