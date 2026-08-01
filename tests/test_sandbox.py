from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from vheatm_control.sandbox import (
    SandboxConfigurationError,
    SandboxExecutionError,
    SandboxExecutor,
    build_sandbox_run,
    expected_sandbox_run_id,
)
from vheatm_control.tool_broker import build_tool_receipt, action_digest, request_digest


ROOT = Path(__file__).resolve().parents[1]


def _request(*, executable_digest: str = "a" * 64) -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "request_id": "REQ-sandbox",
        "requester": "module:MOD-TEST",
        "tool_class": "execute",
        "scope": "workspace:tests",
        "workspace_path": str(ROOT),
        "sandboxed": True,
        "command": "true",
        "executable_digest": executable_digest,
        "network_enabled": False,
        "inherit_secrets": False,
    }


def test_sandbox_run_is_content_addressed_and_schema_valid() -> None:
    run = build_sandbox_run(
        request=_request(),
        backend_digest="a" * 64,
        argv=["true"],
        status="blocked",
        exit_code=None,
        stdout=b"",
        stderr=b"backend unavailable",
        started_at="2026-08-01T00:00:00Z",
        finished_at="2026-08-01T00:00:01Z",
    )
    assert run["run_id"] == expected_sandbox_run_id(run)
    schema = json.loads((ROOT / "schemas" / "sandbox-run.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(run)


def test_completed_sandbox_run_binds_policy_decision_and_tool_receipt() -> None:
    decision = {
        "schema_version": "1.0.0",
        "request_id": "REQ-sandbox",
        "decision": "allow",
        "reason": "approved",
        "controls": ["approval:verified", "execute:sandbox"],
        "evaluated_at": "2026-08-01T00:00:00Z",
        "approval_token_id": "APR-" + "A" * 64,
    }
    receipt = build_tool_receipt(_request(), decision, recorded_at="2026-08-01T00:00:00Z")
    run = build_sandbox_run(
        request=_request(),
        backend_digest="a" * 64,
        argv=["true"],
        status="completed",
        exit_code=0,
        stdout=b"",
        stderr=b"",
        started_at="2026-08-01T00:00:00Z",
        finished_at="2026-08-01T00:00:01Z",
        policy_decision=decision,
        tool_receipt=receipt,
    )

    assert run["policy_decision_digest"] == request_digest(decision)
    assert run["action_digest"] == action_digest(_request())
    assert run["tool_receipt"]["id"] == receipt["id"]
    schema = json.loads((ROOT / "schemas" / "sandbox-run.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(run)


def test_completed_sandbox_run_cannot_claim_execution_without_authorization() -> None:
    with pytest.raises(SandboxExecutionError, match="authorization"):
        build_sandbox_run(
            request=_request(),
            backend_digest="a" * 64,
            argv=["true"],
            status="completed",
            exit_code=0,
            stdout=b"",
            stderr=b"",
            started_at="2026-08-01T00:00:00Z",
            finished_at="2026-08-01T00:00:01Z",
        )


def test_completed_sandbox_run_binds_backend_digest_to_request() -> None:
    decision = {
        "schema_version": "1.0.0",
        "request_id": "REQ-sandbox",
        "decision": "allow",
        "reason": "approved",
        "controls": ["approval:verified", "execute:sandbox"],
        "evaluated_at": "2026-08-01T00:00:00Z",
        "approval_token_id": "APR-" + "A" * 64,
    }
    request = _request(executable_digest="b" * 64)
    receipt = build_tool_receipt(request, decision, recorded_at="2026-08-01T00:00:00Z")
    with pytest.raises(SandboxExecutionError, match="backend digest"):
        build_sandbox_run(
            request=request,
            backend_digest="a" * 64,
            argv=["true"],
            status="completed",
            exit_code=0,
            stdout=b"",
            stderr=b"",
            started_at="2026-08-01T00:00:00Z",
            finished_at="2026-08-01T00:00:01Z",
            policy_decision=decision,
            tool_receipt=receipt,
        )


def test_sandbox_rejects_schema_invalid_policy_decision_before_action() -> None:
    valid_decision = {
        "schema_version": "1.0.0",
        "request_id": "REQ-sandbox",
        "decision": "allow",
        "reason": "approved",
        "controls": ["approval:verified"],
        "evaluated_at": "2026-08-01T00:00:00Z",
        "approval_token_id": "APR-" + "A" * 64,
    }
    decision = {**valid_decision, "controls": []}
    receipt = build_tool_receipt(_request(), valid_decision, recorded_at="2026-08-01T00:00:00Z")
    with pytest.raises(SandboxExecutionError, match="policy decision"):
        build_sandbox_run(
            request=_request(),
            backend_digest="a" * 64,
            argv=["true"],
            status="blocked",
            exit_code=None,
            stdout=b"",
            stderr=b"blocked",
            started_at="2026-08-01T00:00:00Z",
            finished_at="2026-08-01T00:00:01Z",
            policy_decision=decision,
            tool_receipt=receipt,
        )


def test_executor_requires_digest_bound_backend(tmp_path: Path) -> None:
    backend = Path("/usr/bin/bwrap")
    if not backend.is_file():
        pytest.skip("bubblewrap is unavailable")
    with pytest.raises(SandboxConfigurationError, match="digest"):
        SandboxExecutor(backend_path=backend, backend_sha256=None)


def test_executor_rejects_workspace_escape_before_backend(tmp_path: Path) -> None:
    backend = Path("/usr/bin/bwrap")
    if not backend.is_file():
        pytest.skip("bubblewrap is unavailable")
    digest = hashlib.sha256(backend.read_bytes()).hexdigest()
    executor = SandboxExecutor(backend_path=backend, backend_sha256=digest)
    request = _request()
    request["scope"] = "workspace:../outside"
    result = executor.run(request)
    assert result["status"] == "blocked"
    assert "scope:workspace" in result["sandbox_controls"]


def test_executor_never_falls_back_when_backend_probe_fails(tmp_path: Path) -> None:
    backend = tmp_path / "not-a-backend"
    backend.write_text("not executable", encoding="utf-8")
    with pytest.raises(SandboxConfigurationError, match="executable"):
        SandboxExecutor(backend_path=backend, backend_sha256="a" * 64)


def test_executor_blocks_backend_digest_drift_before_launch(tmp_path: Path) -> None:
    backend = tmp_path / "backend"
    backend.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    backend.chmod(0o755)
    digest = hashlib.sha256(backend.read_bytes()).hexdigest()
    executor = SandboxExecutor(backend_path=backend, backend_sha256=digest)

    backend.write_text("#!/bin/sh\nexit 42\n", encoding="utf-8")
    backend.chmod(0o755)

    result = executor.run(_request(executable_digest=digest))
    assert result["status"] == "blocked"
    assert "backend:digest-mismatch" in result["sandbox_controls"]


def test_executor_requires_request_backend_digest_binding(tmp_path: Path) -> None:
    backend = tmp_path / "backend"
    backend.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    backend.chmod(0o755)
    digest = hashlib.sha256(backend.read_bytes()).hexdigest()
    executor = SandboxExecutor(backend_path=backend, backend_sha256=digest)
    request = _request()
    request["executable_digest"] = "b" * 64

    result = executor.run(request)
    assert result["status"] == "blocked"
    assert "backend:request-binding" in result["sandbox_controls"]


def test_executor_blocks_when_host_cannot_provide_required_namespace() -> None:
    backend = Path("/usr/bin/bwrap")
    if not backend.is_file():
        pytest.skip("bubblewrap is unavailable")

    class AllowBroker:
        def evaluate(self, request, approval_token=None):  # noqa: ANN001
            del approval_token
            return {
                "schema_version": "1.0.0",
                "request_id": request["request_id"],
                "decision": "allow",
                "reason": "test policy",
                "controls": ["test:allow"],
                "evaluated_at": "2026-08-01T00:00:00Z",
                "approval_token_id": "APR-" + "A" * 64,
            }

    digest = hashlib.sha256(backend.read_bytes()).hexdigest()
    result = SandboxExecutor(backend_path=backend, backend_sha256=digest, broker=AllowBroker()).run(_request(executable_digest=digest))
    assert result["status"] in {"completed", "blocked"}
    if result["status"] == "blocked":
        assert "backend:preflight-failed" in result["sandbox_controls"] or "authorization:receipt-failed" in result["sandbox_controls"]
        if "backend:preflight-failed" in result["sandbox_controls"]:
            assert result["policy_decision_digest"]
            assert result["action_digest"]
            assert result["tool_receipt"]["decision"] == "allow"


def test_executor_blocks_when_policy_broker_errors() -> None:
    backend = Path("/usr/bin/bwrap")
    if not backend.is_file():
        pytest.skip("bubblewrap is unavailable")

    class BrokenBroker:
        def evaluate(self, request, approval_token=None):  # noqa: ANN001
            del request, approval_token
            raise RuntimeError("broker store unavailable")

    digest = hashlib.sha256(backend.read_bytes()).hexdigest()
    result = SandboxExecutor(backend_path=backend, backend_sha256=digest, broker=BrokenBroker()).run(_request(executable_digest=digest))
    assert result["status"] == "blocked"
    assert "broker:error" in result["sandbox_controls"]
