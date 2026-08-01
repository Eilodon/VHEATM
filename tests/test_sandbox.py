from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from vheatm_control.sandbox import (
    SandboxConfigurationError,
    SandboxExecutor,
    build_sandbox_run,
    expected_sandbox_run_id,
)


ROOT = Path(__file__).resolve().parents[1]


def _request() -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "request_id": "REQ-sandbox",
        "requester": "module:MOD-TEST",
        "tool_class": "execute",
        "scope": "workspace:tests",
        "workspace_path": str(ROOT),
        "sandboxed": True,
        "command": "true",
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


def test_executor_requires_digest_bound_backend(tmp_path: Path) -> None:
    with pytest.raises(SandboxConfigurationError, match="digest"):
        SandboxExecutor(backend_path=Path("/usr/bin/bwrap"), backend_sha256=None)


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


def test_executor_blocks_when_host_cannot_provide_required_namespace() -> None:
    backend = Path("/usr/bin/bwrap")
    if not backend.is_file():
        pytest.skip("bubblewrap is unavailable")

    class AllowBroker:
        def evaluate(self, request, approval_token=None):  # noqa: ANN001
            del request, approval_token
            return {"decision": "allow", "reason": "test policy"}

    digest = hashlib.sha256(backend.read_bytes()).hexdigest()
    result = SandboxExecutor(backend_path=backend, backend_sha256=digest, broker=AllowBroker()).run(_request())
    assert result["status"] in {"completed", "blocked"}
    if result["status"] == "blocked":
        assert "backend:preflight-failed" in result["sandbox_controls"]


def test_executor_blocks_when_policy_broker_errors() -> None:
    backend = Path("/usr/bin/bwrap")
    if not backend.is_file():
        pytest.skip("bubblewrap is unavailable")

    class BrokenBroker:
        def evaluate(self, request, approval_token=None):  # noqa: ANN001
            del request, approval_token
            raise RuntimeError("broker store unavailable")

    digest = hashlib.sha256(backend.read_bytes()).hexdigest()
    result = SandboxExecutor(backend_path=backend, backend_sha256=digest, broker=BrokenBroker()).run(_request())
    assert result["status"] == "blocked"
    assert "broker:error" in result["sandbox_controls"]
