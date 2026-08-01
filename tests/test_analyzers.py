from __future__ import annotations

from pathlib import Path

import pytest

from vheatm_control.analyzers import (
    LocalAnalyzerProvider,
    AnalyzerError,
    build_analyzer_request,
    snapshot_from_probe,
    snapshot_digest,
    expected_analyzer_result_id,
    verify_analyzer_result,
)
from vheatm_control.tool_broker import ToolBroker, action_digest, expected_tool_receipt_id, request_digest
from vheatm_control.structural_probe import probe_workspace


ROOT = Path(__file__).resolve().parents[1]


def _provider() -> LocalAnalyzerProvider:
    return LocalAnalyzerProvider(ToolBroker.from_root(ROOT))


def test_probe_is_brokered_snapshot_bound_and_keeps_sources_tainted(tmp_path) -> None:
    source = tmp_path / "sample.py"
    source.write_text("def hello():\n    return 1\n", encoding="utf-8")
    baseline = probe_workspace(tmp_path, ["sample.py"], captured_at="2026-08-01T00:00:00Z")
    snapshot = snapshot_from_probe(baseline)
    request = build_analyzer_request(
        analyzer_id="python.structural", provider_id="local.python", provider_version="1.0.0", operation="probe",
        workspace_path=tmp_path, requested_paths=["sample.py"], source_snapshot=snapshot,
        session_root="a" * 64, captured_at="2026-08-01T00:00:00Z",
    )
    result = _provider().run(request)
    assert result["status"] == "complete"
    assert result["tool_receipt"]["decision"] == "allow"
    assert all(item["source"]["taint_state"] == "tainted" for item in result["output"]["files"])


def test_analyzer_result_verifier_rejects_scope_or_source_reference_drift(tmp_path) -> None:
    source = tmp_path / "sample.py"
    source.write_text("def hello():\n    return 1\n", encoding="utf-8")
    baseline = probe_workspace(tmp_path, ["sample.py"], captured_at="2026-08-01T00:00:00Z")
    request = build_analyzer_request(
        analyzer_id="python.structural", provider_id="local.python", provider_version="1.0.0", operation="probe",
        workspace_path=tmp_path, requested_paths=["sample.py"], source_snapshot=snapshot_from_probe(baseline),
        session_root="a" * 64, captured_at="2026-08-01T00:00:00Z",
    )
    result = _provider().run(request)
    drifted_scope = {**result, "session_root": "f" * 64}
    with pytest.raises(AnalyzerError, match="identity"):
        verify_analyzer_result(drifted_scope)
    drifted_refs = {**result, "source_refs": ["SRC-" + "0" * 64]}
    drifted_refs["result_id"] = expected_analyzer_result_id(drifted_refs)
    with pytest.raises(AnalyzerError, match="source references"):
        verify_analyzer_result(drifted_refs)
    detached_request = {
        "schema_version": "1.0.0", "request_id": result["request_id"], "requester": result["provider_id"],
        "tool_class": "read", "scope": "workspace:other", "secret_expansion": False, "contains_secrets": False,
    }
    detached_receipt = {**result["tool_receipt"], "request_digest": request_digest(detached_request), "action_digest": action_digest(detached_request)}
    detached_receipt["id"] = expected_tool_receipt_id(detached_receipt)
    detached_request_result = {**result, "tool_request": detached_request, "tool_receipt": detached_receipt}
    detached_request_result["result_id"] = expected_analyzer_result_id(detached_request_result)
    with pytest.raises(AnalyzerError, match="tool request|unsupported"):
        verify_analyzer_result(detached_request_result)
    receipt = verify_analyzer_result(result)
    assert receipt is not None
    assert all(item["source"]["taint_state"] == "tainted" for item in result["output"]["files"])


def test_analyzer_result_verifier_fail_closes_malformed_boundary_values(tmp_path) -> None:
    source = tmp_path / "sample.py"
    source.write_text("value = 1\n", encoding="utf-8")
    baseline = probe_workspace(tmp_path, ["sample.py"], captured_at="2026-08-01T00:00:00Z")
    request = build_analyzer_request(
        analyzer_id="python.structural", provider_id="local.python", provider_version="1.0.0", operation="probe",
        workspace_path=tmp_path, requested_paths=["sample.py"], source_snapshot=snapshot_from_probe(baseline),
        session_root="d" * 64, captured_at="2026-08-01T00:00:00Z",
    )
    result = _provider().run(request)
    with pytest.raises(AnalyzerError, match="object"):
        verify_analyzer_result(None)  # type: ignore[arg-type]
    malformed_refs = {**result, "source_refs": [[]]}
    with pytest.raises(AnalyzerError, match="source references"):
        verify_analyzer_result(malformed_refs)
    malformed_receipt = {**result, "tool_receipt": {**result["tool_receipt"], "request_digest": None}}
    with pytest.raises(AnalyzerError, match="tool receipt"):
        verify_analyzer_result(malformed_receipt)


def test_probe_blocks_when_workspace_changes_after_snapshot(tmp_path) -> None:
    source = tmp_path / "sample.py"
    source.write_text("value = 1\n", encoding="utf-8")
    baseline = probe_workspace(tmp_path, ["sample.py"], captured_at="2026-08-01T00:00:00Z")
    request = build_analyzer_request(
        analyzer_id="python.structural", provider_id="local.python", provider_version="1.0.0", operation="probe",
        workspace_path=tmp_path, requested_paths=["sample.py"], source_snapshot=snapshot_from_probe(baseline),
        session_root="b" * 64, captured_at="2026-08-01T00:00:00Z",
    )
    source.write_text("value = 2\n", encoding="utf-8")
    result = _provider().run(request)
    assert result["status"] == "blocked"
    assert result["output"] is None


def test_link_requires_the_exact_probe_snapshot(tmp_path) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("from .mod import value\n", encoding="utf-8")
    (tmp_path / "pkg" / "mod.py").write_text("value = 1\n", encoding="utf-8")
    probe = probe_workspace(tmp_path, ["pkg"], captured_at="2026-08-01T00:00:00Z")
    request = build_analyzer_request(
        analyzer_id="python.structural", provider_id="local.python", provider_version="1.0.0", operation="link",
        workspace_path=tmp_path, requested_paths=["pkg"], source_snapshot=snapshot_from_probe(probe),
        source_roots=["."], session_root="c" * 64, captured_at="2026-08-01T00:00:00Z",
    )
    result = _provider().run(request, input_probe=probe)
    assert result["status"] == "complete"
    assert result["output"]["input_probe_id"] == probe["probe_id"]
    bad_request = {**request, "snapshot_digest": snapshot_digest([{"path": "pkg/mod.py", "sha256": "d" * 64}])}
    with pytest.raises(AnalyzerError):
        _provider().run(bad_request, input_probe=probe)
