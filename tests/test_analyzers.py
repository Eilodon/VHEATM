from __future__ import annotations

from pathlib import Path

import pytest

from vheatm_control.analyzers import (
    LocalAnalyzerProvider,
    AnalyzerError,
    build_analyzer_request,
    snapshot_from_probe,
    snapshot_digest,
    verify_analyzer_result,
)
from vheatm_control.tool_broker import ToolBroker
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
    receipt = verify_analyzer_result(result)
    assert receipt is not None
    assert all(item["source"]["taint_state"] == "tainted" for item in result["output"]["files"])


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
