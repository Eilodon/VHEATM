from __future__ import annotations

import copy
import shutil
from pathlib import Path

import pytest

from vheatm_control.host_qualification import (
    expected_host_qualification_run_id,
    run_host_qualification,
    validate_host_qualification_run,
)
from vheatm_control.evaluation import evaluate_release_gates
from vheatm_control.serialization import load_json


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = load_json((ROOT / "schemas" / "host-qualification-run.schema.json").read_text(encoding="utf-8"))


def test_host_runner_records_unavailable_backend_without_minting_verified_evidence(tmp_path: Path) -> None:
    run = run_host_qualification(
        ROOT,
        backend_path=tmp_path / "missing-bwrap",
        sample_count=2,
        observed_at="2026-08-02T00:00:00Z",
    )

    assert run["status"] == "blocked"
    assert run["evidence_state"] == "unverified"
    assert run["backend_digest"] is None
    assert run["measurements"] == []
    assert all(item["status"] == "unavailable" for item in run["observations"])
    assert validate_host_qualification_run(run, SCHEMA, root=ROOT) == []


def test_host_runner_does_not_treat_arbitrary_executable_as_bubblewrap(tmp_path: Path) -> None:
    fake_backend = tmp_path / "fake-backend"
    fake_backend.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_backend.chmod(0o755)

    run = run_host_qualification(
        ROOT,
        backend_path=fake_backend,
        sample_count=1,
        observed_at="2026-08-02T00:00:00Z",
    )

    assert run["status"] == "blocked"
    assert run["backend_digest"] is None
    assert run["observations"][0]["status"] == "unavailable"


def test_host_runner_rejects_complete_claim_without_observed_timeout() -> None:
    run = run_host_qualification(
        ROOT,
        backend_path=Path("/definitely/missing/bwrap"),
        sample_count=1,
        observed_at="2026-08-02T00:00:00Z",
    )
    forged = copy.deepcopy(run)
    forged["status"] = "complete"
    forged["run_id"] = expected_host_qualification_run_id(forged)

    issues = validate_host_qualification_run(forged, SCHEMA, root=ROOT)

    assert any("complete host qualification requires observed hard-stop samples" in issue for issue in issues)


def test_host_runner_rejects_status_not_derived_from_observations() -> None:
    run = run_host_qualification(
        ROOT,
        backend_path=Path("/definitely/missing/bwrap"),
        sample_count=1,
        observed_at="2026-08-02T00:00:00Z",
    )
    forged = copy.deepcopy(run)
    forged["status"] = "partial"
    forged["reference_monitor_status"] = "partial"
    forged["run_id"] = expected_host_qualification_run_id(forged)

    issues = validate_host_qualification_run(forged, SCHEMA, root=ROOT)

    assert any("status must be derived from observation statuses" in issue for issue in issues)


def test_unverified_host_record_cannot_mint_release_gate_status() -> None:
    run = run_host_qualification(
        ROOT,
        backend_path=Path("/definitely/missing/bwrap"),
        sample_count=1,
        observed_at="2026-08-02T00:00:00Z",
    )

    report = evaluate_release_gates(
        "17.0.0-dev.1",
        {"host_qualification_run": run},
        evaluated_at="2026-08-02T00:00:00Z",
    )

    assert report["summary"]["ga_eligible"] is False
    assert all(item["status"] == "unknown" for item in report["gates"])


@pytest.mark.skipif(shutil.which("bwrap") is None, reason="bubblewrap is unavailable")
def test_host_runner_uses_real_sandbox_and_only_emits_timeout_metric_when_observed() -> None:
    run = run_host_qualification(ROOT, sample_count=1, timeout_seconds=0.1, observed_at="2026-08-02T00:00:00Z")

    assert run["evidence_state"] == "unverified"
    if run["status"] == "complete":
        assert run["measurements"]
        assert run["measurements"][0]["metric"] == "hard_stop_p99_seconds"
        assert run["observations"][0]["status"] == "observed"
    else:
        assert run["status"] == "blocked"
        assert run["measurements"] == []
        assert any(item["status"] == "unavailable" for item in run["observations"])
