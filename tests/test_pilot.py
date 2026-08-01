from __future__ import annotations

from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from vheatm_control.evaluation import evaluate_release_gates, expected_release_report_id
from vheatm_control.pilot import PilotError, complete_pilot, prepare_pilot, rollback_pilot
from vheatm_control.providers import build_provider_run
from vheatm_control.serialization import load_json


def _report(eligible: bool = False):
    report = evaluate_release_gates("17.0.0-dev.1", {"metrics": {}}, evaluated_at="2026-08-01T00:00:00Z")
    if eligible:
        report["summary"] = {"pass": 16, "fail": 0, "unknown": 0, "ga_eligible": True}
        report["report_id"] = expected_release_report_id(report)
    return report


def _drills(status="pass"):
    return [{"drill_id": name, "status": status, "evidence_refs": [f"EV-{name}"]} for name in ["incident", "rollback", "evidence_store_outage", "clock_skew"]]


def test_shadow_pilot_is_read_only_and_requires_recovery_drills() -> None:
    pilot = prepare_pilot(session_root="b" * 64, plan_id="PLN-" + "c" * 64, release_report=_report(), drills=_drills(), rollback_plan="disable provider and resume from last journal hash", created_at="2026-08-01T00:00:00Z")
    assert pilot["profile"] == "shadow"
    assert pilot["read_only"] is True
    assert pilot["tools_enabled"] is False
    assert pilot["status"] == "ready"
    schema = load_json((Path("schemas") / "pilot-run.schema.json").read_text())
    Draft202012Validator(schema).validate(pilot)


def test_canary_and_failed_drill_block() -> None:
    with pytest.raises(PilotError, match="canary"):
        prepare_pilot(session_root="b" * 64, plan_id="PLN-" + "c" * 64, release_report=_report(False), profile="canary", drills=_drills(), rollback_plan="rollback")
    pilot = prepare_pilot(session_root="b" * 64, plan_id="PLN-" + "c" * 64, release_report=_report(), drills=_drills("unknown"), rollback_plan="rollback")
    assert pilot["status"] == "blocked"
    with pytest.raises(PilotError, match="only"):
        rollback_pilot(pilot, reason="provider outage")


def test_shadow_completion_requires_real_read_only_observation() -> None:
    pilot = prepare_pilot(session_root="b" * 64, plan_id="PLN-" + "c" * 64, release_report=_report(), drills=_drills(), rollback_plan="rollback")
    request = {"request_id": "ANR-" + "a" * 64, "network_request_id": "NET-" + "b" * 64}
    provider_run = build_provider_run(
        request=request,
        provider_id="local.python",
        provider_version="1.0.0",
        config_digest="c" * 64,
        network_receipt={"request_id": request["network_request_id"], "decision": "allow"},
        status="completed",
        response={"candidate": True},
        error=None,
        generated_at="2026-08-01T00:00:00Z",
    )
    observation = {"observation_id": "OBS-1", "status": "pass", "provider_id": "local.python", "provider_run_refs": [provider_run["run_id"]], "sample_count": 10, "read_only_confirmed": True, "evidence_refs": ["EV-shadow-1"], "observed_at": "2026-08-01T00:00:00Z"}
    complete = complete_pilot(pilot, observations=[observation], provider_runs=[provider_run], completed_at="2026-08-01T00:01:00Z")
    assert complete["status"] == "complete"
    assert complete["pilot_id"] != pilot["pilot_id"]
    schema = load_json((Path("schemas") / "pilot-run.schema.json").read_text())
    Draft202012Validator(schema).validate(complete)
    with pytest.raises(PilotError, match="unknown"):
        complete_pilot(pilot, observations=[{**observation, "status": "unknown"}], provider_runs=[provider_run])
