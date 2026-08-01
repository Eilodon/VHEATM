from __future__ import annotations

from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from vheatm_control.evaluation import evaluate_release_gates, expected_release_report_id
from vheatm_control.pilot import PilotError, complete_pilot, prepare_pilot, rollback_pilot
from vheatm_control.providers import build_provider_run, expected_provider_run_id
from vheatm_control.serialization import load_json
from vheatm_control.tool_broker import build_tool_receipt


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


def test_canary_rejects_self_declared_all_pass_release_report() -> None:
    report = _report()
    report["gates"] = [{**gate, "status": "pass", "missing_metrics": [], "failed_metrics": [], "rationale": "self-declared"} for gate in report["gates"]]
    report["summary"] = {"pass": 16, "fail": 0, "unknown": 0, "ga_eligible": True}
    report["evidence_bindings"] = [{"kind": "qualification_evidence", "id": "QEV-" + "A" * 64}]
    report["report_id"] = expected_release_report_id(report)
    with pytest.raises(PilotError, match="re-verified release evidence"):
        prepare_pilot(
            session_root="b" * 64,
            plan_id="PLN-" + "c" * 64,
            release_report=report,
            profile="canary",
            drills=_drills(),
            rollback_plan="rollback",
        )


def test_shadow_rejects_schema_invalid_release_report() -> None:
    report = _report()
    report.pop("evaluated_at")
    report["report_id"] = expected_release_report_id(report)
    with pytest.raises(PilotError, match="schema-valid release report"):
        prepare_pilot(
            session_root="b" * 64,
            plan_id="PLN-" + "c" * 64,
            release_report=report,
            drills=_drills(),
            rollback_plan="rollback",
        )


def test_shadow_rejects_duplicate_release_gate_ids() -> None:
    report = _report()
    report["gates"] = [dict(gate) for gate in report["gates"]]
    report["gates"][1]["gate_id"] = report["gates"][0]["gate_id"]
    report["report_id"] = expected_release_report_id(report)
    with pytest.raises(PilotError, match="canonical order"):
        prepare_pilot(
            session_root="b" * 64,
            plan_id="PLN-" + "c" * 64,
            release_report=report,
            drills=_drills(),
            rollback_plan="rollback",
        )


def test_shadow_completion_requires_real_read_only_observation() -> None:
    pilot = prepare_pilot(session_root="b" * 64, plan_id="PLN-" + "c" * 64, release_report=_report(), drills=_drills(), rollback_plan="rollback")
    network_request = {
        "schema_version": "1.0.0", "request_id": "NET-" + "b" * 64, "requester": "local.python",
        "tool_class": "network", "scope": "workspace:", "destination": "https://provider.example.test/analyze",
        "data_classes": ["source_digests"], "redacted": True,
    }
    request = {"request_id": "ANR-" + "a" * 64, "network_request_id": network_request["request_id"], "network_request": network_request}
    decision = {
        "schema_version": "1.0.0", "request_id": network_request["request_id"], "decision": "allow",
        "reason": "test approval", "controls": ["approval:verified"], "evaluated_at": "2026-08-01T00:00:00Z",
        "approval_token_id": "APR-" + "A" * 64,
    }
    receipt = build_tool_receipt(network_request, decision, recorded_at="2026-08-01T00:00:00Z")
    provider_run = build_provider_run(
        request=request,
        provider_id="local.python",
        provider_version="1.0.0",
        config_digest="c" * 64,
        network_receipt=receipt,
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
    tampered_pilot = {**pilot, "read_only": False, "tools_enabled": True}
    with pytest.raises(PilotError, match="identity"):
        complete_pilot(
            tampered_pilot,
            observations=[{**observation, "read_only_confirmed": False}],
            provider_runs=[provider_run],
        )
    tampered_run = {**provider_run, "network_receipt": {**provider_run["network_receipt"], "action_digest": "0" * 64}}
    tampered_run["run_id"] = expected_provider_run_id(tampered_run)
    tampered_observation = {**observation, "provider_run_refs": [tampered_run["run_id"]]}
    with pytest.raises(PilotError, match="receipt authorization chain"):
        complete_pilot(pilot, observations=[tampered_observation], provider_runs=[tampered_run])
    invalid_config_run = {**provider_run, "config_digest": "not-a-digest"}
    invalid_config_run["run_id"] = expected_provider_run_id(invalid_config_run)
    invalid_config_observation = {**observation, "provider_run_refs": [invalid_config_run["run_id"]]}
    with pytest.raises(PilotError, match="receipt authorization chain"):
        complete_pilot(pilot, observations=[invalid_config_observation], provider_runs=[invalid_config_run])
    with pytest.raises(PilotError, match="unknown"):
        complete_pilot(pilot, observations=[{**observation, "status": "unknown"}], provider_runs=[provider_run])
