from __future__ import annotations

from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from vheatm_control.pilot import PilotError, prepare_pilot, rollback_pilot
from vheatm_control.serialization import load_json


def _report(eligible: bool = False):
    return {"report_id": "RGR-" + "A" * 64, "summary": {"ga_eligible": eligible}}


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
