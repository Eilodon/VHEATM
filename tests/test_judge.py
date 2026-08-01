from __future__ import annotations

import time

import pytest

from vheatm_control.judge import JudgeError, build_blind_packet, compare_verdicts, expected_verdict_id, resolve_hitl, run_independent_judge, validate_verdict_binding


def judge_yes(packet):
    return {"decisions": [{"item_id": item["item_id"], "label": "yes", "confidence": 0.9} for item in packet["items"]]}


def judge_no(packet):
    return {"decisions": [{"item_id": item["item_id"], "label": "no", "confidence": 0.9} for item in packet["items"]]}


def judge_slow(packet):
    time.sleep(2)
    return judge_yes(packet)


def _packet():
    return build_blind_packet(
        source_session_root="a" * 64, judge_context_root="b" * 64,
        origin_provider_id="origin.provider", origin_model_id="origin-model",
        judge_provider_id="judge.provider", judge_model_id="judge-model",
        config_digest="c" * 64, rubric_digest="d" * 64, order_seed="e" * 64,
        items=[{"item_id": "f-1", "text": "Is the control present?"}, {"item_id": "f-2", "text": "Is the evidence fresh?"}],
    )


def test_independent_judge_runs_in_separate_process_and_binds_randomized_order() -> None:
    packet = _packet()
    result = run_independent_judge(packet, judge_yes)
    assert result["status"] == "complete"
    assert result["verdict"]["epistemic_status"] == "independent_candidate"
    assert [item["item_id"] for item in result["verdict"]["decisions"]] == [item["item_id"] for item in packet["items"]]


def test_same_context_or_provider_cannot_be_marked_independent() -> None:
    with pytest.raises(JudgeError, match="distinct"):
        build_blind_packet(
            source_session_root="a" * 64, judge_context_root="a" * 64,
            origin_provider_id="origin.provider", origin_model_id="origin-model",
            judge_provider_id="judge.provider", judge_model_id="judge-model",
            config_digest="c" * 64, rubric_digest="d" * 64, order_seed="e" * 64,
            items=[{"item_id": "f-1", "text": "x"}],
        )


def test_timeout_blocks_and_divergence_escalates() -> None:
    packet = _packet()
    timed_out = run_independent_judge(packet, judge_slow, timeout_seconds=0.1)
    assert timed_out["status"] == "blocked"
    left = run_independent_judge(packet, judge_yes)["verdict"]
    right = run_independent_judge(packet, judge_no)["verdict"]
    comparison = compare_verdicts(left, right)
    assert comparison["status"] == "blocked"
    resolved = resolve_hitl(timed_out["escalation"], actor="owner", decision="defer", rationale="Provider unavailable")
    assert resolved["epistemic_status"] == "unknown"


def test_verdict_binding_requires_exact_packet_item_coverage() -> None:
    packet = _packet()
    verdict = run_independent_judge(packet, judge_yes)["verdict"]
    malformed = {**verdict, "decisions": [dict(verdict["decisions"][0]), {"item_id": "unbound-case", "label": "yes", "confidence": 0.9}]}
    malformed["verdict_id"] = expected_verdict_id(malformed)
    with pytest.raises(JudgeError, match="exactly cover packet items"):
        validate_verdict_binding(packet, malformed)
