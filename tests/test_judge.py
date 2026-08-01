from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vheatm_control.judge import (
    JudgeError,
    build_blind_packet,
    compare_verdicts,
    expected_verdict_id,
    resolve_hitl,
    run_independent_judge,
    sign_verdict,
    validate_verdict_binding,
    verify_signed_verdict,
)


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


def test_signed_verdict_is_required_for_persisted_independent_evidence() -> None:
    packet = _packet()
    candidate = run_independent_judge(packet, judge_yes)["verdict"]
    key = Ed25519PrivateKey.generate()
    signed = sign_verdict(candidate, private_key=key, key_id="judge-key")
    verify_signed_verdict(signed, public_key=key.public_key(), key_id="judge-key")

    tampered = {**signed, "decisions": [dict(signed["decisions"][0]), dict(signed["decisions"][1], label="no")]}
    tampered["verdict_id"] = expected_verdict_id(tampered)
    with pytest.raises(JudgeError, match="signature"):
        verify_signed_verdict(tampered, public_key=key.public_key(), key_id="judge-key")
