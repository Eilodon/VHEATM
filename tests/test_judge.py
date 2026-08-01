from __future__ import annotations

import base64
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
from vheatm_control.signer_service import SignerClient

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def judge_yes(packet):
    return {"decisions": [{"item_id": item["item_id"], "label": "yes", "confidence": 0.9} for item in packet["items"]]}


def judge_no(packet):
    return {"decisions": [{"item_id": item["item_id"], "label": "no", "confidence": 0.9} for item in packet["items"]]}


def judge_slow(packet):
    time.sleep(2)
    return judge_yes(packet)


def _signer_client(key: Ed25519PrivateKey) -> SignerClient:
    def transport(request: dict[str, object]) -> dict[str, object]:
        payload = base64.urlsafe_b64decode(str(request["payload"]))
        return {
            "schema_version": "1.0.0",
            "request_id": request["request_id"],
            "framework_version": request["framework_version"],
            "bundle_root": request["bundle_root"],
            "purpose": request["purpose"],
            "key_id": request["key_id"],
            "signature_algorithm": "ed25519",
            "payload_digest": request["payload_digest"],
            "signature_value": base64.urlsafe_b64encode(key.sign(payload)).decode("ascii"),
            "signer_service_id": "test-kms",
            "signed_at": "2026-08-02T00:00:01Z",
        }

    return SignerClient(transport, root=ROOT)


def _packet():
    return build_blind_packet(
        source_session_root="a" * 64, judge_context_root="b" * 64,
        origin_provider_id="origin.provider", origin_model_id="origin-model",
        judge_provider_id="judge.test", judge_provider_version="1.0.0",
        judge_endpoint="https://judge.example.test/evaluate", judge_adapter_profile="judge-json-v1",
        judge_model_id="judge-model",
        config_digest="5a1a6363c4c7eab9cd90aacc3cd96f693f2816a185f0dd9f5b074f4678af7c5c", rubric_digest="d" * 64, order_seed="e" * 64,
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
            judge_provider_id="judge.test", judge_provider_version="1.0.0",
            judge_endpoint="https://judge.example.test/evaluate", judge_adapter_profile="judge-json-v1",
            judge_model_id="judge-model",
            config_digest="5a1a6363c4c7eab9cd90aacc3cd96f693f2816a185f0dd9f5b074f4678af7c5c", rubric_digest="d" * 64, order_seed="e" * 64,
            items=[{"item_id": "f-1", "text": "x"}],
        )


def test_non_allowlisted_judge_provider_is_rejected() -> None:
    with pytest.raises(JudgeError, match="not allowlisted"):
        build_blind_packet(
            source_session_root="a" * 64, judge_context_root="b" * 64,
            origin_provider_id="origin.provider", origin_model_id="origin-model",
            judge_provider_id="judge.provider", judge_provider_version="1.0.0",
            judge_endpoint="https://judge.example.test/evaluate", judge_adapter_profile="judge-json-v1",
            judge_model_id="judge-model",
            config_digest="5a1a6363c4c7eab9cd90aacc3cd96f693f2816a185f0dd9f5b074f4678af7c5c", rubric_digest="d" * 64, order_seed="e" * 64,
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


def test_verdict_can_delegate_to_external_signer_with_exact_scope() -> None:
    packet = build_blind_packet(
        source_session_root="a" * 64,
        judge_context_root="b" * 64,
        origin_provider_id="origin.provider",
        origin_model_id="origin-model",
        judge_provider_id="judge.test",
        judge_provider_version="1.0.0",
        judge_endpoint="https://judge.example.test/evaluate",
        judge_adapter_profile="judge-json-v1",
        judge_model_id="judge-model",
        config_digest="5a1a6363c4c7eab9cd90aacc3cd96f693f2816a185f0dd9f5b074f4678af7c5c",
        rubric_digest="d" * 64,
        order_seed="e" * 64,
        framework_version="17.0.0-dev.1",
        bundle_root="f" * 64,
        items=[{"item_id": "f-1", "text": "Is the control present?"}],
    )
    verdict = run_independent_judge(packet, judge_yes)["verdict"]
    key = Ed25519PrivateKey.generate()
    signed = sign_verdict(
        verdict,
        signer=_signer_client(key),
        framework_version="17.0.0-dev.1",
        bundle_root="f" * 64,
        public_key=key.public_key(),
        key_id="judge-key",
    )
    verify_signed_verdict(
        signed,
        public_key=key.public_key(),
        key_id="judge-key",
        expected_framework_version="17.0.0-dev.1",
        expected_bundle_root="f" * 64,
    )

    with pytest.raises(JudgeError, match="scope"):
        sign_verdict(
            verdict,
            signer=_signer_client(key),
            framework_version="17.0.0-wrong",
            bundle_root="f" * 64,
            public_key=key.public_key(),
            key_id="judge-key",
        )
    with pytest.raises(JudgeError, match="cannot be combined"):
        sign_verdict(
            verdict,
            private_key=key,
            signer=_signer_client(key),
            framework_version="17.0.0-dev.1",
            bundle_root="f" * 64,
            public_key=key.public_key(),
            key_id="judge-key",
        )
