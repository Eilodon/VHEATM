from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from vheatm_control.analyzers import snapshot_digest
from vheatm_control.provider_policy import ProviderPolicyError, provider_config_digest, provider_descriptor
from vheatm_control.providers import (
    ExternalAnalyzerProvider,
    ProviderAdapterError,
    expected_provider_run_id,
    https_json_transport,
    verify_provider_run,
)


ROOT = Path(__file__).resolve().parents[1]


class FakeBroker:
    def __init__(self, allow: bool) -> None:
        self.allow = allow
        self.calls = 0

    def evaluate(self, request, approval_token=None):  # noqa: ANN001
        self.calls += 1
        return {
            "schema_version": "1.0.0",
            "request_id": request["request_id"],
            "decision": "allow" if self.allow else "deny",
            "reason": "test decision",
            "controls": ["test", "approval:verified"] if self.allow else ["test"],
            "evaluated_at": "2026-08-01T00:00:00Z",
            "approval_token_id": "APR-" + "A" * 64 if self.allow else None,
        }


def _request() -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "request_id": "ANR-" + "A" * 64,
        "analyzer_id": "python.remote",
        "provider_id": "remote.test",
        "provider_version": "1.0.0",
        "operation": "probe",
        "workspace_path": "/workspace",
        "requested_paths": ["src"],
        "source_snapshot": [{"path": "src/a.py", "sha256": "b" * 64}],
        "snapshot_digest": snapshot_digest([{"path": "src/a.py", "sha256": "b" * 64}]),
        "session_root": "d" * 64,
    }


def _provider(broker: FakeBroker, transport):  # noqa: ANN001
    return ExternalAnalyzerProvider(
        broker=broker,
        provider_id="remote.test",
        provider_version="1.0.0",
        endpoint="https://provider.example.test/analyze",
        config={"model": "fixed", "temperature": 0},
        transport=transport,
    )


def test_provider_allowlist_is_canonical_and_untrusted_descriptors_block() -> None:
    descriptor = provider_descriptor("remote.test", "1.0.0")
    assert descriptor["qualification_state"] == "pending"
    assert descriptor["adapter_profile"] == "remote-json-v1"
    assert descriptor["endpoint"] == "https://provider.example.test/analyze"
    assert descriptor["config_digest"] == provider_config_digest({"model": "fixed", "temperature": 0})
    with pytest.raises(ProviderPolicyError, match="not allowlisted"):
        provider_descriptor("untrusted.vendor", "1.0.0")


def test_provider_config_digest_rejects_non_finite_values() -> None:
    with pytest.raises(ProviderPolicyError, match="canonical JSON"):
        provider_config_digest({"temperature": float("nan")})


def test_external_provider_rejects_non_canonical_config_at_construction() -> None:
    with pytest.raises(ProviderAdapterError, match="config"):
        ExternalAnalyzerProvider(
            broker=FakeBroker(True),
            provider_id="remote.test",
            provider_version="1.0.0",
            endpoint="https://provider.example.test/analyze",
            config={"temperature": float("nan")},
            transport=lambda payload: payload,
        )


def test_revoked_provider_is_not_runtime_usable(monkeypatch) -> None:
    monkeypatch.setattr(
        "vheatm_control.provider_policy._load_policy",
        lambda root=None: {"providers": [{"provider_id": "remote.test", "provider_versions": ["1.0.0"], "qualification_state": "revoked"}]},
    )
    with pytest.raises(ProviderPolicyError, match="revoked"):
        provider_descriptor("remote.test", "1.0.0")


def test_external_provider_is_brokered_and_metadata_only() -> None:
    broker = FakeBroker(True)
    sent = []

    def transport(payload):
        sent.append(payload)
        return {"request_id": payload["request_id"], "provider_id": payload["provider_id"], "provider_version": payload["provider_version"], "output": {"candidate": True}}

    result = _provider(broker, transport).run(_request())
    assert result["status"] == "completed"
    assert result["epistemic_status"] == "candidate"
    assert broker.calls == 1
    assert "source_snapshot" in sent[0]
    assert "source" not in sent[0]
    schema = json.loads((ROOT / "schemas" / "provider-run.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(result)


def test_external_provider_denial_never_calls_transport() -> None:
    broker = FakeBroker(False)
    called = False

    def transport(payload):
        nonlocal called
        called = True
        return payload

    result = _provider(broker, transport).run(_request())
    assert result["status"] == "blocked"
    assert called is False


def test_external_provider_binding_drift_blocks_before_broker_or_transport() -> None:
    broker = FakeBroker(True)
    called = False

    def transport(payload):
        nonlocal called
        called = True
        return payload

    provider = ExternalAnalyzerProvider(
        broker=broker,
        provider_id="remote.test",
        provider_version="1.0.0",
        endpoint="https://attacker.example.test/analyze",
        config={"model": "fixed", "temperature": 0},
        transport=transport,
    )
    result = provider.run(_request())
    assert result["status"] == "blocked"
    assert "endpoint" in result["error"]
    assert broker.calls == 0
    assert called is False


def test_external_provider_config_binding_drift_blocks_before_broker_or_transport() -> None:
    broker = FakeBroker(True)
    called = False

    def transport(payload):
        nonlocal called
        called = True
        return payload

    provider = ExternalAnalyzerProvider(
        broker=broker,
        provider_id="remote.test",
        provider_version="1.0.0",
        endpoint="https://provider.example.test/analyze",
        config={"model": "attacker-controlled", "temperature": 0},
        transport=transport,
    )
    result = provider.run(_request())
    assert result["status"] == "blocked"
    assert "config digest" in result["error"]
    assert broker.calls == 0
    assert called is False


def test_external_provider_profile_binding_drift_blocks_before_broker() -> None:
    broker = FakeBroker(True)
    called = False

    def transport(payload):
        nonlocal called
        called = True
        return payload

    provider = ExternalAnalyzerProvider(
        broker=broker,
        provider_id="remote.test",
        provider_version="1.0.0",
        endpoint="https://provider.example.test/analyze",
        config={"model": "fixed", "temperature": 0},
        adapter_profile="unapproved-profile",
        transport=transport,
    )
    result = provider.run(_request())
    assert result["status"] == "blocked"
    assert "adapter profile" in result["error"]
    assert broker.calls == 0
    assert called is False


def test_external_provider_identity_mismatch_is_unknown() -> None:
    broker = FakeBroker(True)

    def transport(payload):
        return {"request_id": payload["request_id"], "provider_id": "other", "provider_version": "1.0.0"}

    result = _provider(broker, transport).run(_request())
    assert result["status"] == "unknown"
    assert "mismatch" in result["error"]


def test_persisted_provider_run_rejects_config_descriptor_drift() -> None:
    broker = FakeBroker(True)

    def transport(payload):
        return {"request_id": payload["request_id"], "provider_id": payload["provider_id"], "provider_version": payload["provider_version"], "output": {"candidate": True}}

    run = _provider(broker, transport).run(_request())
    tampered = {**run, "config_digest": "f" * 64}
    tampered["run_id"] = expected_provider_run_id(tampered)
    with pytest.raises(ProviderAdapterError, match="config digest"):
        verify_provider_run(tampered)


def test_malformed_provider_policy_decision_fails_closed_without_transport() -> None:
    class MalformedBroker:
        def evaluate(self, request, approval_token=None):  # noqa: ANN001
            return {
                "request_id": request["request_id"],
                "decision": "allow",
                "reason": "test decision",
                "controls": ["test"],
                "evaluated_at": "2026-08-01T00:00:00Z",
                "approval_token_id": "APR-" + "A" * 64,
            }

    called = False

    def transport(payload):
        nonlocal called
        called = True
        return payload

    result = _provider(MalformedBroker(), transport).run(_request())
    assert result["status"] == "blocked"
    assert result["network_receipt"] is None
    assert called is False
    schema = json.loads((ROOT / "schemas" / "provider-run.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(result)


def test_provider_defaults_to_bounded_https_transport(monkeypatch) -> None:
    class Response:
        headers = {"Content-Length": "18"}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, limit):
            assert limit == 1_048_577
            return b'{"status":"ok"}'

    class Opener:
        def open(self, request, timeout):
            assert request.full_url == "https://provider.example.test/analyze"
            assert request.get_method() == "POST"
            assert timeout == 2.0
            return Response()

    monkeypatch.setattr("vheatm_control.providers.build_opener", lambda _: Opener())
    assert https_json_transport("https://provider.example.test/analyze", {"metadata": True}, timeout_seconds=2.0) == {"status": "ok"}

    with pytest.raises(ProviderAdapterError, match="userinfo"):
        https_json_transport("https://user:pass@provider.example.test/analyze", {})
