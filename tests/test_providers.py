from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from vheatm_control.analyzers import snapshot_digest
from vheatm_control.providers import ExternalAnalyzerProvider


ROOT = Path(__file__).resolve().parents[1]


class FakeBroker:
    def __init__(self, allow: bool) -> None:
        self.allow = allow
        self.calls = 0

    def evaluate(self, request, approval_token=None):  # noqa: ANN001
        self.calls += 1
        return {
            "request_id": request["request_id"],
            "decision": "allow" if self.allow else "deny",
            "reason": "test decision",
            "controls": ["test"],
            "evaluated_at": "2026-08-01T00:00:00Z",
            "approval_token_id": None,
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


def test_external_provider_identity_mismatch_is_unknown() -> None:
    broker = FakeBroker(True)

    def transport(payload):
        return {"request_id": payload["request_id"], "provider_id": "other", "provider_version": "1.0.0"}

    result = _provider(broker, transport).run(_request())
    assert result["status"] == "unknown"
    assert "mismatch" in result["error"]
