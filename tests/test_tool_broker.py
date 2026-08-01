from __future__ import annotations

import copy
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from vheatm_control.tool_broker import (
    action_digest,
    BrokerCapabilities,
    InMemoryTokenLedger,
    ToolBroker,
    approval_signing_payload,
    build_tool_receipt,
    expected_approval_token_id,
    expected_tool_receipt_id,
    request_digest,
)

NOW = datetime(2026, 8, 1, 0, 0, tzinfo=timezone.utc)
KEY = b"test-broker-key-material"


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _broker(root: Path, *, commands: set[str] | None = None, secrets: set[str] | None = None) -> ToolBroker:
    del root
    return ToolBroker.from_root(
        PROJECT_ROOT,
        keyring={"operator-key": KEY},
        capabilities=BrokerCapabilities(
            exact_command_allowlist=frozenset(commands or set()),
            known_secret_names=frozenset(secrets or set()),
        ),
        token_ledger=InMemoryTokenLedger(),
        clock=lambda: NOW,
    )


def _request(tool_class: str, **extra: object) -> dict[str, object]:
    request: dict[str, object] = {
        "schema_version": "1.0.0",
        "request_id": f"REQ-{tool_class}",
        "requester": "module:MOD-TEST",
        "tool_class": tool_class,
        "scope": "workspace:src",
    }
    request.update(extra)
    return request


def _token(request: dict[str, object], *, token_id: str = "APR-" + "01" * 32) -> dict[str, object]:
    token: dict[str, object] = {
        "token_id": token_id,
        "schema_version": "1.0.0",
        "requester": request["requester"],
        "tool_class": request["tool_class"],
        "exact_scope": request["scope"],
        "request_digest": request_digest(request),
        "issued_at": (NOW - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        "approved_by": "operator:alice",
        "nonce": "nonce-" + token_id,
        "single_use": True,
        "signature": {
            "algorithm": "hmac-sha256",
            "key_id": "operator-key",
            "value": "0" * 64,
        },
    }
    token["token_id"] = expected_approval_token_id(token)
    token["signature"]["value"] = hmac.new(KEY, approval_signing_payload(token), hashlib.sha256).hexdigest()  # type: ignore[index]
    return token


def test_read_allows_only_explicit_non_secret_access(tmp_path: Path) -> None:
    broker = _broker(tmp_path)
    request = _request("read", secret_expansion=False, contains_secrets=False)
    assert broker.evaluate(request)["decision"] == "allow"

    missing_declaration = copy.deepcopy(request)
    missing_declaration.pop("contains_secrets")
    decision = broker.evaluate(missing_declaration)
    assert decision["decision"] == "deny"
    assert "contains no secrets" in decision["reason"]


def test_read_rejects_scope_traversal(tmp_path: Path) -> None:
    broker = _broker(tmp_path)
    decision = broker.evaluate(
        _request("read", scope="workspace:src/../secrets", secret_expansion=False, contains_secrets=False)
    )
    assert decision["decision"] == "deny"
    assert "safe workspace-relative" in decision["reason"]


def test_execute_requires_valid_approval_and_exact_command(tmp_path: Path) -> None:
    broker = _broker(tmp_path, commands={"pytest -q"})
    request = _request(
        "execute",
        sandboxed=True,
        command="pytest -q",
        network_enabled=False,
        inherit_secrets=False,
    )
    assert broker.evaluate(request)["decision"] == "deny"
    assert broker.evaluate(request, _token(request))["decision"] == "allow"

    other = copy.deepcopy(request)
    other["command"] = "pytest -q tests/test_tool_broker.py"
    assert broker.evaluate(other, _token(other, token_id="APR-" + "11" * 32))["decision"] == "deny"


def test_execute_blocks_sandbox_network_and_secret_inheritance_gaps(tmp_path: Path) -> None:
    broker = _broker(tmp_path, commands={"pytest -q"})
    base = _request(
        "execute",
        sandboxed=True,
        command="pytest -q",
        network_enabled=False,
        inherit_secrets=False,
    )
    mutations = {
        "sandboxed": False,
        "network_enabled": True,
        "inherit_secrets": True,
    }
    for index, (field, value) in enumerate(mutations.items()):
        request = copy.deepcopy(base)
        request[field] = value
        token = _token(request, token_id=f"APR-{index + 2:064X}")
        assert broker.evaluate(request, token)["decision"] == "deny"


def test_approval_binding_signature_expiry_and_replay(tmp_path: Path) -> None:
    broker = _broker(tmp_path, commands={"pytest -q"})
    request = _request(
        "execute",
        sandboxed=True,
        command="pytest -q",
        network_enabled=False,
        inherit_secrets=False,
    )
    token = _token(request)
    assert broker.evaluate(request, token)["decision"] == "allow"
    replay = broker.evaluate(request, token)
    assert replay["decision"] == "deny"
    assert "already been consumed" in replay["reason"]

    bad_scope = _token(request, token_id="APR-" + "22" * 32)
    bad_scope["exact_scope"] = "workspace:tests"
    bad_scope["signature"]["value"] = hmac.new(KEY, approval_signing_payload(bad_scope), hashlib.sha256).hexdigest()  # type: ignore[index]
    assert broker.evaluate(request, bad_scope)["decision"] == "deny"

    expired = _token(request, token_id="APR-" + "33" * 32)
    expired["expires_at"] = (NOW - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    expired["signature"]["value"] = hmac.new(KEY, approval_signing_payload(expired), hashlib.sha256).hexdigest()  # type: ignore[index]
    assert broker.evaluate(request, expired)["decision"] == "deny"


def test_verified_token_is_consumed_even_when_command_control_denies(tmp_path: Path) -> None:
    broker = _broker(tmp_path, commands={"pytest -q"})
    request = _request(
        "execute",
        sandboxed=True,
        command="pytest -q tests",
        network_enabled=False,
        inherit_secrets=False,
    )
    token = _token(request, token_id="APR-" + "66" * 32)
    first = broker.evaluate(request, token)
    assert first["decision"] == "deny"
    assert "not present" in first["reason"]
    second = broker.evaluate(request, token)
    assert second["decision"] == "deny"
    assert "already been consumed" in second["reason"]


def test_write_paths_must_remain_within_exact_scope(tmp_path: Path) -> None:
    broker = _broker(tmp_path)
    valid = _request("write", diff_paths=["src/a.py", "src/pkg/b.py"], rollback_plan="git revert the scoped diff")
    assert broker.evaluate(valid, _token(valid))["decision"] == "allow"

    escaped = _request("write", diff_paths=["tests/a.py"], rollback_plan="revert")
    decision = broker.evaluate(escaped, _token(escaped, token_id="APR-" + "44" * 32))
    assert decision["decision"] == "deny"
    assert "escapes" in decision["reason"]


def test_network_is_denied_while_policy_destination_allowlist_is_empty(tmp_path: Path) -> None:
    broker = _broker(tmp_path)
    request = _request(
        "network",
        destination="https://example.com",
        data_classes=["public"],
        redacted=True,
    )
    decision = broker.evaluate(request, _token(request))
    assert decision["decision"] == "deny"
    assert "not allowlisted" in decision["reason"]


def test_secret_request_requires_registered_name_and_non_disclosure_controls(tmp_path: Path) -> None:
    broker = _broker(tmp_path, secrets={"ci-read-token"})
    request = _request(
        "secrets",
        secret_name="ci-read-token",
        least_privilege=True,
        no_model_echo=True,
    )
    assert broker.evaluate(request, _token(request))["decision"] == "allow"

    unknown = copy.deepcopy(request)
    unknown["secret_name"] = "production-root"
    assert broker.evaluate(unknown, _token(unknown, token_id="APR-" + "55" * 32))["decision"] == "deny"


def test_all_decisions_match_canonical_schema(tmp_path: Path) -> None:
    broker = _broker(tmp_path)
    decisions = [
        broker.evaluate(_request("read", secret_expansion=False, contains_secrets=False)),
        broker.evaluate(_request("execute", sandboxed=True, command="pytest -q", network_enabled=False, inherit_secrets=False)),
        broker.evaluate({"unexpected": True}),
    ]
    schema = json.loads((PROJECT_ROOT / "schemas" / "policy-decision.schema.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for decision in decisions:
        assert not list(validator.iter_errors(decision))


def test_approval_and_receipt_bind_full_request_and_action() -> None:
    request = _request("execute", sandboxed=True, command="pytest -q", network_enabled=False, inherit_secrets=False)
    token = _token(request)
    mutated = copy.deepcopy(request)
    mutated["command"] = "pytest -q tests"
    broker = _broker(PROJECT_ROOT, commands={"pytest -q", "pytest -q tests"})
    assert broker.evaluate(mutated, token)["decision"] == "deny"

    decision = broker.evaluate(request, _token(request, token_id="APR-" + "77" * 32))
    receipt = build_tool_receipt(request, decision, recorded_at="2026-08-01T00:00:00Z")
    assert receipt["request_digest"] == request_digest(request)
    assert receipt["action_digest"] == action_digest(request)
    assert receipt["id"] == expected_tool_receipt_id(receipt)
