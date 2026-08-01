from datetime import UTC, datetime

import pytest

from vheatm_control.policy import (
    ApprovalLedger,
    ApprovalVerifier,
    GuardedExecutor,
    PolicyDenied,
    PolicyEngine,
    request_digest,
    sign_approval_token,
)

POLICY = {
    "tools": {"classes": {name: {} for name in ["read", "execute", "write", "network", "secrets"]}},
    "egress": {"destinations": ["https://api.example.com"], "prohibited_data": ["secrets", "raw_pii", "unreviewed_source"]},
}
KEY = b"approval-secret-out-of-band"
NOW = datetime(2026, 7, 31, 15, 0, tzinfo=UTC)


def token_for(request: dict, *, expires_at: str = "2026-07-31T16:00:00Z", ledger=None) -> tuple[dict, ApprovalVerifier]:
    token = sign_approval_token(
        {
            "requester": request["requester"],
            "tool_class": request["tool_class"],
            "exact_scope": request["scope"],
            "request_digest": request_digest(request),
            "issued_at": "2026-07-31T14:00:00Z",
            "expires_at": expires_at,
            "approved_by": "human-reviewer",
            "nonce": "nonce-1",
        },
        key=KEY,
        key_id="human-1",
    )
    return token, ApprovalVerifier({"human-1": KEY}, ledger=ledger)


def test_read_is_allowed_only_inside_workspace_without_secrets() -> None:
    engine = PolicyEngine(POLICY)
    allowed = engine.authorize({"request_id": "R1", "requester": "agent", "tool_class": "read", "scope": "workspace:/repo"})
    denied = engine.authorize({"request_id": "R2", "requester": "agent", "tool_class": "read", "scope": "workspace:/repo", "contains_secrets": True})
    assert allowed.decision == "allow"
    assert denied.decision == "deny"


def test_guarded_executor_does_not_call_denied_action() -> None:
    called = False

    def action() -> str:
        nonlocal called
        called = True
        return "ran"

    engine = PolicyEngine(POLICY)
    with pytest.raises(PolicyDenied):
        GuardedExecutor(engine).run(
            {"request_id": "R3", "requester": "agent", "tool_class": "write", "scope": "workspace:/repo"},
            action,
            now=NOW,
        )
    assert called is False


def test_execute_requires_exact_signed_scope_sandbox_and_allowlist() -> None:
    request = {
        "request_id": "R4",
        "requester": "agent",
        "tool_class": "execute",
        "scope": "workspace:/repo:test",
        "sandboxed": True,
        "command": "pytest",
        "network_enabled": False,
        "inherit_secrets": False,
    }
    token, verifier = token_for(request)
    engine = PolicyEngine(POLICY, approval_verifier=verifier, command_allowlist={"pytest"})
    decision = engine.authorize(request, approval_token=token, now=NOW)
    assert decision.decision == "allow"
    assert decision.approval_token_id == token["token_id"]


def test_approval_is_single_use_and_scope_bound() -> None:
    request = {
        "request_id": "R5",
        "requester": "agent",
        "tool_class": "write",
        "scope": "workspace:/repo:file-a",
        "diff_paths": ["file-a"],
        "rollback_plan": "git restore file-a",
    }
    ledger = ApprovalLedger()
    token, verifier = token_for(request, ledger=ledger)
    engine = PolicyEngine(POLICY, approval_verifier=verifier)
    assert engine.authorize(request, approval_token=token, now=NOW).decision == "allow"
    assert engine.authorize(request, approval_token=token, now=NOW).decision == "deny"

    other = dict(request, request_id="R6", scope="workspace:/repo:file-b")
    other_token, other_verifier = token_for(request)
    other_engine = PolicyEngine(POLICY, approval_verifier=other_verifier)
    assert other_engine.authorize(other, approval_token=other_token, now=NOW).decision == "deny"


def test_network_rejects_prohibited_data_even_with_approval() -> None:
    request = {
        "request_id": "R7",
        "requester": "agent",
        "tool_class": "network",
        "scope": "workspace:/repo:egress",
        "destination": "https://api.example.com",
        "data_classes": ["raw_pii"],
        "redacted": True,
    }
    token, verifier = token_for(request)
    engine = PolicyEngine(POLICY, approval_verifier=verifier)
    decision = engine.authorize(request, approval_token=token, now=NOW)
    assert decision.decision == "deny"
    assert "prohibited" in decision.reason


def test_expired_token_is_denied() -> None:
    request = {
        "request_id": "R8",
        "requester": "agent",
        "tool_class": "write",
        "scope": "workspace:/repo:file-a",
        "diff_paths": ["file-a"],
        "rollback_plan": "restore",
    }
    token, verifier = token_for(request, expires_at="2026-07-31T14:30:00Z")
    engine = PolicyEngine(POLICY, approval_verifier=verifier)
    assert engine.authorize(request, approval_token=token, now=NOW).decision == "deny"


def test_denied_preconditions_do_not_burn_approval() -> None:
    request = {
        "request_id": "R9",
        "requester": "agent",
        "tool_class": "execute",
        "scope": "workspace:/repo:test",
        "sandboxed": False,
        "command": "pytest",
        "network_enabled": False,
        "inherit_secrets": False,
    }
    token, verifier = token_for(request)
    engine = PolicyEngine(POLICY, approval_verifier=verifier, command_allowlist={"pytest"})
    assert engine.authorize(request, approval_token=token, now=NOW).decision == "deny"
    request["sandboxed"] = True
    assert engine.authorize(request, approval_token=token, now=NOW).decision == "deny"
    refreshed_token, refreshed_verifier = token_for(request)
    refreshed_engine = PolicyEngine(POLICY, approval_verifier=refreshed_verifier, command_allowlist={"pytest"})
    assert refreshed_engine.authorize(request, approval_token=refreshed_token, now=NOW).decision == "allow"
