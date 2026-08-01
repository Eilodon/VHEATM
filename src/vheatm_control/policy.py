"""Compatibility surface for the canonical VHEATM tool broker.

The old in-process policy engine is preserved as a non-authoritative text
archive under ``docs/migration/legacy-policy.py.txt``. Runtime callers must
use :class:`vheatm_control.tool_broker.ToolBroker`; this module deliberately
does not provide a second authorization implementation.
"""

from .tool_broker import (
    BrokerCapabilities,
    BrokerConfigurationError,
    BrokerSchemas,
    DirectoryTokenLedger,
    InMemoryTokenLedger,
    TokenLedger,
    ToolBroker,
    action_digest,
    approval_signing_payload,
    build_tool_receipt,
    expected_approval_token_id,
    expected_tool_receipt_id,
    request_digest,
    validate_policy_decision,
)

__all__ = [
    "BrokerCapabilities",
    "BrokerConfigurationError",
    "BrokerSchemas",
    "DirectoryTokenLedger",
    "InMemoryTokenLedger",
    "TokenLedger",
    "ToolBroker",
    "action_digest",
    "approval_signing_payload",
    "build_tool_receipt",
    "expected_approval_token_id",
    "expected_tool_receipt_id",
    "request_digest",
    "validate_policy_decision",
]

_RETIRED_NAMES = frozenset({"ApprovalLedger", "ApprovalVerifier", "GuardedExecutor", "PolicyDecision", "PolicyEngine", "PolicyDenied", "PolicyError", "sign_approval_token"})


def __getattr__(name: str):  # noqa: ANN001
    if name in _RETIRED_NAMES:
        raise AttributeError(
            f"vheatm_control.policy.{name} is retired; use vheatm_control.tool_broker.ToolBroker"
        )
    raise AttributeError(name)
