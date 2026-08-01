from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime, timedelta
from typing import Any, Mapping

from .tool_broker import approval_signing_payload, expected_approval_token_id, request_digest


POLICY_KEY = b"vheatm-public-seeded-runner-key"


def build_qualification_approval_token(request: Mapping[str, Any], observed_at: str) -> dict[str, Any]:
    issued = datetime.fromisoformat(observed_at.replace("Z", "+00:00")) - timedelta(minutes=1)
    expires = issued + timedelta(minutes=10)
    token: dict[str, Any] = {
        "token_id": "APR-" + "0" * 64,
        "schema_version": "1.0.0",
        "requester": request["requester"],
        "tool_class": request["tool_class"],
        "exact_scope": request["scope"],
        "request_digest": request_digest(request),
        "issued_at": issued.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "expires_at": expires.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "approved_by": "operator:public-seeded-runner",
        "nonce": "public-seeded-runner-once",
        "single_use": True,
        "signature": {"algorithm": "hmac-sha256", "key_id": "runner-key", "value": "0" * 64},
    }
    token["token_id"] = expected_approval_token_id(token)
    token["signature"]["value"] = hmac.new(POLICY_KEY, approval_signing_payload(token), hashlib.sha256).hexdigest()
    return token
