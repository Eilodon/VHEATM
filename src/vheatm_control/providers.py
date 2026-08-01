from __future__ import annotations

import hashlib
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Callable, Mapping

from .analyzers import snapshot_digest
from .tool_broker import build_tool_receipt, request_digest


class ProviderAdapterError(ValueError):
    """Raised when an external provider record is malformed."""


ProviderTransport = Callable[[Mapping[str, Any]], Mapping[str, Any]]


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def https_json_transport(
    endpoint: str,
    payload: Mapping[str, Any],
    *,
    timeout_seconds: float = 10.0,
    max_response_bytes: int = 1_048_576,
) -> Mapping[str, Any]:
    """Send the provider's metadata-only JSON request over bounded HTTPS.

    This function is deliberately transport-only. Authorization, destination
    allowlisting, redaction, and human approval remain the broker's job and are
    checked before the provider calls it.
    """

    parsed = urlparse(endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ProviderAdapterError("provider endpoint must be an HTTPS URL without userinfo")
    if timeout_seconds <= 0 or max_response_bytes < 1:
        raise ProviderAdapterError("provider transport limits must be positive")
    body = _canonical(dict(payload))
    request = Request(
        endpoint,
        data=body,
        headers={"Accept": "application/json", "Content-Type": "application/json", "Content-Length": str(len(body))},
        method="POST",
    )
    opener = build_opener(_NoRedirect)
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    declared_length = int(content_length)
                except ValueError as exc:
                    raise ProviderAdapterError("provider response has an invalid Content-Length") from exc
                if declared_length < 0 or declared_length > max_response_bytes:
                    raise ProviderAdapterError("provider response exceeds the configured byte limit")
            raw = response.read(max_response_bytes + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise ProviderAdapterError(f"HTTPS provider request failed: {exc}") from exc
    if len(raw) > max_response_bytes:
        raise ProviderAdapterError("provider response exceeds the configured byte limit")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProviderAdapterError("provider response is not UTF-8 JSON") from exc
    if not isinstance(value, Mapping):
        raise ProviderAdapterError("provider response must be a JSON object")
    return value


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProviderAdapterError("provider timestamps must be RFC 3339") from exc
    if parsed.tzinfo is None:
        raise ProviderAdapterError("provider timestamps must include a timezone")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def expected_provider_run_id(run: Mapping[str, Any]) -> str:
    return "PRV-" + _digest({key: value for key, value in run.items() if key != "run_id"}).upper()


def build_provider_run(
    *,
    request: Mapping[str, Any],
    provider_id: str,
    provider_version: str,
    config_digest: str,
    network_receipt: Mapping[str, Any],
    status: str,
    response: Mapping[str, Any] | None,
    error: str | None,
    generated_at: str,
) -> dict[str, Any]:
    if status not in {"completed", "blocked", "unknown"}:
        raise ProviderAdapterError("provider status is invalid")
    if len(config_digest) != 64 or any(char not in "0123456789abcdef" for char in config_digest):
        raise ProviderAdapterError("provider config_digest must be lowercase SHA-256")
    if network_receipt.get("request_id") != request.get("network_request_id"):
        raise ProviderAdapterError("provider network receipt is not bound to the request")
    response_copy = deepcopy(dict(response)) if isinstance(response, Mapping) else None
    identity: dict[str, Any] = {
        "schema_version": "1.0.0",
        "request_id": str(request.get("request_id", "")),
        "provider_id": provider_id,
        "provider_version": provider_version,
        "config_digest": config_digest,
        "request_digest": request_digest(request),
        "network_receipt": deepcopy(dict(network_receipt)),
        "status": status,
        "epistemic_status": "candidate" if status == "completed" else "unknown",
        "response_digest": _digest(response_copy),
        "response": response_copy,
        "generated_at": _timestamp(generated_at),
    }
    if error:
        identity["error"] = error
    return {"run_id": expected_provider_run_id(identity), **identity}


@dataclass(frozen=True)
class ExternalAnalyzerProvider:
    """Metadata-only external analyzer adapter behind a brokered transport.

    The transport is an injected, already-governed network capability. This
    class never opens sockets and never sends source contents; only provider
    identity, requested paths, and immutable source digests are transmitted.
    """

    broker: Any
    provider_id: str
    provider_version: str
    endpoint: str
    config: Mapping[str, Any]
    transport: ProviderTransport | None = None
    timeout_seconds: float = 10.0
    max_response_bytes: int = 1_048_576

    def __post_init__(self) -> None:
        if not self.provider_id or not self.provider_version or not self.endpoint.startswith("https://"):
            raise ProviderAdapterError("provider identity and HTTPS endpoint are required")
        parsed = urlparse(self.endpoint)
        if parsed.username or parsed.password or not parsed.hostname:
            raise ProviderAdapterError("provider endpoint must be an HTTPS URL without userinfo")
        if self.timeout_seconds <= 0 or self.max_response_bytes < 1:
            raise ProviderAdapterError("provider transport limits must be positive")
        if self.transport is None:
            object.__setattr__(
                self,
                "transport",
                lambda payload: https_json_transport(
                    self.endpoint,
                    payload,
                    timeout_seconds=self.timeout_seconds,
                    max_response_bytes=self.max_response_bytes,
                ),
            )
        elif not callable(self.transport):
            raise ProviderAdapterError("provider transport must be callable")

    @property
    def config_digest(self) -> str:
        return _digest(dict(self.config))

    def run(self, analyzer_request: Mapping[str, Any], *, approval_token: Mapping[str, Any] | None = None) -> dict[str, Any]:
        required = {"request_id", "analyzer_id", "provider_id", "provider_version", "requested_paths", "source_snapshot", "snapshot_digest", "session_root"}
        if not required.issubset(analyzer_request):
            raise ProviderAdapterError("analyzer request is incomplete")
        if analyzer_request.get("provider_id") != self.provider_id or analyzer_request.get("provider_version") != self.provider_version:
            raise ProviderAdapterError("analyzer request provider descriptor does not match adapter")
        if snapshot_digest(analyzer_request["source_snapshot"]) != analyzer_request.get("snapshot_digest"):
            raise ProviderAdapterError("analyzer request source snapshot digest is invalid")
        network_request: dict[str, Any] = {
            "schema_version": "1.0.0",
            "request_id": "NET-" + _digest({"request_id": analyzer_request["request_id"], "endpoint": self.endpoint}).upper(),
            "requester": self.provider_id,
            "tool_class": "network",
            "scope": "workspace:",
            "destination": self.endpoint,
            "data_classes": ["source_digests"],
            "redacted": True,
        }
        decision = self.broker.evaluate(network_request, approval_token)
        receipt = build_tool_receipt(network_request, decision, recorded_at=str(decision.get("evaluated_at", datetime.now(UTC).isoformat().replace("+00:00", "Z"))))
        request = {
            **dict(analyzer_request),
            "network_request_id": network_request["request_id"],
            "network_request": network_request,
        }
        if decision.get("decision") != "allow":
            return build_provider_run(
                request=request, provider_id=self.provider_id, provider_version=self.provider_version,
                config_digest=self.config_digest, network_receipt=receipt, status="blocked", response=None,
                error=str(decision.get("reason", "network policy denied provider")),
                generated_at=str(decision.get("evaluated_at", datetime.now(UTC).isoformat().replace("+00:00", "Z"))),
            )
        payload = {
            "request_id": analyzer_request["request_id"],
            "analyzer_id": analyzer_request["analyzer_id"],
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "config_digest": self.config_digest,
            "requested_paths": sorted(str(path) for path in analyzer_request["requested_paths"]),
            "source_snapshot": deepcopy(list(analyzer_request["source_snapshot"])),
            "snapshot_digest": analyzer_request["snapshot_digest"],
            "session_root": analyzer_request["session_root"],
        }
        try:
            response = self.transport(payload)
        except Exception as exc:  # provider outage is an explicit unknown boundary
            return build_provider_run(
                request=request, provider_id=self.provider_id, provider_version=self.provider_version,
                config_digest=self.config_digest, network_receipt=receipt, status="unknown", response=None,
                error=f"provider outage: {exc}", generated_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            )
        if not isinstance(response, Mapping):
            return build_provider_run(
                request=request, provider_id=self.provider_id, provider_version=self.provider_version,
                config_digest=self.config_digest, network_receipt=receipt, status="unknown", response=None,
                error="provider response must be an object", generated_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            )
        if response.get("request_id") != analyzer_request["request_id"] or response.get("provider_id") != self.provider_id or response.get("provider_version") != self.provider_version:
            return build_provider_run(
                request=request, provider_id=self.provider_id, provider_version=self.provider_version,
                config_digest=self.config_digest, network_receipt=receipt, status="unknown", response=dict(response),
                error="provider response identity mismatch", generated_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            )
        return build_provider_run(
            request=request, provider_id=self.provider_id, provider_version=self.provider_version,
            config_digest=self.config_digest, network_receipt=receipt, status="completed", response=dict(response),
            error=None, generated_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        )
