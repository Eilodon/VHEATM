from __future__ import annotations

import hashlib
import json
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Callable, Mapping

from .analyzers import snapshot_digest
from .tool_broker import action_digest, build_tool_receipt, expected_tool_receipt_id, request_digest, validate_policy_decision


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


def _validate_network_request(network_request: Mapping[str, Any]) -> None:
    required = {"schema_version", "request_id", "requester", "tool_class", "scope", "destination", "data_classes", "redacted"}
    if not isinstance(network_request, Mapping) or network_request.get("schema_version") != "1.0.0" or not required.issubset(network_request):
        raise ProviderAdapterError("provider network request is incomplete")
    if set(network_request) - required:
        raise ProviderAdapterError("provider network request contains unsupported fields")
    if not isinstance(network_request.get("request_id"), str) or not network_request["request_id"]:
        raise ProviderAdapterError("provider network request_id is invalid")
    if not isinstance(network_request.get("requester"), str) or not network_request["requester"].strip():
        raise ProviderAdapterError("provider network requester is invalid")
    if network_request.get("tool_class") != "network":
        raise ProviderAdapterError("provider network request tool class is invalid")
    if not isinstance(network_request.get("scope"), str) or not network_request["scope"].startswith("workspace:"):
        raise ProviderAdapterError("provider network request scope is invalid")
    destination = network_request.get("destination")
    parsed_destination = urlparse(destination) if isinstance(destination, str) else None
    if not isinstance(destination, str) or parsed_destination is None or parsed_destination.scheme != "https" or not parsed_destination.hostname or parsed_destination.username or parsed_destination.password:
        raise ProviderAdapterError("provider network request destination must be HTTPS")
    data_classes = network_request.get("data_classes")
    if not isinstance(data_classes, list) or not data_classes or any(not isinstance(item, str) or not item for item in data_classes) or len(data_classes) != len(set(data_classes)):
        raise ProviderAdapterError("provider network request data_classes are invalid")
    if network_request.get("redacted") is not True:
        raise ProviderAdapterError("provider network request must be redacted")


def _validate_network_receipt(network_request: Mapping[str, Any], receipt: Mapping[str, Any] | None, *, status: str) -> None:
    if receipt is None:
        if status == "completed":
            raise ProviderAdapterError("completed provider run requires an authorization receipt")
        return
    receipt_required = {"id", "request_id", "request_digest", "tool_class", "decision", "action_digest", "recorded_at", "approval_token_id"}
    if not receipt_required.issubset(receipt) or set(receipt) - receipt_required:
        raise ProviderAdapterError("provider network receipt is incomplete or contains unsupported fields")
    if receipt.get("request_id") != network_request.get("request_id"):
        raise ProviderAdapterError("provider network receipt is not bound to the network request")
    if receipt.get("tool_class") != "network" or receipt.get("decision") not in {"allow", "deny"}:
        raise ProviderAdapterError("provider network receipt has an invalid tool binding")
    if receipt.get("id") != expected_tool_receipt_id(receipt):
        raise ProviderAdapterError("provider network receipt identity is invalid")
    try:
        validate_policy_decision(
            {
                "schema_version": "1.0.0",
                "request_id": receipt.get("request_id"),
                "decision": receipt.get("decision"),
                "reason": "receipt-bound decision",
                "controls": ["receipt:validated"],
                "evaluated_at": receipt.get("recorded_at"),
                "approval_token_id": receipt.get("approval_token_id"),
            },
            network_request,
        )
    except Exception as exc:
        raise ProviderAdapterError(f"provider network receipt decision binding is invalid: {exc}") from exc
    if receipt.get("request_digest") != request_digest(network_request) or receipt.get("action_digest") != action_digest(network_request):
        raise ProviderAdapterError("provider network receipt digest binding is invalid")
    if status == "completed" and receipt.get("decision") != "allow":
        raise ProviderAdapterError("completed provider run requires an allowed network receipt")


def expected_provider_run_id(run: Mapping[str, Any]) -> str:
    return "PRV-" + _digest({key: value for key, value in run.items() if key != "run_id"}).upper()


def build_provider_run(
    *,
    request: Mapping[str, Any],
    provider_id: str,
    provider_version: str,
    config_digest: str,
    network_receipt: Mapping[str, Any] | None,
    status: str,
    response: Mapping[str, Any] | None,
    error: str | None,
    generated_at: str,
) -> dict[str, Any]:
    if status not in {"completed", "blocked", "unknown"}:
        raise ProviderAdapterError("provider status is invalid")
    if len(config_digest) != 64 or any(char not in "0123456789abcdef" for char in config_digest):
        raise ProviderAdapterError("provider config_digest must be lowercase SHA-256")
    network_request = request.get("network_request")
    _validate_network_request(network_request)
    if request.get("network_request_id") != network_request.get("request_id"):
        raise ProviderAdapterError("provider network_request_id is not bound to the network request")
    _validate_network_receipt(network_request, network_receipt, status=status)
    response_copy = deepcopy(dict(response)) if isinstance(response, Mapping) else None
    identity: dict[str, Any] = {
        "schema_version": "1.0.0",
        "request_id": str(request.get("request_id", "")),
        "provider_id": provider_id,
        "provider_version": provider_version,
        "config_digest": config_digest,
        "request_digest": request_digest(request),
        "network_request": deepcopy(dict(network_request)),
        "network_receipt": deepcopy(dict(network_receipt)) if isinstance(network_receipt, Mapping) else None,
        "status": status,
        "epistemic_status": "candidate" if status == "completed" else "unknown",
        "response_digest": _digest(response_copy),
        "response": response_copy,
        "generated_at": _timestamp(generated_at),
    }
    if error:
        identity["error"] = error
    return {"run_id": expected_provider_run_id(identity), **identity}


def verify_provider_run(run: Mapping[str, Any]) -> None:
    """Re-verify a persisted provider run before it can become pilot evidence."""

    required = {"schema_version", "run_id", "request_id", "provider_id", "provider_version", "config_digest", "request_digest", "network_request", "network_receipt", "status", "epistemic_status", "response_digest", "response", "generated_at"}
    if not isinstance(run, Mapping) or run.get("schema_version") != "1.0.0" or not required.issubset(run):
        raise ProviderAdapterError("provider run is incomplete")
    if set(run) - required - {"error"}:
        raise ProviderAdapterError("provider run contains unsupported fields")
    if run.get("run_id") != expected_provider_run_id(run):
        raise ProviderAdapterError("provider run identity is invalid")
    if not isinstance(run.get("request_id"), str) or not run["request_id"]:
        raise ProviderAdapterError("provider run request_id is invalid")
    provider_id = run.get("provider_id")
    if not isinstance(provider_id, str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{2,63}", provider_id):
        raise ProviderAdapterError("provider run provider_id is invalid")
    if not isinstance(run.get("provider_version"), str) or not run["provider_version"].strip():
        raise ProviderAdapterError("provider run provider_version is invalid")
    for field in ("config_digest", "request_digest", "response_digest"):
        value = run.get(field)
        if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
            raise ProviderAdapterError(f"provider run {field} is invalid")
    if run.get("status") not in {"completed", "blocked", "unknown"}:
        raise ProviderAdapterError("provider run status is invalid")
    if run.get("epistemic_status") != ("candidate" if run.get("status") == "completed" else "unknown"):
        raise ProviderAdapterError("provider run epistemic status is invalid")
    network_request = run.get("network_request")
    _validate_network_request(network_request)
    _validate_network_receipt(network_request, run.get("network_receipt"), status=str(run.get("status")))
    response = run.get("response")
    if response is not None and not isinstance(response, Mapping):
        raise ProviderAdapterError("provider run response must be an object or null")
    if run.get("response_digest") != _digest(deepcopy(dict(response)) if isinstance(response, Mapping) else None):
        raise ProviderAdapterError("provider run response digest is invalid")
    if run.get("status") == "completed" and not isinstance(response, Mapping):
        raise ProviderAdapterError("completed provider run requires a provider response")
    if "error" in run and (not isinstance(run["error"], str) or not run["error"].strip()):
        raise ProviderAdapterError("provider run error is invalid")
    _timestamp(str(run.get("generated_at")))


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
        request = {
            **dict(analyzer_request),
            "network_request_id": network_request["request_id"],
            "network_request": network_request,
        }
        generated_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        try:
            decision = self.broker.evaluate(network_request, approval_token)
            generated_at = str(decision.get("evaluated_at", generated_at))
            receipt = build_tool_receipt(network_request, decision, recorded_at=generated_at)
        except Exception as exc:  # authorization boundary failures are typed blocked outcomes
            return build_provider_run(
                request=request, provider_id=self.provider_id, provider_version=self.provider_version,
                config_digest=self.config_digest, network_receipt=None, status="blocked", response=None,
                error=f"provider authorization unavailable: {exc}", generated_at=generated_at,
            )
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
