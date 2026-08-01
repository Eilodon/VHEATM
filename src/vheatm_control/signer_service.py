from __future__ import annotations

import base64
import binascii
import hashlib
import json
import socket
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker

from .bundle import resolve_control_root
from .serialization import load_json


class SignerServiceError(ValueError):
    """Raised when the external signer boundary is unavailable or invalid."""


SIGNER_SCHEMA_VERSION = "1.0.0"
MAX_PAYLOAD_BYTES = 1024 * 1024
MAX_FRAME_BYTES = 2 * 1024 * 1024
SIGNING_PURPOSES = frozenset(
    {"qualification", "judge", "host", "supply_chain", "vulnerability", "provenance", "authority"}
)


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SignerServiceError("signing payload is not canonical JSON") from exc


def canonical_signing_payload(value: Mapping[str, Any] | bytes) -> bytes:
    """Return the exact bytes the external signer is asked to sign."""

    payload = value if isinstance(value, bytes) else _canonical(dict(value))
    if not payload or len(payload) > MAX_PAYLOAD_BYTES:
        raise SignerServiceError("signing payload must be non-empty and within the size limit")
    return payload


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _b64(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode("ascii")


def _decode_b64(value: Any, *, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise SignerServiceError(f"{label} is missing")
    try:
        return base64.b64decode(value, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SignerServiceError(f"{label} encoding is invalid") from exc


def _timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SignerServiceError("signer timestamps must be RFC 3339") from exc
    if parsed.tzinfo is None:
        raise SignerServiceError("signer timestamps must include a timezone")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _schema(root: Path, name: str) -> Mapping[str, Any]:
    try:
        value = load_json((resolve_control_root(root) / "schemas" / name).read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SignerServiceError(f"signer schema is unavailable: {name}") from exc
    if not isinstance(value, Mapping):
        raise SignerServiceError(f"signer schema must be an object: {name}")
    return value


def _validate(document: Mapping[str, Any], *, root: Path, schema_name: str) -> None:
    issues = sorted(
        Draft202012Validator(dict(_schema(root, schema_name)), format_checker=FormatChecker()).iter_errors(document),
        key=lambda error: list(error.absolute_path),
    )
    if issues:
        location = ".".join(str(part) for part in issues[0].absolute_path) or "<root>"
        raise SignerServiceError(f"signer response is not schema-valid at {location}: {issues[0].message}")


def _request_identity(request: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in request.items() if key != "request_id"}


def expected_signing_request_id(request: Mapping[str, Any]) -> str:
    return "SGR-" + hashlib.sha256(_canonical(_request_identity(request))).hexdigest().upper()


def build_signing_request(
    payload: bytes,
    *,
    framework_version: str,
    bundle_root: str,
    purpose: str,
    key_id: str,
    created_at: str,
) -> dict[str, Any]:
    payload = canonical_signing_payload(payload)
    if not isinstance(framework_version, str) or not framework_version.strip():
        raise SignerServiceError("signer framework_version is required")
    if not isinstance(bundle_root, str) or len(bundle_root) != 64 or any(char not in "0123456789abcdef" for char in bundle_root):
        raise SignerServiceError("signer bundle_root must be a lowercase SHA-256 digest")
    if purpose not in SIGNING_PURPOSES:
        raise SignerServiceError("signer purpose is not supported")
    if not isinstance(key_id, str) or not key_id.strip():
        raise SignerServiceError("signer key_id is required")
    request: dict[str, Any] = {
        "schema_version": SIGNER_SCHEMA_VERSION,
        "framework_version": framework_version,
        "bundle_root": bundle_root,
        "purpose": purpose,
        "key_id": key_id,
        "signature_algorithm": "ed25519",
        "payload_digest": _digest(payload),
        "payload": _b64(payload),
        "created_at": _timestamp(created_at),
    }
    request["request_id"] = expected_signing_request_id(request)
    return request


def _validate_response_binding(
    response: Mapping[str, Any],
    request: Mapping[str, Any],
    *,
    public_key: Ed25519PublicKey,
    root: Path,
) -> dict[str, Any]:
    _validate(response, root=root, schema_name="signer-response.schema.json")
    if response.get("request_id") != request.get("request_id"):
        raise SignerServiceError("signer response request binding does not match")
    for field in ("framework_version", "bundle_root", "purpose", "key_id", "signature_algorithm", "payload_digest"):
        if response.get(field) != request.get(field):
            raise SignerServiceError(f"signer response {field} binding does not match")
    if response.get("request_id") != expected_signing_request_id(request):
        raise SignerServiceError("signer request identity does not match content")
    payload = _decode_b64(request.get("payload"), label="signing request payload")
    if _digest(payload) != request.get("payload_digest"):
        raise SignerServiceError("signing request payload digest does not match bytes")
    signature = _decode_b64(response.get("signature_value"), label="signer signature")
    try:
        public_key.verify(signature, payload)
    except (InvalidSignature, ValueError) as exc:
        raise SignerServiceError("signer response signature is invalid") from exc
    verified = dict(response)
    verified["verification_state"] = "verified"
    _validate(verified, root=root, schema_name="signer-response.schema.json")
    return verified


Transport = Callable[[dict[str, Any]], Mapping[str, Any]]


class SignerClient:
    """Client for a separate signer/key service; it never accepts key material."""

    def __init__(self, transport: Transport, *, root: Path | None = None) -> None:
        self._transport = transport
        self._root = resolve_control_root(root)

    def sign(
        self,
        payload: bytes,
        *,
        framework_version: str,
        bundle_root: str,
        purpose: str,
        key_id: str,
        public_key: Ed25519PublicKey,
        created_at: str,
    ) -> dict[str, Any]:
        request = build_signing_request(
            payload,
            framework_version=framework_version,
            bundle_root=bundle_root,
            purpose=purpose,
            key_id=key_id,
            created_at=created_at,
        )
        _validate(request, root=self._root, schema_name="signer-request.schema.json")
        try:
            # The transport is an untrusted process boundary. Keep the exact
            # request snapshot used for verification separate from its input.
            response = self._transport(dict(request))
        except Exception as exc:  # service outages must not trigger local signing
            raise SignerServiceError(f"signer service unavailable: {exc}") from exc
        if not isinstance(response, Mapping):
            raise SignerServiceError("signer response must be an object")
        return _validate_response_binding(response, request, public_key=public_key, root=self._root)


class SocketSignerTransport:
    """Bounded AF_UNIX JSON-lines transport for an external signer process."""

    def __init__(self, socket_path: Path | str, *, timeout_seconds: float = 2.0) -> None:
        self._socket_path = Path(socket_path)
        self._timeout_seconds = timeout_seconds
        if not self._socket_path.is_absolute():
            raise SignerServiceError("signer socket path must be absolute")
        if timeout_seconds <= 0:
            raise SignerServiceError("signer timeout must be positive")

    def __call__(self, request: dict[str, Any]) -> Mapping[str, Any]:
        try:
            metadata = self._socket_path.lstat()
        except OSError as exc:
            raise SignerServiceError(f"signer service unavailable: {exc}") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISSOCK(metadata.st_mode):
            raise SignerServiceError("signer endpoint must be a non-symlink Unix socket")
        frame = _canonical(request) + b"\n"
        if len(frame) > MAX_FRAME_BYTES:
            raise SignerServiceError("signer request exceeds the frame limit")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self._timeout_seconds)
                connection.connect(str(self._socket_path))
                connection.sendall(frame)
                received = bytearray()
                while b"\n" not in received and len(received) <= MAX_FRAME_BYTES:
                    chunk = connection.recv(min(65536, MAX_FRAME_BYTES - len(received) + 1))
                    if not chunk:
                        break
                    received.extend(chunk)
        except OSError as exc:
            raise SignerServiceError(f"signer service unavailable: {exc}") from exc
        if b"\n" not in received or received.index(b"\n") > MAX_FRAME_BYTES:
            raise SignerServiceError("signer response frame is missing or oversized")
        try:
            response = load_json(bytes(received).split(b"\n", 1)[0].decode("utf-8"))
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            raise SignerServiceError("signer response is not strict JSON") from exc
        if not isinstance(response, Mapping):
            raise SignerServiceError("signer response must be an object")
        return response
