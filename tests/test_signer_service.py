from __future__ import annotations

import base64
import hashlib
import json
import socket
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vheatm_control.signer_service import (
    SignerClient,
    SignerServiceError,
    SocketSignerTransport,
    build_signing_request,
    canonical_signing_payload,
    expected_signing_request_id,
)


BUNDLE_ROOT = "a" * 64


def test_signing_request_is_content_addressed_and_contains_no_private_key() -> None:
    payload = canonical_signing_payload({"artifact": "candidate", "value": 7})

    request = build_signing_request(
        payload,
        framework_version="17.0.0-dev.1",
        bundle_root=BUNDLE_ROOT,
        purpose="host",
        key_id="host-key",
        created_at="2026-08-02T00:00:00Z",
    )

    assert request["request_id"] == expected_signing_request_id(request)
    assert request["payload_digest"] == hashlib.sha256(payload).hexdigest()
    assert base64.urlsafe_b64decode(request["payload"]) == payload
    assert "private_key" not in request
    assert "secret" not in request


def test_signer_client_accepts_only_a_response_bound_to_the_request() -> None:
    key = Ed25519PrivateKey.generate()

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
            "signer_service_id": "kms.test",
            "signed_at": "2026-08-02T00:00:01Z",
        }

    receipt = SignerClient(transport).sign(
        canonical_signing_payload({"release": "candidate"}),
        framework_version="17.0.0-dev.1",
        bundle_root=BUNDLE_ROOT,
        purpose="host",
        key_id="host-key",
        public_key=key.public_key(),
        created_at="2026-08-02T00:00:00Z",
    )

    assert receipt["verification_state"] == "verified"
    assert receipt["request_id"].startswith("SGR-")


def test_signer_client_rejects_mismatched_response_without_local_fallback() -> None:
    key = Ed25519PrivateKey.generate()

    def forged_transport(request: dict[str, object]) -> dict[str, object]:
        forged = dict(request)
        forged.update(
            {
                "signature_algorithm": "ed25519",
                "signature_value": base64.urlsafe_b64encode(b"forged").decode("ascii"),
                "signer_service_id": "untrusted.test",
                "signed_at": "2026-08-02T00:00:01Z",
            }
        )
        forged.pop("payload", None)
        return forged

    with pytest.raises(SignerServiceError, match="response"):
        SignerClient(forged_transport).sign(
            b"payload",
            framework_version="17.0.0-dev.1",
            bundle_root=BUNDLE_ROOT,
            purpose="host",
            key_id="host-key",
            public_key=key.public_key(),
            created_at="2026-08-02T00:00:00Z",
        )


def test_signer_client_rejects_transport_mutation_of_the_original_request() -> None:
    key = Ed25519PrivateKey.generate()

    def mutating_transport(request: dict[str, object]) -> dict[str, object]:
        replacement = b"attacker-controlled-payload"
        request["payload"] = base64.urlsafe_b64encode(replacement).decode("ascii")
        request["payload_digest"] = hashlib.sha256(replacement).hexdigest()
        request["request_id"] = expected_signing_request_id(request)
        response = {key: value for key, value in request.items() if key not in {"payload", "created_at"}}
        response.update(
            {
                "signature_value": base64.urlsafe_b64encode(key.sign(replacement)).decode("ascii"),
                "signer_service_id": "untrusted.test",
                "signed_at": "2026-08-02T00:00:01Z",
            }
        )
        return response

    with pytest.raises(SignerServiceError, match="binding|identity"):
        SignerClient(mutating_transport).sign(
            b"original-payload",
            framework_version="17.0.0-dev.1",
            bundle_root=BUNDLE_ROOT,
            purpose="host",
            key_id="host-key",
            public_key=key.public_key(),
            created_at="2026-08-02T00:00:00Z",
        )


def test_signer_client_fails_closed_when_service_is_unavailable() -> None:
    def unavailable(_: dict[str, object]) -> dict[str, object]:
        raise OSError("socket missing")

    with pytest.raises(SignerServiceError, match="unavailable"):
        SignerClient(unavailable).sign(
            b"payload",
            framework_version="17.0.0-dev.1",
            bundle_root=BUNDLE_ROOT,
            purpose="host",
            key_id="host-key",
            public_key=Ed25519PrivateKey.generate().public_key(),
            created_at="2026-08-02T00:00:00Z",
        )


def test_socket_transport_uses_bounded_unix_socket_json_lines(tmp_path) -> None:
    socket_path = tmp_path / "signer.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    server.listen(1)

    def serve() -> None:
        connection, _ = server.accept()
        with connection:
            received = connection.recv(4096)
            assert received.endswith(b"\n")
            assert json.loads(received.decode("utf-8")) == {"request_id": "SGR-test"}
            connection.sendall(b'{"status":"accepted"}\n')

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        response = SocketSignerTransport(socket_path)({"request_id": "SGR-test"})
    finally:
        thread.join(timeout=2)
        server.close()

    assert response == {"status": "accepted"}
