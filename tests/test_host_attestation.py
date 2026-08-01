from __future__ import annotations

import copy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vheatm_control.bundle import build_bundle
from vheatm_control.evaluation import derive_verified_evidence_metrics
from vheatm_control.host_attestation import (
    HostAttestationError,
    build_host_attestation,
    expected_host_attestation_id,
    sign_host_attestation,
    verify_host_attestation,
)
from vheatm_control.host_qualification import expected_host_qualification_run_id
from vheatm_control.qualification_methods import expected_method_digest
from vheatm_control.serialization import load_yaml


ROOT = Path(__file__).resolve().parents[1]


def _complete_host_run() -> dict[str, object]:
    manifest = load_yaml((ROOT / "manifests" / "vheatm-v17.yaml").read_text(encoding="utf-8"))
    observation = {
        "observation_id": "HOB-" + "A" * 64,
        "sample_index": 1,
        "kind": "hard_stop_timeout",
        "status": "observed",
        "elapsed_seconds": 0.2,
        "sandbox_run_id": "SBR-" + "B" * 64,
        "controls": ["timeout:enforced"],
        "details": {
            "reason": "timeout enforcement observed",
            "sandbox_status": "blocked",
            "exit_code": None,
            "stderr_digest": "c" * 64,
            "timeout_budget_seconds": 0.1,
        },
    }
    run: dict[str, object] = {
        "schema_version": "1.0.0",
        "framework_version": str(manifest["framework"]["version"]),
        "bundle_root": build_bundle(ROOT)["bundle_root"],
        "runner_id": "vheatm.host-qualification",
        "runner_version": "1.0.0",
        "backend": "bubblewrap",
        "backend_digest": "d" * 64,
        "host_identity_digest": "e" * 64,
        "reference_monitor_status": "observed",
        "status": "complete",
        "evidence_state": "unverified",
        "observations": [observation],
        "measurements": [{
            "metric": "hard_stop_p99_seconds",
            "value": 0.2,
            "sample_count": 1,
            "confidence_lower": 0,
            "method_digest": expected_method_digest("hard_stop_p99_seconds", root=ROOT),
            "evidence_refs": [observation["observation_id"]],
        }],
        "generated_at": "2026-08-02T00:00:00Z",
    }
    run["run_id"] = expected_host_qualification_run_id(run)
    return run


def test_host_attestation_signs_and_verifies_exact_host_run() -> None:
    run = _complete_host_run()
    key = Ed25519PrivateKey.generate()

    attestation = build_host_attestation(
        run,
        authority_id="host-authority:v17",
        deployment_id="sandbox-host-01",
        generated_at="2026-08-02T00:00:00Z",
        root=ROOT,
    )
    signed = sign_host_attestation(attestation, private_key=key, key_id="host-key")
    verified = verify_host_attestation(
        signed,
        host_run=run,
        public_key=key.public_key(),
        key_id="host-key",
        expected_bundle_root=run["bundle_root"],
        root=ROOT,
    )

    assert signed["attestation_id"] == expected_host_attestation_id(signed)
    assert verified["verification_state"] == "verified"
    assert verified["host_run_id"] == run["run_id"]


def test_host_attestation_rejects_host_run_mutation_after_signing() -> None:
    run = _complete_host_run()
    key = Ed25519PrivateKey.generate()
    signed = sign_host_attestation(
        build_host_attestation(
            run,
            authority_id="host-authority:v17",
            deployment_id="sandbox-host-01",
            generated_at="2026-08-02T00:00:00Z",
            root=ROOT,
        ),
        private_key=key,
        key_id="host-key",
    )
    tampered = copy.deepcopy(run)
    tampered["measurements"][0]["value"] = 1.9  # type: ignore[index]
    tampered["run_id"] = expected_host_qualification_run_id(tampered)

    with pytest.raises(HostAttestationError, match="digest"):
        verify_host_attestation(
            signed,
            host_run=tampered,
            public_key=key.public_key(),
            key_id="host-key",
            expected_bundle_root=run["bundle_root"],
            root=ROOT,
        )


def test_host_attestation_requires_complete_host_run() -> None:
    run = _complete_host_run()
    run["status"] = "blocked"
    run["reference_monitor_status"] = "unavailable"
    run["measurements"] = []
    run["run_id"] = expected_host_qualification_run_id(run)

    with pytest.raises(HostAttestationError, match="complete"):
        build_host_attestation(
            run,
            authority_id="host-authority:v17",
            deployment_id="sandbox-host-01",
            generated_at="2026-08-02T00:00:00Z",
            root=ROOT,
        )


def test_host_attestation_rejects_non_finite_measurement() -> None:
    run = _complete_host_run()
    run["measurements"][0]["value"] = float("nan")  # type: ignore[index]
    run["run_id"] = expected_host_qualification_run_id(run)

    with pytest.raises(HostAttestationError, match="finite"):
        build_host_attestation(
            run,
            authority_id="host-authority:v17",
            deployment_id="sandbox-host-01",
            generated_at="2026-08-02T00:00:00Z",
            root=ROOT,
        )


def test_host_attestation_rejects_malformed_signature_encoding() -> None:
    run = _complete_host_run()
    key = Ed25519PrivateKey.generate()
    signed = sign_host_attestation(
        build_host_attestation(
            run,
            authority_id="host-authority:v17",
            deployment_id="sandbox-host-01",
            generated_at="2026-08-02T00:00:00Z",
            root=ROOT,
        ),
        private_key=key,
        key_id="host-key",
    )
    signed["signature_value"] = "A"

    with pytest.raises(HostAttestationError, match="signature"):
        verify_host_attestation(
            signed,
            host_run=run,
            public_key=key.public_key(),
            key_id="host-key",
            expected_bundle_root=run["bundle_root"],
            root=ROOT,
        )


def test_host_attestation_signature_binds_key_identity() -> None:
    run = _complete_host_run()
    key = Ed25519PrivateKey.generate()
    signed = sign_host_attestation(
        build_host_attestation(
            run,
            authority_id="host-authority:v17",
            deployment_id="sandbox-host-01",
            generated_at="2026-08-02T00:00:00Z",
            root=ROOT,
        ),
        private_key=key,
        key_id="host-key",
    )
    tampered = dict(signed)
    tampered["signature_key_id"] = "renamed-host-key"

    with pytest.raises(HostAttestationError, match="signature"):
        verify_host_attestation(
            tampered,
            host_run=run,
            public_key=key.public_key(),
            key_id="renamed-host-key",
            expected_bundle_root=run["bundle_root"],
            root=ROOT,
        )


def test_verified_host_attestation_is_the_only_source_for_release_hard_stop_metric() -> None:
    run = _complete_host_run()
    key = Ed25519PrivateKey.generate()
    signed = sign_host_attestation(
        build_host_attestation(
            run,
            authority_id="host-authority:v17",
            deployment_id="sandbox-host-01",
            generated_at="2026-08-02T00:00:00Z",
            root=ROOT,
        ),
        private_key=key,
        key_id="host-key",
    )
    evidence = {"host_qualification_run": run, "host_qualification_attestation": signed}

    without_key = derive_verified_evidence_metrics(
        evidence,
        expected_bundle_root=run["bundle_root"],
        verification_keys={},
        verification_key_ids={},
        schema_root=ROOT,
    )
    with_key = derive_verified_evidence_metrics(
        evidence,
        expected_bundle_root=run["bundle_root"],
        verification_keys={"host": key.public_key()},
        verification_key_ids={"host": "host-key"},
        schema_root=ROOT,
    )

    assert "hard_stop_p99_seconds" not in without_key
    assert with_key["hard_stop_p99_seconds"] == 0.2
