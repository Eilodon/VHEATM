from __future__ import annotations

import base64
import hashlib
import json
import multiprocessing
import queue
import random
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any, Callable, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .provider_policy import ProviderPolicyError, validate_provider_binding
from .signer_service import SignerClient, SignerServiceError


class JudgeError(ValueError):
    """Raised when an independent-judge packet or verdict is invalid."""


JudgeProvider = Callable[[Mapping[str, Any]], Mapping[str, Any]]


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _content_id(prefix: str, value: Any) -> str:
    return f"{prefix}-{_digest(value).upper()}"


def _timestamp(value: str | None = None) -> str:
    result = value or datetime.now(UTC).isoformat().replace("+00:00", "Z")
    try:
        parsed = datetime.fromisoformat(result.replace("Z", "+00:00"))
    except ValueError as exc:
        raise JudgeError("judge timestamp must be RFC 3339") from exc
    if parsed.tzinfo is None:
        raise JudgeError("judge timestamp must include a timezone")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _require_digest(value: str, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise JudgeError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _order_digest(items: Sequence[Mapping[str, Any]]) -> str:
    return _digest([str(item.get("item_id", "")) for item in items])


_PACKET_ID_FIELDS = (
    "source_session_root", "judge_context_root", "origin_provider_id", "origin_model_id",
    "judge_provider_id", "judge_provider_version", "judge_endpoint", "judge_adapter_profile",
    "judge_model_id", "config_digest", "rubric_digest", "order_seed", "order_digest", "items",
)


def _packet_identity(packet: Mapping[str, Any]) -> dict[str, Any]:
    identity = {key: packet[key] for key in _PACKET_ID_FIELDS}
    for key in ("framework_version", "bundle_root"):
        if key in packet:
            identity[key] = packet[key]
    return identity


def build_blind_packet(
    *,
    source_session_root: str,
    judge_context_root: str,
    origin_provider_id: str,
    origin_model_id: str,
    judge_provider_id: str,
    judge_provider_version: str,
    judge_endpoint: str,
    judge_adapter_profile: str,
    judge_model_id: str,
    config_digest: str,
    rubric_digest: str,
    order_seed: str,
    framework_version: str | None = None,
    bundle_root: str | None = None,
    items: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    for value, field in ((source_session_root, "source_session_root"), (judge_context_root, "judge_context_root"), (config_digest, "config_digest"), (rubric_digest, "rubric_digest"), (order_seed, "order_seed")):
        _require_digest(value, field)
    if (framework_version is None) != (bundle_root is None):
        raise JudgeError("judge scope requires both framework_version and bundle_root")
    if framework_version is not None:
        if not isinstance(framework_version, str) or not framework_version.strip():
            raise JudgeError("judge framework_version is required when scope is supplied")
        _require_digest(str(bundle_root), "bundle_root")
    if source_session_root == judge_context_root:
        raise JudgeError("independent judge requires a distinct judge context root")
    if not origin_provider_id or not origin_model_id or not judge_provider_id or not judge_model_id:
        raise JudgeError("judge and origin provider/model identifiers are required")
    if not judge_provider_version or not judge_endpoint or not judge_adapter_profile:
        raise JudgeError("judge provider version, endpoint and adapter profile are required")
    if origin_provider_id == judge_provider_id or origin_model_id == judge_model_id:
        raise JudgeError("same provider or model cannot be labelled independent")
    try:
        validate_provider_binding(
            judge_provider_id,
            judge_provider_version,
            endpoint=judge_endpoint,
            config_digest=config_digest,
            adapter_profile=judge_adapter_profile,
        )
    except ProviderPolicyError as exc:
        raise JudgeError(str(exc)) from exc
    normalized = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, Mapping) or not str(item.get("item_id", "")).strip() or not str(item.get("text", "")).strip():
            raise JudgeError("judge items require item_id and text")
        item_id = str(item["item_id"])
        if item_id in seen:
            raise JudgeError("judge item ids must be unique")
        seen.add(item_id)
        normalized.append({"item_id": item_id, "text": str(item["text"])})
    if not normalized:
        raise JudgeError("blind packet requires at least one item")
    normalized.sort(key=lambda item: item["item_id"])
    randomizer = random.Random(int(order_seed, 16))
    randomizer.shuffle(normalized)
    identity = {
        "source_session_root": source_session_root, "judge_context_root": judge_context_root,
        "origin_provider_id": origin_provider_id, "origin_model_id": origin_model_id,
        "judge_provider_id": judge_provider_id, "judge_provider_version": judge_provider_version,
        "judge_endpoint": judge_endpoint, "judge_adapter_profile": judge_adapter_profile,
        "judge_model_id": judge_model_id,
        "config_digest": config_digest, "rubric_digest": rubric_digest, "order_seed": order_seed,
        "order_digest": _order_digest(normalized), "items": normalized,
    }
    if framework_version is not None and bundle_root is not None:
        identity.update({"framework_version": framework_version, "bundle_root": bundle_root})
    packet_id = _content_id("JPK", identity)
    request_id = _content_id("JDR", {"packet_id": packet_id, "judge_context_root": judge_context_root})
    return {"schema_version": "1.0.0", "packet_id": packet_id, "request_id": request_id, **identity}


def _validate_packet(packet: Mapping[str, Any]) -> None:
    required = {"schema_version", "packet_id", "request_id", "source_session_root", "judge_context_root", "origin_provider_id", "origin_model_id", "judge_provider_id", "judge_provider_version", "judge_endpoint", "judge_adapter_profile", "judge_model_id", "config_digest", "rubric_digest", "order_seed", "order_digest", "items"}
    if not isinstance(packet, Mapping) or packet.get("schema_version") != "1.0.0" or not required.issubset(packet):
        raise JudgeError("blind judge packet is incomplete")
    if packet["source_session_root"] == packet["judge_context_root"]:
        raise JudgeError("judge context root must be distinct from source session root")
    if packet["origin_provider_id"] == packet["judge_provider_id"] or packet["origin_model_id"] == packet["judge_model_id"]:
        raise JudgeError("same provider/model cannot be independent")
    try:
        validate_provider_binding(
            str(packet["judge_provider_id"]),
            str(packet["judge_provider_version"]),
            endpoint=str(packet["judge_endpoint"]),
            config_digest=str(packet["config_digest"]),
            adapter_profile=str(packet["judge_adapter_profile"]),
        )
    except ProviderPolicyError as exc:
        raise JudgeError(str(exc)) from exc
    if _order_digest(packet["items"]) != packet["order_digest"]:
        raise JudgeError("blind packet order digest mismatch")
    if ("framework_version" in packet) != ("bundle_root" in packet):
        raise JudgeError("judge packet scope requires both framework_version and bundle_root")
    if "framework_version" in packet and (not isinstance(packet["framework_version"], str) or not packet["framework_version"].strip()):
        raise JudgeError("judge packet framework_version is invalid")
    if "bundle_root" in packet:
        _require_digest(str(packet["bundle_root"]), "bundle_root")
    expected_packet = _content_id("JPK", _packet_identity(packet))
    if packet["packet_id"] != expected_packet:
        raise JudgeError("blind packet id mismatch")
    if packet["request_id"] != _content_id("JDR", {"packet_id": packet["packet_id"], "judge_context_root": packet["judge_context_root"]}):
        raise JudgeError("judge request id mismatch")


def validate_packet_identity(packet: Mapping[str, Any]) -> None:
    """Validate a blind packet's content identity at downstream evidence boundaries."""

    _validate_packet(packet)


def _judge_worker(provider: JudgeProvider, packet: Mapping[str, Any], output: Any) -> None:
    try:
        value = provider(deepcopy(dict(packet)))
        output.put({"ok": True, "value": deepcopy(dict(value))})
    except BaseException as exc:  # process boundary converts provider failure into a typed outage
        output.put({"ok": False, "error": f"{type(exc).__name__}: {exc}"})


def _escalation(packet_id: str, reason: str, *, created_at: str) -> dict[str, Any]:
    identity = {"packet_id": packet_id, "reason": reason, "created_at": created_at}
    return {
        "schema_version": "1.0.0", "escalation_id": _content_id("HITL", identity), "packet_id": packet_id,
        "reason": reason, "state": "open", "epistemic_status": "unknown", "created_at": created_at,
    }


def run_independent_judge(packet: Mapping[str, Any], provider: JudgeProvider, *, timeout_seconds: float = 10.0) -> dict[str, Any]:
    _validate_packet(packet)
    if timeout_seconds <= 0:
        raise JudgeError("timeout_seconds must be positive")
    context = multiprocessing.get_context("spawn")
    output = context.Queue(maxsize=1)
    process = context.Process(target=_judge_worker, args=(provider, dict(packet), output), name="vheatm-independent-judge")
    process.daemon = True
    try:
        process.start()
        process.join(timeout_seconds)
        if process.is_alive():
            process.terminate()
            process.join(2.0)
            now = _timestamp()
            return {"status": "blocked", "reason": "judge provider timeout", "escalation": _escalation(packet["packet_id"], "judge provider timeout", created_at=now)}
        try:
            raw = output.get_nowait()
        except queue.Empty:
            now = _timestamp()
            return {"status": "blocked", "reason": "judge provider exited without a verdict", "escalation": _escalation(packet["packet_id"], "judge provider exited without a verdict", created_at=now)}
    finally:
        output.close()
        output.join_thread()
    if process.exitcode != 0 or raw.get("ok") is not True:
        reason = str(raw.get("error", "judge provider failed"))
        now = _timestamp()
        return {"status": "blocked", "reason": reason, "escalation": _escalation(packet["packet_id"], reason, created_at=now)}
    try:
        verdict = _build_verdict(packet, raw.get("value"))
    except JudgeError as exc:
        now = _timestamp()
        return {"status": "blocked", "reason": str(exc), "escalation": _escalation(packet["packet_id"], str(exc), created_at=now)}
    return {"status": verdict["status"], "verdict": verdict, "escalation": None if verdict["status"] == "complete" else _escalation(packet["packet_id"], "judge returned unknown item", created_at=verdict["generated_at"])}


def _build_verdict(packet: Mapping[str, Any], raw: Any) -> dict[str, Any]:
    if not isinstance(raw, Mapping) or not isinstance(raw.get("decisions"), list):
        raise JudgeError("judge provider must return a decisions array")
    decisions = []
    expected_ids = [str(item["item_id"]) for item in packet["items"]]
    for item in raw["decisions"]:
        if not isinstance(item, Mapping) or set(item) - {"item_id", "label", "confidence"}:
            raise JudgeError("judge decision contains unsupported fields")
        label = item.get("label")
        confidence = item.get("confidence")
        if str(item.get("item_id")) not in expected_ids or label not in {"yes", "no", "unknown"} or not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= confidence <= 1:
            raise JudgeError("judge decision is malformed")
        decisions.append({"item_id": str(item["item_id"]), "label": label, "confidence": float(confidence)})
    if [item["item_id"] for item in decisions] != expected_ids or len(decisions) != len(set(item["item_id"] for item in decisions)):
        raise JudgeError("judge decisions must cover items exactly in randomized packet order")
    status = "unknown" if any(item["label"] == "unknown" for item in decisions) else "complete"
    identity = {
        "packet_id": packet["packet_id"], "request_id": packet["request_id"], "judge_provider_id": packet["judge_provider_id"],
        "judge_model_id": packet["judge_model_id"], "config_digest": packet["config_digest"], "order_digest": packet["order_digest"],
        "status": status, "epistemic_status": "independent_candidate" if status == "complete" else "unknown", "decisions": decisions,
    }
    for key in ("framework_version", "bundle_root"):
        if key in packet:
            identity[key] = packet[key]
    return {"schema_version": "1.0.0", "verdict_id": _content_id("JVR", identity), **identity, "generated_at": _timestamp()}


def expected_verdict_id(verdict: Mapping[str, Any]) -> str:
    identity = {key: verdict[key] for key in ("packet_id", "request_id", "judge_provider_id", "judge_model_id", "config_digest", "order_digest", "status", "epistemic_status", "decisions") if key in verdict}
    for key in ("framework_version", "bundle_root"):
        if key in verdict:
            identity[key] = verdict[key]
    return _content_id("JVR", identity)


def _signed_verdict_subject(verdict: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in verdict.items()
        if key not in {"verdict_id", "signature_algorithm", "signature_key_id", "signature_value"}
    }


def sign_verdict(
    verdict: Mapping[str, Any], *, private_key: Ed25519PrivateKey | None = None, key_id: str,
    signer: SignerClient | None = None, framework_version: str | None = None,
    bundle_root: str | None = None, public_key: Ed25519PublicKey | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Attach an independent judge signature to a complete candidate verdict."""

    validate_verdict_identity(verdict)
    if verdict.get("status") != "complete" or verdict.get("epistemic_status") != "independent_candidate":
        raise JudgeError("only a complete independent candidate verdict can be signed")
    if not isinstance(key_id, str) or not key_id.strip():
        raise JudgeError("judge signing key ID is required")
    signed = dict(verdict)
    signed.update({"signature_algorithm": "ed25519", "signature_key_id": key_id})
    subject = _signed_verdict_subject(signed)
    if signer is not None:
        if private_key is not None:
            raise JudgeError("external signer and local private key cannot be combined")
        if not isinstance(public_key, Ed25519PublicKey):
            raise JudgeError("external signer requires the expected judge public key")
        if not isinstance(framework_version, str) or not framework_version.strip() or not isinstance(bundle_root, str):
            raise JudgeError("external signer requires the canonical judge framework and bundle scope")
        if framework_version != signed.get("framework_version") or bundle_root != signed.get("bundle_root"):
            raise JudgeError("external signer scope does not match judge verdict")
        try:
            receipt = signer.sign(
                _canonical_bytes(subject),
                framework_version=framework_version,
                bundle_root=bundle_root,
                purpose="judge",
                key_id=key_id,
                public_key=public_key,
                created_at=str(created_at or signed.get("generated_at", "")),
            )
        except SignerServiceError as exc:
            raise JudgeError(str(exc)) from exc
        signed["signature_value"] = str(receipt["signature_value"])
    else:
        if not isinstance(private_key, Ed25519PrivateKey):
            raise JudgeError("a local fixture key or external signer is required")
        signed["signature_value"] = base64.urlsafe_b64encode(private_key.sign(_canonical_bytes(subject))).decode("ascii")
    return signed


def verify_signed_verdict(
    verdict: Mapping[str, Any], *, public_key: Ed25519PublicKey, key_id: str | None = None,
    expected_framework_version: str | None = None, expected_bundle_root: str | None = None,
) -> None:
    """Verify the independent signer before a verdict contributes release metrics."""

    validate_verdict_identity(verdict)
    if verdict.get("status") != "complete" or verdict.get("epistemic_status") != "independent_candidate":
        raise JudgeError("persisted independent evidence requires a complete independent verdict")
    if verdict.get("signature_algorithm") != "ed25519" or not isinstance(verdict.get("signature_value"), str):
        raise JudgeError("independent judge verdict signature is missing")
    if key_id is not None and verdict.get("signature_key_id") != key_id:
        raise JudgeError("independent judge signing key does not match")
    if expected_framework_version is not None and verdict.get("framework_version") != expected_framework_version:
        raise JudgeError("independent judge verdict framework version does not match release")
    if expected_bundle_root is not None and verdict.get("bundle_root") != expected_bundle_root:
        raise JudgeError("independent judge verdict bundle root does not match release")
    try:
        public_key.verify(base64.urlsafe_b64decode(str(verdict["signature_value"])), _canonical_bytes(_signed_verdict_subject(verdict)))
    except (InvalidSignature, ValueError) as exc:
        raise JudgeError("independent judge verdict signature is invalid") from exc


def validate_verdict_identity(verdict: Mapping[str, Any]) -> None:
    required = {"schema_version", "verdict_id", "packet_id", "request_id", "judge_provider_id", "judge_model_id", "config_digest", "order_digest", "status", "epistemic_status", "decisions", "generated_at"}
    if not isinstance(verdict, Mapping) or verdict.get("schema_version") != "1.0.0" or not required.issubset(verdict):
        raise JudgeError("independent judge verdict is incomplete")
    if verdict.get("verdict_id") != expected_verdict_id(verdict):
        raise JudgeError("independent judge verdict identity does not match its content")
    if ("framework_version" in verdict) != ("bundle_root" in verdict):
        raise JudgeError("independent judge verdict scope requires both framework_version and bundle_root")
    if "framework_version" in verdict and (not isinstance(verdict["framework_version"], str) or not verdict["framework_version"].strip()):
        raise JudgeError("independent judge verdict framework_version is invalid")
    if "bundle_root" in verdict:
        _require_digest(str(verdict["bundle_root"]), "bundle_root")
    decisions = verdict.get("decisions")
    if not isinstance(decisions, list) or not decisions:
        raise JudgeError("independent judge verdict requires decisions")
    seen: set[str] = set()
    for decision in decisions:
        if not isinstance(decision, Mapping) or not isinstance(decision.get("item_id"), str) or decision["item_id"] in seen or decision.get("label") not in {"yes", "no", "unknown"} or not isinstance(decision.get("confidence"), (int, float)) or isinstance(decision.get("confidence"), bool) or not 0 <= decision["confidence"] <= 1:
            raise JudgeError("independent judge verdict decision is malformed")
        seen.add(decision["item_id"])
    expected_status = "unknown" if any(item["label"] == "unknown" for item in decisions) else "complete"
    if verdict.get("status") != expected_status or verdict.get("epistemic_status") != ("independent_candidate" if expected_status == "complete" else "unknown"):
        raise JudgeError("independent judge verdict status is inconsistent with its decisions")


def validate_verdict_binding(packet: Mapping[str, Any], verdict: Mapping[str, Any]) -> None:
    """Validate that a verdict is an exact, content-bound result for one packet."""

    _validate_packet(packet)
    validate_verdict_identity(verdict)
    for field in ("request_id", "judge_provider_id", "judge_model_id", "config_digest", "order_digest"):
        if verdict.get(field) != packet.get(field):
            raise JudgeError(f"independent judge verdict {field} is not bound to its packet")
    for field in ("framework_version", "bundle_root"):
        if (field in packet) != (field in verdict) or (field in packet and verdict.get(field) != packet.get(field)):
            raise JudgeError(f"independent judge verdict {field} is not bound to its packet")
    packet_item_ids = [str(item["item_id"]) for item in packet["items"]]
    verdict_item_ids = [str(item["item_id"]) for item in verdict["decisions"]]
    if verdict_item_ids != packet_item_ids:
        raise JudgeError("independent judge verdict decisions do not exactly cover packet items in order")


def compare_verdicts(first: Mapping[str, Any], second: Mapping[str, Any]) -> dict[str, Any]:
    if first.get("packet_id") != second.get("packet_id"):
        raise JudgeError("cannot compare verdicts from different packets")
    left = {str(item["item_id"]): item.get("label") for item in first.get("decisions", [])}
    right = {str(item["item_id"]): item.get("label") for item in second.get("decisions", [])}
    if set(left) != set(right):
        return {"status": "blocked", "reason": "judge verdict item coverage diverged", "order_consistent": False}
    divergence = sorted(item_id for item_id in left if left[item_id] != right[item_id])
    return {
        "status": "complete" if not divergence else "blocked", "reason": "order-consistent agreement" if not divergence else "hard judge divergence",
        "order_consistent": True, "divergent_items": divergence,
    }


def resolve_hitl(escalation: Mapping[str, Any], *, actor: str, decision: str, rationale: str, occurred_at: str | None = None) -> dict[str, Any]:
    if escalation.get("state") != "open":
        raise JudgeError("only open HITL escalations can be resolved")
    if decision not in {"accept", "reject", "defer"} or not actor.strip() or not rationale.strip():
        raise JudgeError("HITL resolution requires actor, decision and rationale")
    timestamp = _timestamp(occurred_at)
    state = "deferred" if decision == "defer" else "adjudicated"
    epistemic = "unknown" if decision == "defer" else "human_adjudicated"
    body = {"escalation_id": escalation["escalation_id"], "actor": actor, "decision": decision, "rationale": rationale, "occurred_at": timestamp}
    return {**dict(escalation), "state": state, "epistemic_status": epistemic, "actor": actor, "decision": decision, "rationale": rationale, "resolution_id": _content_id("HITL", body)}
