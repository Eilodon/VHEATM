from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, MutableSet, Protocol

import yaml
from jsonschema import Draft202012Validator, FormatChecker


class BrokerConfigurationError(ValueError):
    """Raised when broker policy or schema configuration is unsafe."""


class TokenLedger(Protocol):
    def consume(self, token_id: str) -> bool:
        """Atomically consume a token. Return False when it was already consumed."""


@dataclass
class InMemoryTokenLedger:
    consumed: MutableSet[str] = field(default_factory=set)

    def consume(self, token_id: str) -> bool:
        if token_id in self.consumed:
            return False
        self.consumed.add(token_id)
        return True


@dataclass(frozen=True)
class DirectoryTokenLedger:
    root: Path

    def consume(self, token_id: str) -> bool:
        self.root.mkdir(parents=True, exist_ok=True)
        marker = self.root / token_id
        try:
            descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return False
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write("consumed\n")
        return True


@dataclass(frozen=True)
class BrokerCapabilities:
    exact_command_allowlist: frozenset[str] = frozenset()
    known_secret_names: frozenset[str] = frozenset()


@dataclass(frozen=True)
class BrokerSchemas:
    runtime_policy: Mapping[str, Any]
    tool_request: Mapping[str, Any]
    approval_token: Mapping[str, Any]
    policy_decision: Mapping[str, Any]


class ToolBroker:
    """Fail-closed evaluator for guarded VHEATM tool requests.

    The broker returns policy decisions only. It never executes, writes, performs
    network access, or resolves secrets itself.
    """

    def __init__(
        self,
        *,
        policy: Mapping[str, Any],
        schemas: BrokerSchemas,
        keyring: Mapping[str, bytes] | None = None,
        capabilities: BrokerCapabilities | None = None,
        token_ledger: TokenLedger | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.policy = policy
        self.schemas = schemas
        self.keyring = dict(keyring or {})
        self.capabilities = capabilities or BrokerCapabilities()
        self.token_ledger = token_ledger or InMemoryTokenLedger()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._format_checker = FormatChecker()
        self._validate_configuration()

    @classmethod
    def from_root(
        cls,
        root: Path,
        *,
        keyring: Mapping[str, bytes] | None = None,
        capabilities: BrokerCapabilities | None = None,
        token_ledger: TokenLedger | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> "ToolBroker":
        root = root.resolve()
        policy = _load_yaml(root / "policies" / "runtime-boundaries.yaml")
        schemas = BrokerSchemas(
            runtime_policy=_load_json(root / "schemas" / "runtime-policy.schema.json"),
            tool_request=_load_json(root / "schemas" / "tool-request.schema.json"),
            approval_token=_load_json(root / "schemas" / "approval-token.schema.json"),
            policy_decision=_load_json(root / "schemas" / "policy-decision.schema.json"),
        )
        return cls(
            policy=policy,
            schemas=schemas,
            keyring=keyring,
            capabilities=capabilities,
            token_ledger=token_ledger,
            clock=clock,
        )

    def evaluate(
        self,
        request: Mapping[str, Any],
        approval_token: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = _ensure_aware_utc(self.clock())
        request_id = request.get("request_id") if isinstance(request, Mapping) else None
        if not isinstance(request_id, str) or not request_id:
            request_id = "invalid-request"

        request_errors = self._schema_errors(request, self.schemas.tool_request)
        if request_errors:
            return self._decision(
                request_id=request_id,
                allowed=False,
                reason=f"tool request schema validation failed: {request_errors[0]}",
                controls=("schema:tool-request", "policy:fail-closed"),
                evaluated_at=now,
            )

        try:
            scope = _workspace_scope(str(request["scope"]))
        except ValueError as exc:
            return self._decision(
                request_id=request_id,
                allowed=False,
                reason=str(exc),
                controls=("scope:workspace", "policy:fail-closed"),
                evaluated_at=now,
            )

        tool_class = str(request["tool_class"])
        tool_policy = self.policy.get("tools", {}).get("classes", {}).get(tool_class)
        if not isinstance(tool_policy, Mapping):
            return self._decision(
                request_id=request_id,
                allowed=False,
                reason=f"tool class {tool_class!r} has no validated policy",
                controls=("policy:tools.default-deny",),
                evaluated_at=now,
            )

        controls = ["schema:tool-request", "scope:workspace", "policy:tools.default-deny"]
        verified_token_id: str | None = None
        token_required_for = set(self.policy.get("human_approval", {}).get("token_required_for", []))
        requires_approval = tool_class in token_required_for or tool_policy.get("allowed_without_approval") is not True
        if requires_approval:
            token_result = self._verify_approval(request, approval_token, now)
            if token_result[0] is None:
                return self._decision(
                    request_id=request_id,
                    allowed=False,
                    reason=token_result[1],
                    controls=tuple(controls + ["approval:required", "policy:fail-closed"]),
                    evaluated_at=now,
                )
            verified_token_id = token_result[0]
            controls.extend(("approval:verified", "approval:single-use"))
            if not self.token_ledger.consume(verified_token_id):
                return self._decision(
                    request_id=request_id,
                    allowed=False,
                    reason="approval token has already been consumed",
                    controls=tuple(controls + ["approval:replay-blocked", "policy:fail-closed"]),
                    evaluated_at=now,
                    approval_token_id=verified_token_id,
                )
        elif approval_token is not None:
            return self._decision(
                request_id=request_id,
                allowed=False,
                reason="approval token supplied for a tool class that does not require approval",
                controls=tuple(controls + ["approval:unexpected", "policy:fail-closed"]),
                evaluated_at=now,
            )

        evaluator = getattr(self, f"_evaluate_{tool_class}", None)
        if evaluator is None:
            return self._decision(
                request_id=request_id,
                allowed=False,
                reason=f"tool class {tool_class!r} is unsupported by the broker",
                controls=tuple(controls + ["policy:fail-closed"]),
                evaluated_at=now,
                approval_token_id=verified_token_id,
            )

        allowed, reason, class_controls = evaluator(request, scope)
        controls.extend(class_controls)
        if not allowed:
            return self._decision(
                request_id=request_id,
                allowed=False,
                reason=reason,
                controls=tuple(controls + ["policy:fail-closed"]),
                evaluated_at=now,
                approval_token_id=verified_token_id,
            )

        return self._decision(
            request_id=request_id,
            allowed=True,
            reason=reason,
            controls=tuple(controls),
            evaluated_at=now,
            approval_token_id=verified_token_id,
        )

    def _evaluate_read(
        self, request: Mapping[str, Any], scope: PurePosixPath
    ) -> tuple[bool, str, tuple[str, ...]]:
        del scope
        if request.get("secret_expansion") is not False:
            return False, "read requests must explicitly disable secret expansion", ("read:no-secret-expansion",)
        if request.get("contains_secrets") is not False:
            return False, "read requests must explicitly declare that the target contains no secrets", ("read:no-secret-content",)
        return True, "read request satisfies workspace and secret-boundary controls", (
            "read:workspace-only",
            "read:no-secret-expansion",
            "read:no-secret-content",
        )

    def _evaluate_execute(
        self, request: Mapping[str, Any], scope: PurePosixPath
    ) -> tuple[bool, str, tuple[str, ...]]:
        del scope
        if request.get("sandboxed") is not True:
            return False, "execute requests require an active sandbox", ("execute:sandbox",)
        if request.get("network_enabled") is not False:
            return False, "execute sandbox network must be disabled", ("execute:network-disabled",)
        if request.get("inherit_secrets") is not False:
            return False, "execute sandbox must not inherit environment secrets", ("execute:no-secret-inheritance",)
        command = request.get("command")
        if not isinstance(command, str) or command != command.strip() or "\x00" in command:
            return False, "execute command must be a normalized non-null string", ("execute:normalized-command",)
        if command not in self.capabilities.exact_command_allowlist:
            return False, "execute command is not present in the exact command allowlist", ("execute:command-allowlist",)
        return True, "execute request satisfies sandbox and exact-command controls", (
            "execute:sandbox",
            "execute:network-disabled",
            "execute:no-secret-inheritance",
            "execute:command-allowlist",
        )

    def _evaluate_write(
        self, request: Mapping[str, Any], scope: PurePosixPath
    ) -> tuple[bool, str, tuple[str, ...]]:
        diff_paths = request.get("diff_paths", [])
        try:
            normalized = tuple(_workspace_relative_path(str(value), label="diff path") for value in diff_paths)
        except ValueError as exc:
            return False, str(exc), ("write:scoped-diff",)
        if not all(_is_within_scope(path, scope) for path in normalized):
            return False, "write diff path escapes the approved workspace scope", ("write:scoped-diff",)
        if not isinstance(request.get("rollback_plan"), str) or not request["rollback_plan"].strip():
            return False, "write requests require a non-empty rollback plan", ("write:rollback-plan",)
        return True, "write request satisfies scoped-diff and rollback controls", (
            "write:scoped-diff",
            "write:rollback-plan",
        )

    def _evaluate_network(
        self, request: Mapping[str, Any], scope: PurePosixPath
    ) -> tuple[bool, str, tuple[str, ...]]:
        del scope
        destination = request.get("destination")
        allowlist = self.policy.get("egress", {}).get("destinations", [])
        if destination not in allowlist:
            return False, "network destination is not allowlisted by runtime policy", ("network:destination-allowlist",)
        data_classes = set(request.get("data_classes", []))
        prohibited = set(self.policy.get("egress", {}).get("prohibited_data", []))
        if data_classes & prohibited:
            return False, "network request contains prohibited data classes", ("network:data-classification",)
        if self.policy.get("egress", {}).get("requires_redaction") is True and request.get("redacted") is not True:
            return False, "network request must confirm redaction", ("network:redaction",)
        return True, "network request satisfies destination, data-class, and redaction controls", (
            "network:destination-allowlist",
            "network:data-classification",
            "network:redaction",
        )

    def _evaluate_secrets(
        self, request: Mapping[str, Any], scope: PurePosixPath
    ) -> tuple[bool, str, tuple[str, ...]]:
        del scope
        secret_name = request.get("secret_name")
        if secret_name not in self.capabilities.known_secret_names:
            return False, "secret name is not registered with the broker", ("secrets:named-secret",)
        if request.get("least_privilege") is not True:
            return False, "secret requests must assert least-privilege use", ("secrets:least-privilege",)
        if request.get("no_model_echo") is not True:
            return False, "secret requests must prohibit model echo", ("secrets:no-model-echo",)
        return True, "secret request satisfies named-secret and non-disclosure controls", (
            "secrets:named-secret",
            "secrets:least-privilege",
            "secrets:no-model-echo",
        )

    def _verify_approval(
        self,
        request: Mapping[str, Any],
        approval_token: Mapping[str, Any] | None,
        now: datetime,
    ) -> tuple[str | None, str]:
        if approval_token is None:
            return None, "tool class requires an explicit approval token"
        errors = self._schema_errors(approval_token, self.schemas.approval_token)
        if errors:
            return None, f"approval token schema validation failed: {errors[0]}"

        if approval_token["requester"] != request["requester"]:
            return None, "approval token requester does not match the tool request"
        if approval_token["tool_class"] != request["tool_class"]:
            return None, "approval token tool class does not match the tool request"
        if approval_token["exact_scope"] != request["scope"]:
            return None, "approval token scope does not exactly match the tool request"

        try:
            issued_at = _parse_datetime(approval_token["issued_at"])
            expires_at = _parse_datetime(approval_token["expires_at"])
        except (TypeError, ValueError) as exc:
            return None, f"approval token timestamp is invalid: {exc}"
        if issued_at > now:
            return None, "approval token was issued in the future"
        if expires_at <= issued_at:
            return None, "approval token expiry must be after issuance"
        if expires_at <= now:
            return None, "approval token has expired"

        signature = approval_token["signature"]
        key_id = signature["key_id"]
        key = self.keyring.get(key_id)
        if key is None:
            return None, "approval token signing key is unknown"
        expected = hmac.new(key, approval_signing_payload(approval_token), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature["value"]):
            return None, "approval token signature is invalid"
        return str(approval_token["token_id"]), "approval verified"

    def _validate_configuration(self) -> None:
        if self.policy.get("default_decision") != "unknown":
            raise BrokerConfigurationError("runtime policy default_decision must remain unknown")
        if self.policy.get("fail_safe") is not True:
            raise BrokerConfigurationError("runtime policy must enable fail_safe")
        if self.policy.get("tools", {}).get("default") != "deny":
            raise BrokerConfigurationError("runtime policy tools.default must be deny")
        if self.policy.get("egress", {}).get("default") != "deny":
            raise BrokerConfigurationError("runtime policy egress.default must be deny")
        if self.policy.get("human_approval", {}).get("reusable") is not False:
            raise BrokerConfigurationError("approval tokens must be single-use")
        for schema in (
            self.schemas.runtime_policy,
            self.schemas.tool_request,
            self.schemas.approval_token,
            self.schemas.policy_decision,
        ):
            Draft202012Validator.check_schema(schema)
        policy_errors = self._schema_errors(self.policy, self.schemas.runtime_policy)
        if policy_errors:
            raise BrokerConfigurationError(f"runtime policy schema validation failed: {policy_errors[0]}")

    def _schema_errors(self, instance: Any, schema: Mapping[str, Any]) -> list[str]:
        validator = Draft202012Validator(schema, format_checker=self._format_checker)
        errors: list[str] = []
        for error in sorted(validator.iter_errors(instance), key=lambda item: list(item.absolute_path)):
            location = ".".join(str(part) for part in error.absolute_path) or "<root>"
            errors.append(f"{location}: {error.message}")
        return errors

    def _decision(
        self,
        *,
        request_id: str,
        allowed: bool,
        reason: str,
        controls: tuple[str, ...],
        evaluated_at: datetime,
        approval_token_id: str | None = None,
    ) -> dict[str, Any]:
        decision = {
            "schema_version": "1.0.0",
            "request_id": request_id,
            "decision": "allow" if allowed else "deny",
            "reason": reason,
            "controls": list(dict.fromkeys(controls)),
            "evaluated_at": evaluated_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "approval_token_id": approval_token_id,
        }
        errors = self._schema_errors(decision, self.schemas.policy_decision)
        if errors:
            raise BrokerConfigurationError(f"broker emitted an invalid policy decision: {errors[0]}")
        return decision


def approval_signing_payload(token: Mapping[str, Any]) -> bytes:
    payload = dict(token)
    payload.pop("signature", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise BrokerConfigurationError(f"expected object in {path}")
    return value


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = yaml.safe_load(handle)
    if not isinstance(value, dict):
        raise BrokerConfigurationError(f"expected object in {path}")
    return value


def _ensure_aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise BrokerConfigurationError("broker clock must return a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise BrokerConfigurationError("approval token timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def _workspace_relative_path(value: str, *, label: str) -> PurePosixPath:
    if not value or "\\" in value or "\x00" in value:
        raise ValueError(f"{label} must be a normalized POSIX path")
    path = PurePosixPath(value)
    if str(path) != value:
        raise ValueError(f"{label} must be normalized without redundant separators or dot segments")
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"{label} must be a safe workspace-relative path")
    return path


def _workspace_scope(value: str) -> PurePosixPath:
    if not value.startswith("workspace:"):
        raise ValueError("scope must start with 'workspace:'")
    suffix = value[len("workspace:") :]
    if suffix == "":
        return PurePosixPath(".")
    return _workspace_relative_path(suffix, label="workspace scope")


def _is_within_scope(path: PurePosixPath, scope: PurePosixPath) -> bool:
    if scope == PurePosixPath("."):
        return True
    return path == scope or path.parts[: len(scope.parts)] == scope.parts


def _decode_keyring(path: Path | None) -> dict[str, bytes]:
    if path is None:
        return {}
    document = _load_json(path)
    decoded: dict[str, bytes] = {}
    for key_id, value in document.items():
        if not isinstance(key_id, str) or not isinstance(value, str):
            raise BrokerConfigurationError("keyring must map string key IDs to base64 strings")
        try:
            decoded[key_id] = base64.b64decode(value, validate=True)
        except Exception as exc:  # pragma: no cover - exact decoder exception is implementation-specific
            raise BrokerConfigurationError(f"invalid base64 key for {key_id!r}") from exc
        if not decoded[key_id]:
            raise BrokerConfigurationError(f"empty key for {key_id!r}")
    return decoded


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate a guarded VHEATM tool request without executing it.")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--approval", type=Path)
    parser.add_argument("--keyring", type=Path, help="JSON map of key IDs to base64-encoded HMAC keys")
    parser.add_argument("--used-token-dir", type=Path, default=Path(".vheatm/used-approvals"))
    parser.add_argument("--allow-command", action="append", default=[])
    parser.add_argument("--known-secret", action="append", default=[])
    args = parser.parse_args()

    request = _load_json(args.request)
    approval = _load_json(args.approval) if args.approval else None
    broker = ToolBroker.from_root(
        args.root,
        keyring=_decode_keyring(args.keyring),
        capabilities=BrokerCapabilities(
            exact_command_allowlist=frozenset(args.allow_command),
            known_secret_names=frozenset(args.known_secret),
        ),
        token_ledger=DirectoryTokenLedger(args.used_token_dir),
    )
    decision = broker.evaluate(request, approval)
    print(json.dumps(decision, indent=2, sort_keys=True))
    return 0 if decision["decision"] == "allow" else 1


if __name__ == "__main__":
    raise SystemExit(main())
