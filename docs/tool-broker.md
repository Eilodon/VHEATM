# Guarded tool broker

`vheatm-broker` evaluates canonical tool requests against `policies/runtime-boundaries.yaml`. It emits a schema-valid allow/deny decision and never performs the requested operation.

## Fail-closed rules

- Every request is validated against `tool-request.schema.json` and must use a normalized `workspace:` scope.
- Read requests require explicit `secret_expansion: false` and `contains_secrets: false` declarations.
- Execute requests require a valid single-use approval, an active sandbox, disabled network, disabled secret inheritance, and an exact command allowlist match.
- Write requests require a valid single-use approval, safe diff paths contained by the exact workspace scope, and a rollback plan.
- Network requests require a valid single-use approval, a destination listed by runtime policy, permitted data classes, and redaction. The current empty destination list therefore denies all network requests.
- Secret requests require a valid single-use approval, a broker-registered secret name, least-privilege use, and a no-model-echo declaration.

A cryptographically valid approval is consumed on its first verified evaluation attempt, even when later class-specific controls deny the request. This prevents command or argument probing with one approval token.

## Approval signatures

The broker verifies `hmac-sha256` over canonical UTF-8 JSON of the complete token except the `signature` object. Canonical JSON uses sorted keys with compact separators. Keyring files map key IDs to base64-encoded key bytes.

## CLI

```bash
vheatm-broker \
  --root . \
  --request request.json \
  --approval approval.json \
  --keyring operator-keys.json \
  --used-token-dir .vheatm/used-approvals \
  --allow-command "pytest -q"
```

Exit code `0` means allow; exit code `1` means deny. Decisions conform to `policy-decision.schema.json` and include the controls evaluated. Approval and key material are never echoed.
