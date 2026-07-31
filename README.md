# VHEATM

VHEATM is an AI-executable audit orchestration framework being rebuilt as a **machine-validated, AI-native control plane**.

The V17 line moves invariants, activation rules, evidence contracts, and runtime boundaries out of prose-only instructions and into executable artifacts.

## Implemented slices

### P0 — control-plane foundation

- canonical manifest for 8 phases and 22 hard gates;
- JSON Schema 2020-12 contracts;
- Pydantic and cross-file validation;
- tri-state declarations (`yes`, `no`, `unknown`);
- deny-by-default trust, taint, tool, sandbox, and egress policy;
- coding-agent contract and CI.

### P1 — deterministic planning and provenance

- safe activation DSL parsed without Python `eval` or `exec`;
- strong-Kleene three-valued logic, where unresolved security context remains `unknown`;
- deterministic gate activation plans with machine-readable reasons;
- context-schema reference validation that catches misspelled identifiers in CI;
- content-addressed source and claim IDs;
- append-only provenance registry with cross-reference checks;
- optional provenance and activation-plan links in audit reports and findings.

The evaluator decides only whether a gate is **active**, **inactive**, or **unknown**. It never claims that a gate passed.

## Quick start

```bash
python -m pip install -e '.[dev]'
vheatm-validate --root .
vheatm-evaluate --root . --context examples/context-low-risk.yaml
pytest
```

`vheatm-evaluate` exit codes:

- `0`: every activation is resolved;
- `1`: invalid context, malformed input, or runtime error;
- `2`: one or more activations remain unknown, so completion is blocked.

## Source-of-truth order

1. `manifests/vheatm-v17.yaml` — framework inventory and activation expressions.
2. `policies/runtime-boundaries.yaml` — runtime trust and safety policy.
3. `schemas/` — machine contracts, including audit context and gate plans.
4. `src/vheatm_control/` — executable validation, planning, and provenance.
5. `tests/` — invariants and regression behavior.
6. `docs/` — explanation; never overrides executable artifacts.

The v16.1.1 prose corpus remains non-authoritative until migrated module-by-module with declared inputs, outputs, activation, evidence, failure behavior, and tests.
