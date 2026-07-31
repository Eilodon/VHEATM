# VHEATM

VHEATM is an AI-executable audit orchestration framework being rebuilt as a **machine-validated, AI-native control plane**.

The V17 line moves invariants, activation rules, evidence contracts, runtime boundaries, and audit completion decisions out of prose-only instructions and into executable artifacts.

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
- provenance registry with cross-reference checks.

### P1.5 — enforcement closure

- replayable, append-only audit lifecycle state machine;
- semantic report validation across manifest, plan, all 22 gate results, findings, provenance, lifecycle, and attestation;
- passing gates require verified evidence references;
- mandatory and verified findings cannot bypass claim/source lineage;
- signed, scoped, expiring, single-use approval tokens for restricted tool classes;
- deny-before-execution policy guard for execute, write, network, and secret requests;
- atomic persistent provenance with ID recomputation, byte-digest verification, append-only updates, and optimistic concurrency protection;
- expiring attestations bound to canonical manifest, runtime policy, and report subject digests.

The evaluator decides only whether a gate is **active**, **inactive**, or **unknown**. Gate pass/fail remains evidence-bearing output and is checked separately by `vheatm-validate-report`.

## Quick start

```bash
python -m pip install -e '.[dev]'
vheatm-validate --root .
vheatm-evaluate --root . --context examples/context-low-risk.yaml
vheatm-validate-report --root . --report path/to/report.json
pytest
```

`vheatm-evaluate` exit codes:

- `0`: every activation is resolved;
- `1`: invalid context, malformed input, or runtime error;
- `2`: one or more activations remain unknown, so completion is blocked.

## Source-of-truth order

1. `manifests/vheatm-v17.yaml` — framework inventory and activation expressions.
2. `policies/runtime-boundaries.yaml` — runtime trust and safety policy.
3. `schemas/` — machine contracts for context, plans, reports, lifecycle, provenance, approvals, tool requests, and policy decisions.
4. `src/vheatm_control/` — executable validation, planning, enforcement, lifecycle, and provenance.
5. `tests/` — invariants and regression behavior.
6. `docs/` — explanation; never overrides executable artifacts.

The policy engine is a decision-and-guard layer. Platform adapters must still supply the concrete sandbox, filesystem isolation, and network transport required by an allowed decision.

The v16.1.1 prose corpus remains non-authoritative until migrated module-by-module with declared inputs, outputs, activation, evidence, failure behavior, provenance expectations, and tests.
