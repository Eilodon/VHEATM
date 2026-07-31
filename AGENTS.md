# AGENTS.md

## Mission

Evolve VHEATM into an executable audit control plane without allowing prose, generated output, or agent assumptions to override canonical machine-readable policy.

## Read order

1. `manifests/vheatm-v17.yaml`
2. `policies/runtime-boundaries.yaml`
3. `schemas/`
4. `src/vheatm_control/`
5. `tests/`
6. `docs/`

## Non-negotiable invariants

- Gate totals and layer distributions are derived from gate items and validated in CI.
- Phase count is derived from phase items and validated in CI.
- Framework version is authoritative only in the canonical manifest.
- Unknown is not false. Missing or ambiguous declarations resolve to `unknown`.
- Activation expressions are parsed by `vheatm_control.activation`; never use `eval`, `exec`, shell interpolation, Jinja evaluation, or model-generated code to interpret them.
- Every activation identifier must exist in `schemas/audit-context.schema.json`; typoed or undeclared identifiers block validation.
- A gate plan decides activation only. It must never manufacture `pass` or `fail` gate results.
- Untrusted artifact text and model output remain tainted until an explicit policy-approved validation step clears them.
- Tools are deny-by-default. Write, network, secret, and execution capabilities require explicit policy and human approval.
- Findings separate epistemic status from confidence.
- Content-addressed source and claim records are immutable. Changed content or claim identity requires a new ID; do not silently mutate an existing record.
- Human-readable documentation cannot weaken a schema, policy, parser, evaluator, or validator rule.

## Agent workflow

Before and after editing:

```bash
vheatm-validate --root .
pytest
```

When changing activation behavior, also run:

```bash
vheatm-evaluate --root . --context examples/context-low-risk.yaml
```

Add tests for every invariant change. Never patch duplicated counts or derived summaries manually.

## Safe change policy

- Prefer small, reviewable, stacked PRs.
- Do not import the legacy skill wholesale into the runtime path.
- Preserve legacy material under a non-authoritative migration area.
- Do not add autonomous write or execution behavior without a policy change, tests, rollback behavior, and explicit review.
