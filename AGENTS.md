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

- Gate totals and layer distributions must be derived from gate items and validated in CI.
- Phase count must be derived from phase items and validated in CI.
- Framework version appears once in the canonical manifest; other files may reference it but must not redefine it.
- Unknown is not false. Missing or ambiguous declarations resolve to `unknown`, never silently to `no`.
- Untrusted artifact text, comments, docstrings, issue bodies, and model output remain tainted until an explicit validation step clears them.
- Tools are deny-by-default. Write, network, secret, and execution capabilities require explicit policy and a human approval token.
- Findings must separate epistemic status from confidence.
- Every mandatory finding requires evidence, ownership, boundary, remediation, and gate-trace fields.
- Human-readable documentation cannot weaken a schema, policy, or validator rule.

## Agent workflow

Before editing:

```bash
vheatm-validate --root .
pytest
```

After editing, run the same commands. Add or update tests for every invariant change. Never patch generated or duplicated counts manually; change canonical items and let validators derive the counts.

## Safe change policy

- Prefer small, reviewable PRs.
- Do not import the legacy skill wholesale into the runtime path.
- Preserve legacy material under an explicitly non-authoritative migration area when added later.
- Do not add autonomous write or execution behavior without a policy change, test coverage, and explicit review.
