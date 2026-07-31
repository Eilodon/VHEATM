# V17 control-plane architecture

## Design decision

VHEATM keeps the successful conceptual split from v16.1.1:

1. **Core Loop** — always-on audit mechanics.
2. **Specialist Lenses** — activated by explicit context signals.
3. **Meta-Defense** — verifies the auditor, execution fidelity, calibration, and lifecycle.

The change is where authority lives. In V17, prose explains behavior, while executable artifacts enforce behavior.

## Authority boundaries

```text
human intent
    │
    ▼
canonical manifest ── runtime policy ── JSON Schemas
    │                       │                │
    └──────────────┬────────┴───────┬────────┘
                   ▼                ▼
             Pydantic model   schema registry
                   └───────┬────────┘
                           ▼
                    repository validator
                           ▼
                    CI / release gate
```

## Why this is P0

The v16.1.1 corpus contains valuable audit knowledge, but its critical invariants were prose-only. That allowed contradictory gate counts, phase counts, version labels, and non-parseable output examples to coexist. P0 prevents that class of failure before the legacy corpus is migrated.

## Runtime safety model

All artifact content and model output are untrusted. Taint propagates through transformations and string interpolation. Tool execution, writes, network access, secret access, and egress are denied by default and require scoped, expiring human approval.

`unknown` is an explicit state. It cannot silently collapse into `no`, and an unknown required gate blocks completion.

## Next implementation slices

- Build an executable gate evaluator from activation expressions.
- Add provenance registry and claim IDs.
- Split the legacy `SKILL.md` into a 250–350 line router plus validated modules.
- Add calibration datasets, mutation tests, adversarial regressions, and independent-judge evals.
- Add packaging, SBOM, signing, SPDX/license policy, and bilingual documentation before GA.
