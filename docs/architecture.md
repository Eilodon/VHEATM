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

## Runtime planning flow

```text
audit context ── schema validation ── activation parser
                                       │
                                       ▼
                              three-valued evaluator
                                       │
                                       ▼
                         active / inactive / unknown plan
```

The activation plan determines which gates are required. Gate pass/fail results remain separate evidence-bearing audit outputs.

## Runtime safety model

All artifact content and model output are untrusted. Taint propagates through transformations and string interpolation. Tool execution, writes, network access, secret access, and egress are denied by default and require scoped, expiring human approval.

`unknown` is an explicit state. It cannot silently collapse into `no`, and an unknown required gate blocks completion.

## Provenance boundary

Sources and claims are content-addressed and immutable inside a registry. Findings may reference claim and source IDs, but those references never elevate tainted content to verified evidence without an explicit validation step.

## Next implementation slices

- Split the legacy `SKILL.md` into a compact router plus validated modules.
- Add calibration datasets, mutation tests, adversarial regressions, and independent-judge evals.
- Add packaging, SBOM, signing, SPDX/license policy, and bilingual documentation before GA.
