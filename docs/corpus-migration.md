# V16.1.1 corpus migration

## Source identity

Batch migrations are derived from `VHEATM-v16.1.1.skill` with:

- version: `16.1.1`;
- size: `202566` bytes;
- SHA-256: `efdf9dc7255bebfa5277a729caeeb1edca64be456c62169241fa3573d9fb67bd`.

The fingerprint is recorded in `modules/registry.yaml` and included in the deterministic registry root. The archive is not loaded into the runtime repository, so CI validates the fingerprint contract but does not independently rehash the omitted bundle.

## Batch 1 — analysis chain

```text
MOD-CONTEXT-CONTRACT
  -> MOD-SYSTEM-MAPS
  -> MOD-COMPOUND-DECOMPOSITION
  -> MOD-HYPOTHESIS-GENERATION
  -> MOD-PATTERN-GLOBALIZATION
  -> MOD-EVIDENCE-ANCHORS
```

Architecture smell scanning depends on system maps. Auditor defense depends on hypothesis generation.

## Batch 2 — decision and closure chain

```text
MOD-EVIDENCE-ANCHORS
  -> MOD-ARCHITECTURE-DECISIONS
  -> MOD-TRANSFORMATION-VERIFICATION
  -> MOD-FIX-VERIFICATION
  -> MOD-ADVERSARIAL-PASS
```

Hybrid verification also depends on evidence anchoring and is selected only when `HG-HV` is active. The migrated procedures preserve explicit unknowns, require evidence-bearing outputs, and never treat skipped execution or broad test success as proof.

## Non-authoritative remainder

Eight gates remain unmigrated: `HG-UT`, `HG-FL`, `HG-INC`, `HG-ORG`, `HG-CPT`, `HG-IJ`, `HG-M`, and `HG-KB`. Their legacy sections remain research input only.

## Acceptance rule

A migration batch is accepted only when module and instruction digests validate, every gate has a unique owner, legacy references match the registered archive, dependencies are deterministic and acyclic, disclosure stays within budget, and regression tests prove routing plus tamper detection.
