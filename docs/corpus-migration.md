# V16.1.1 corpus migration

## Source identity

Batch migrations are derived from `VHEATM-v16.1.1.skill` with:

- version: `16.1.1`;
- size: `202566` bytes;
- SHA-256: `efdf9dc7255bebfa5277a729caeeb1edca64be456c62169241fa3573d9fb67bd`.

The fingerprint is recorded in `modules/registry.yaml`. The archive is not loaded into the runtime repository, so CI validates the declared fingerprint contract but does not independently rehash the omitted bundle.

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

## Batch 3 — triggered and meta-defense completion

```text
MOD-SYSTEM-MAPS -> MOD-UTILITY-TREE -> MOD-FMEA-LITE
MOD-HYPOTHESIS-GENERATION -> MOD-INCENTIVE-MISALIGNMENT -> MOD-ORG-BLAST-RADIUS
MOD-HYPOTHESIS-GENERATION -> MOD-CODE-PATH-TRACE
MOD-EVIDENCE-ANCHORS -> MOD-INDEPENDENT-JUDGE
MOD-ADVERSARIAL-PASS + MOD-EXECUTION-FIDELITY -> MOD-CLOSURE-METRICS -> MOD-KNOWLEDGE-BASE
```

All 22 gates are now migrated. The V16.1.1 archive remains source provenance rather than runtime instruction authority.

## Acceptance rule

A migration batch is accepted only when module and instruction digests validate, required registry coverage is present, legacy references identify archive/path/heading sources, dependencies are deterministic and acyclic, disclosure stays within budget, and regression tests prove routing plus tamper detection.
