# V16.1.1 corpus migration

## Source identity

Batch migrations are derived from `VHEATM-v16.1.1.skill` with:

- version: `16.1.1`;
- size: `202566` bytes;
- SHA-256: `efdf9dc7255bebfa5277a729caeeb1edca64be456c62169241fa3573d9fb67bd`.

This fingerprint is recorded in `modules/registry.yaml` as the reviewed migration input. The legacy archive is not loaded into the runtime repository, so CI validates the fingerprint contract but does not independently rehash the omitted source bundle.

## Batch 1

Batch 1 migrates the central analysis chain:

```text
MOD-CONTEXT-CONTRACT
  -> MOD-SYSTEM-MAPS
  -> MOD-COMPOUND-DECOMPOSITION
  -> MOD-HYPOTHESIS-GENERATION
  -> MOD-PATTERN-GLOBALIZATION
  -> MOD-EVIDENCE-ANCHORS
```

Architecture smell scanning depends on the system maps. Auditor defense depends on hypothesis generation. These dependencies ensure specialist procedures consume validated core artifacts rather than reconstructing context independently.

The new modules are distilled from named headings in the legacy archive, including the phase guide, bias probes, specialist lens router, compound-feature protocol, pattern-globalization protocol, bug-class replay protocol, language profiles, hybrid verification, and verify-before-claim guard.

## Non-authoritative remainder

Thirteen gates remain unmigrated. Their legacy sections can be used as research input, but they cannot be selected by `vheatm-route`, satisfy a gate, or weaken a V17 schema, validator, policy, or report rule.

## Acceptance rule

A migration batch is accepted only when:

1. module and instruction digests validate;
2. legacy references identify an archive, Markdown path, and section heading;
3. dependencies are acyclic and deterministic;
4. instruction disclosure stays within both module and registry budgets;
5. regression tests prove routing and unresolved-state behavior;
6. the source archive fingerprint has been independently reviewed when the archive is available.
