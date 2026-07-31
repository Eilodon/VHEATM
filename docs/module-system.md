# V17 module system

VHEATM modules are digest-bound instruction packages selected from the canonical 22-gate activation plan. The root `SKILL.md` remains a compact router; it never duplicates the complete audit corpus.

## Artifact chain

```text
audit context
  -> gate plan (`vheatm-evaluate`)
  -> module registry validation
  -> deterministic module selection (`vheatm-route`)
  -> progressive instruction disclosure
  -> module outputs and evidence
  -> semantic report validation
```

## Pilot coverage

The registry remains `pilot`. Batch 2 expands validated coverage to fourteen gates:

- context, system maps, hypothesis generation, compound decomposition, pattern globalization, and evidence anchoring (`HG-P`, `HG-V`, `HG-G`, `HG-CF`, `HG-PG`, `HG-E`);
- architecture decision synthesis, transformation verification, and post-fix verification (`HG-A`, `HG-T`, `HG-FV`);
- architecture smells, auditor defense, hybrid verification, and the adversarial pass (`HG-AS`, `HG-AD`, `HG-HV`, `HG-AP`);
- execution fidelity (`HG-EF`).

`complete` coverage mode is reserved for the point where all 22 gates have validated module coverage.

## Integrity

The registry pins every module digest and every module pins its instruction digest. Repository validation rejects path escape, digest mismatch, unknown gates or phases, dependency cycles, asymmetric conflicts, malformed legacy references, missing instructions, and budget overflow.

The registry records the reviewed legacy archive fingerprint, but the archive remains outside the runtime repository. Its fingerprint is therefore a migration-review assertion rather than a CI rehash of the omitted source bundle.

## Routing semantics

A module selects when its contract policy is satisfied by active covered gates. Unknown covered gates create an unresolved module rather than silently skipping it. Dependencies are included transitively and ordered before dependents. Selected modules are ordered deterministically by phase, priority, dependency, and module ID.

The Batch 2 closure path is:

```text
evidence anchors
  -> architecture decisions
  -> transformation verification
  -> fix verification
  -> adversarial pass
```

Hybrid verification branches from evidence anchoring for mandatory findings. Routing blocks completion when the plan contains unknown gates, a module remains unresolved, selected modules conflict, or disclosure exceeds the hard budget.

## Migration rule

Legacy prose can inform a module, but does not become authoritative until the module has a machine contract, archive/path/heading references, digest-bound instructions, registry inclusion, and regression tests.
