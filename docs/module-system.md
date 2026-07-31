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

The registry remains `pilot`, but Batch 1 expands validated coverage to nine gates:

- core context contract (`HG-P`);
- core system and boundary maps (`HG-V`);
- core hypothesis generation and bias control (`HG-G`);
- core compound feature decomposition (`HG-CF`);
- core pattern globalization (`HG-PG`);
- core evidence anchors and claim disposition (`HG-E`);
- triggered architecture smell scanning (`HG-AS`);
- triggered auditor defense (`HG-AD`);
- meta execution fidelity (`HG-EF`).

`complete` coverage mode is reserved for the point where all 22 gates have validated module coverage.

## Integrity

The registry pins the SHA-256 of every module document. Each module document pins the SHA-256 of its instruction file. The registry also records the artifact name, version, byte length, and SHA-256 declared for the legacy archive used during migration.

Repository validation rejects path escape, digest mismatch, unknown gates or phases, dependency cycles, asymmetric conflicts, missing instructions, malformed legacy references, and instruction bodies that exceed their declared token budget. The legacy archive is intentionally not loaded into the runtime repository, so its recorded byte fingerprint is a migration-review assertion rather than a CI rehash of the source bundle.

## Routing semantics

A module selects when its contract policy is satisfied by active covered gates. Unknown covered gates create an unresolved module rather than silently skipping it. Dependencies are included transitively and ordered before dependents. Selected modules are ordered deterministically by phase, priority, dependency, and module ID.

Routing blocks completion when the plan contains unknown gates, a module remains unresolved, selected modules conflict, or instruction disclosure exceeds the registry hard budget.

## Migration rule

Legacy prose can inform a module, but does not become authoritative until the module has a machine contract, archive/path/heading references, digest-bound instructions, registry inclusion, and tests. The recorded archive fingerprint identifies the reviewed migration source; it does not make the legacy archive executable policy.
