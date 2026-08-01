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

## Complete coverage

The registry is `complete`: all 22 canonical gates have exactly one runtime-authoritative module. The final batch adds utility-tree analysis, FMEA-lite, incentive and organizational probes, code-path tracing, independent judging, closure metrics, and knowledge-base lifecycle updates.

Triggered modules remain selected only by the canonical activation plan. Dependencies may disclose prerequisite modules, but no gate gains a second authoritative owner.

## Integrity

The registry pins every module digest and every module pins its instruction digest. Repository validation rejects path escape, digest mismatch, unknown gates or phases, multiple authoritative owners for one gate, dependency cycles, asymmetric conflicts, malformed legacy references, missing instructions, and budget overflow.

The emitted `registry_root` commits to the schema and framework versions, coverage mode, hard window, 75% phase disclosure cap, required gate coverage, module identity and digests, and the reviewed legacy archive fingerprint. The archive remains outside the runtime repository, so CI validates that declared source identity and the migrated digest chain but does not independently rehash the omitted source bundle.

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

Hybrid verification branches from evidence anchoring for mandatory findings. Routing blocks completion when the plan contains unknown gates, a module remains unresolved, selected modules conflict, or any phase exceeds the derived disclosure budget. Instruction bodies can be requested only for one explicit phase at a time; phase transitions carry results through typed artifacts/session state rather than shared prompt context.

## Migration rule

Legacy prose can inform a module, but does not become authoritative until the module has a machine contract, archive/path/heading references, digest-bound instructions, registry inclusion, and regression tests.
