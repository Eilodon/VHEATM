# V17 Hardened Kernel Closure

**Date:** 2026-08-01
**Source:** user-approved VHEATM V17 Ultimate roadmap
**Status:** WP1–WP12 local-first contract slices implemented; production GA remains blocked by explicit release evidence

## Implemented in this cycle

- Canonical control bundle inventory and SHA-256 root, with strict duplicate-key YAML/JSON loading.
- Wheel/sdist packaging of the canonical bundle and offline fallback when no checkout root is present.
- Required context-v2 subject snapshot, risk/organization dimensions, finding ledger, and empty-context rejection.
- Plan binding to manifest, bundle, context, evaluator, session root, revision parent, and immutable monotonic replanning.
- Content-addressed provenance sources, claims, validation receipts, lineage, 256-bit IDs, append-only journal, and atomic extension checks.
- Typed artifact envelopes, provider-bound ModuleRuns, typed failures, static dependency artifact/schema compatibility, and derived gate results.
- Report binding to plan ID, selection digest, typed run/artifact/receipt collection digests, provenance, and lifecycle replay.
- Broker approval tokens bound to the complete request digest and content-addressed tool decision receipts.
- SQLite WAL plus filesystem CAS session store with immutable snapshots, idempotent event keys, monotonic plan attachment, replay, and tamper detection.
- Brokered Python AST/linkage adapters with versioned descriptors, source-snapshot binding, read receipts, candidate-only output, and separate deterministic validation receipts.
- Blind independent-judge packet/verdict contracts with spawn-process isolation, randomized order, provider/model/config binding, timeout blocking, divergence detection, and HITL escalation.
- Capability ledger for all 33 legacy corpus files; 22 are corrected/owned and 11 remain explicitly `missing` rather than being silently promoted.
- Seeded evaluation corpus, frozen RG-00…RG-15 metric evaluator, canonical SBOM evidence, and a shadow/canary pilot record with rollback and outage/clock-skew drills.

## Verification gates

Fresh evidence for this cycle:

- `.venv/bin/vheatm-validate --root .` — pass.
- `.venv/bin/pytest -o addopts=''` — 174 passed.
- Low-risk evaluate/route — exit 0; 15 active, 7 inactive, 0 unknown; 3374/4096 estimated tokens; context route equals plan route; current bundle root `6a7c3af65570204e64511dc6656ffeeb5ff094920ab36a4154c0cac7dccd288d` with 149 canonical entries.
- Session, analyzer, judge, capability, release-gate, supply-chain, and pilot contract tests — pass; incomplete release evidence remains unknown/blocking by design.
- Wheel/sdist and offline packaged checks must be rerun after this tranche; canonical assets now include the migration corpus and seeded eval corpus.
- Global authority scan — no built-in `eval`/`exec`, shell, or target-code import/execution in the control runtime; judge code is the explicit spawn-process trust boundary and activation remains parser-backed (`ast.literal_eval` only).

## Explicitly not complete

Open release work is intentionally evidence-dependent: a real sandbox action adapter/reference monitor, dependency lock, release signing/key service, vulnerability scan evidence, private/time-sliced gold data, and a successful shadow pilot are not fabricated here. The current implementation can produce their required typed records, but no production `complete`, `attested`, canary, or GA claim is authorized until RG-00…RG-15 are independently evidenced.
