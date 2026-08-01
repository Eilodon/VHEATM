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
- Machine-readable standards baseline with namespace/review semantics, plus a canonical `uv.lock` bound into the bundle and supply-chain attestation.
- Digest-bound bubblewrap reference-monitor adapter with read-only workspace, mandatory network namespace preflight, cleared environment, dropped capabilities, resource limits, and typed blocked run evidence.
- Ed25519-bound supply-chain, vulnerability, provenance, private/time-sliced qualification, external-provider, and pilot-completion records; verified typed evidence now takes precedence over raw release metric shortcuts.
- Release-gate evaluation now ignores caller-supplied metric shortcuts, verifies qualification and supply-chain signatures at the trust boundary, and binds the report digest to the content-addressed evidence IDs.
- External providers now have a bounded HTTPS transport with TLS, redirect refusal, timeout/response caps, metadata-only payloads, and broker-before-network ordering; pilot completion requires content-addressed completed provider runs.
- Qualification evidence now binds to content-addressed independent-judge verdicts, rejects undeclared metrics, enforces critical sample floors, and validates typed evidence schemas at CLI ingest.
- Canonical executable semantic profiles for RPN, corrected FMEA→QBR mapping, QBR mode adjustments, and unknown-preserving BRS scoring.

## Verification gates

Fresh evidence for this cycle:

- `.venv/bin/vheatm-validate --root .` — pass.
- `.venv/bin/pytest -o addopts=''` — 187 passed.
- Low-risk evaluate/route — exit 0; 15 active, 7 inactive, 0 unknown; 3374/4096 estimated tokens; context route equals plan route; current bundle root `9ad5fb4f3f765b337820e3ba270e9428cea1812915319ab41b9adc532ae7c797` with 155 canonical entries.
- Session, analyzer, judge, capability, release-gate, supply-chain, and pilot contract tests — pass; incomplete release evidence remains unknown/blocking by design.
- `uv build --wheel --sdist` — pass; package assets include the migration corpus, seeded eval corpus, standards/semantic policies, schemas, and `uv.lock`.
- Global authority scan — no built-in `eval`/`exec`, shell interpolation, or target-code import/execution in the control runtime; the only subprocess boundary is the explicit digest-bound sandbox adapter with `shell=False`, while activation remains parser-backed (`ast.literal_eval` only).

## Explicitly not complete

Open release work is intentionally evidence-dependent: external key custody/signing service, fresh vulnerability scan feed, private/time-sliced gold data, allowlisted external provider qualification, host-level namespace capability, and a successful shadow/canary observation run are not fabricated here. The implementation now has enforcing/verifying seams and typed records for each; no production `complete`, `attested`, canary, or GA claim is authorized until RG-00…RG-15 are independently evidenced.
