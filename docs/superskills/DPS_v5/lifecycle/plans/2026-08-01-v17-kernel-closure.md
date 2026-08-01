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
- Capability ledger for all 33 legacy corpus files; 32 are corrected/owned and UX-04 remains explicitly `missing` because real user-research evidence is unavailable.
- Seeded evaluation corpus, frozen RG-00…RG-15 metric evaluator, canonical SBOM evidence, and a shadow/canary pilot record with rollback and outage/clock-skew drills.
- Machine-readable standards baseline with namespace/review semantics, plus a canonical `uv.lock` bound into the bundle and supply-chain attestation.
- Digest-bound bubblewrap reference-monitor adapter with read-only workspace, mandatory network namespace preflight, cleared environment, dropped capabilities, resource limits, and typed blocked run evidence.
- Ed25519-bound supply-chain, vulnerability, provenance, private/time-sliced qualification, external-provider, and pilot-completion records; verified typed evidence now takes precedence over raw release metric shortcuts.
- Release-gate evaluation now ignores caller-supplied metric shortcuts, verifies qualification and supply-chain signatures at the trust boundary, and binds the report digest to the content-addressed evidence IDs.
- External providers now have a bounded HTTPS transport with TLS, redirect refusal, timeout/response caps, metadata-only payloads, and broker-before-network ordering; pilot completion requires content-addressed completed provider runs.
- Qualification evidence now binds to content-addressed independent-judge verdicts and their blind packet sidecars, requires exact packet-item coverage, rejects undeclared metrics, enforces private-case sample floors, and validates typed evidence schemas at CLI ingest.
- Direct evaluator APIs now enforce the same typed evidence schemas and RFC 3339 format checks before cryptographic verification; schema-invalid qualification stays unknown and schema-invalid supply-chain evidence cannot pass RG-13.
- Critical qualification measurements now declare canonical sample populations; private-case trial counts cannot exceed the verified private receipt case count or independently judged packet coverage, bounded metric domains are enforced, and unbound/oversized claims remain `unknown`.
- Sandbox outcomes now bind schema-valid reference-monitor decisions and content-addressed tool receipts to the exact action; malformed authorization fails closed before backend launch.
- All brokered action adapters now share semantic decision validation; malformed provider authorization is blocked before transport and cannot emit a completed run without a valid network receipt.
- Pilot completion now re-verifies the persisted redacted network request, receipt identity, request/action digests, broker semantics, response digest, and completed-response requirement before accepting shadow/canary observations.
- Canary preparation now re-evaluates the supplied typed release evidence with verification keys and the current bundle root, then requires exact equality with the proposed 16-gate release report; self-declared all-pass reports remain blocked.
- Release-report identity is now bound to schema version and evaluation time; evaluator and pilot boundaries enforce the canonical report schema, ordered RG-00…RG-15 inventory, derived summary, and deterministic unique evidence bindings.
- Canonical semantic calculators now load schema-valid profile values bound to the manifest version; invalid/mismatched profiles fail closed, and FMEA/BRS/RPN/QBR thresholds are no longer duplicated in runtime code.
- Legacy `policy.py` authority has been migrated out of the runtime path; the canonical `ToolBroker` is now the only policy implementation, with historical code retained as non-authoritative migration text.
- Canonical executable semantic profiles for RPN, corrected FMEA→QBR mapping, QBR mode adjustments, and unknown-preserving BRS scoring.
- Public seeded qualification corpus now executes through a static, deterministic runner into `QRL-*` typed replay evidence; it records observed case outcomes and measurements as `public_seeded`/`unverified` and cannot mint private qualification or GA status.
- Private qualification ingestion now verifies a signed manifest, an absolute/file locator, exact time-slice membership, case digests, corpus identity, and framework binding before emitting a payload-free `PQR-*` receipt; qualification evidence and release reports must bind to and re-verify that receipt.
- Independent judge verdicts contributing to qualification now require a distinct Ed25519 judge signature at the release boundary; unsigned or evaluator-key-reused verdicts remain unknown and cannot authorize RG-04/RG-05/RG-07.
- RG measurement method digests now resolve to a schema-valid, manifest-bound qualification-method policy; estimator, confidence method, sample basis, and minimum sample floors cannot be caller-invented, and public seeded replay emits the same canonical identities.
- RG-13 supply-chain evidence now resolves to a schema-valid, manifest-bound freshness/key-separation policy; stale/future vulnerability scans and reused signing key material fail closed with diagnostic rationale.
- Pilot completion and rollback now revalidate the prepared pilot's immutable content-addressed ID; caller-mutated execution mode or scope cannot cross a lifecycle transition.
- Provider execution and persisted-run verification now require canonical allowlist membership; shadow accepts only `pending` allowlisted providers and canary requires external `qualified` state, with all local entries intentionally pending.
- Execute approvals now bind the backend executable digest; the sandbox revalidates bytes per run and passes the verified backend FD to preflight/action launch to narrow TOCTOU exposure.
- Verified claims used by gates/findings now carry content-addressed gate traces; report validation rejects a claim whose trace does not cover the consuming gate, closing generic-claim cross-gate reuse.
- Passing gates now reject direct `SRC-*` evidence, including trusted sources; source records must remain lineage for a gate-bound claim or typed artifact.
- Seeded security qualification now exercises read, write, execute, network, and secrets denial paths with real schema/approval-bound broker requests; all five are blocked and the public run remains `unverified`.
- Semantic migration now has schema-bound, non-authoritative records for signal/noise decisions, FAST/Standard/Full legacy-output mapping, enterprise stakeholder ownership, cross-cutting L7 obligations, ordered temporal/L4 scans, AI-RMF governance, and assurance maturity deltas; unknown and tainted states remain explicit.
- Legacy archive provenance is now machine-readable: the unavailable original V16 archive is explicitly re-baselined to the content-addressed extracted corpus, and validator checks prevent an absent archive from being labelled `verified`.
- RG-13 supply-chain attestations now re-compute and bind SBOM, dependencies, and dependency-lock metadata to the current canonical bundle before signed evidence can contribute release metrics.
- Host qualification now has a separate `vheatm-qualify-host` runner and typed `HQR-*` record: it rehashes bubblewrap, runs approval-bound timeout probes through the real sandbox boundary, records only executor-reported `timeout:enforced` samples, and leaves unavailable namespace capability as `blocked/unverified`.

## Verification gates

Fresh evidence for this cycle:

- `.venv/bin/vheatm-validate --root .` — pass.
- `.venv/bin/pytest -o addopts=''` — 268 passed.
- Release-evidence regressions cover signed qualification and supply-chain documents with undeclared fields; both fail closed at the direct evaluator boundary.
- Qualification regressions reject signed evidence with arbitrary method digests and verify canonical method-policy/bundle binding.
- Supply-chain regressions reject stale/future vulnerability scans and reuse of one signing key across release, vulnerability, and provenance roles.
- Pilot regressions reject a mutated `ready` pilot before accepting observations or enabling a changed execution mode.
- Provider/pilot regressions reject unallowlisted providers and prevent pending providers from crossing the canary boundary.
- `.venv/bin/vheatm-qualify-public --root . --observed-at 2026-08-01T00:00:00Z` — 17/17 seeded cases executed, `QRL-*` identity/schema valid, 14 observed measurements; determinism case executed 1,000 evaluation runs; visibility remains `public_seeded` and evidence state `unverified`.
- Low-risk evaluate/route — exit 0; 15 active, 7 inactive, 0 unknown; 3374/4096 estimated tokens; context route equals plan route; current bundle root is regenerated after this canonical adapter/schema change and remains content-addressed.
- Session, analyzer, judge, capability, release-gate, private-corpus, supply-chain, and pilot contract tests — pass; incomplete release evidence remains unknown/blocking by design.
- `uv build --wheel --sdist` — pass; package assets include the migration corpus, seeded eval corpus, standards/semantic policies, schemas, and `uv.lock`.
- Global authority scan — no built-in `eval`/`exec`, shell interpolation, or target-code import/execution in the control runtime; the only subprocess boundary is the explicit digest-bound sandbox adapter with `shell=False`, while activation remains parser-backed (`ast.literal_eval` only).
- Backend-integrity regression — backend replacement after executor construction is blocked, and execute request/approval identity includes `executable_digest`; verified backend FD is reused for preflight and action launch.
- Provenance/report regressions — a claim bound to `HG-B` cannot support passing `HG-A`; gate binding is part of the claim identity and schema-valid claims remain immutable.
- Direct-source regression — a trusted `SRC-*` record cannot be promoted to passing gate evidence without a typed gate-bound claim/artifact.
- Security-matrix regression — the seeded RG-09 authorization case covers all five tool classes with `unauthorized_block_rate=1.0` over five observations; no host hard-stop latency is synthesized.
- Legacy provenance regression — the canonical registry validates the extracted-corpus digest and rejects a `verified` archive declaration when the original archive is absent.
- Capability-ledger regression — extracted-corpus symlink content is rejected before the ledger digest can authorize migration coverage.
- Supply-chain source-binding regression — a signed attestation with a self-consistent forged SBOM is rejected at RG-13 because it does not match the current canonical bundle.
- Host qualification regression — unavailable bubblewrap/namespace capability emits no hard-stop metric; only real sandbox timeout enforcement can create a local `hard_stop_p99_seconds` candidate. A separate Ed25519 host attestation now binds that candidate to the exact run, current bundle, deployment, and capability profile, but external key custody/authority is still required before it can mint release-gate status.

## Explicitly not complete

Open release work is intentionally evidence-dependent: external key custody/signing service and authority registry, fresh vulnerability scan feed, private/time-sliced gold data, allowlisted external provider qualification, independently attested host-level namespace capability and hard-stop latency, and a successful shadow/canary observation run are not fabricated here. The original V16 archive itself remains unavailable, but its limitation is now explicitly recorded as an extracted-corpus re-baseline rather than an unqualified archive hash. The seeded runner is a replayable local test artifact, not a private or independently judged qualification source; its five-class authorization matrix does not establish host-level p99 hard-stop evidence. The new host runner is a real local probe, and the new HAT verifier is a fail-closed handoff seam, but this checkout has no trusted external host authority and therefore cannot authorize RG-09. The implementation now has enforcing/verifying seams and typed records for each; no production `complete`, `attested`, canary, or GA claim is authorized until RG-00…RG-15 are independently evidenced.
