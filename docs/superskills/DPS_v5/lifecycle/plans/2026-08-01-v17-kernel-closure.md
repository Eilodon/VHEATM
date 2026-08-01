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
- Canary preparation now re-evaluates the supplied typed release evidence with the externally signed trust-key registry and current bundle root, then requires exact equality with the proposed 16-gate release report; self-declared all-pass reports remain blocked.
- Release-report identity is now bound to schema version and evaluation time; evaluator and pilot boundaries enforce the canonical report schema, ordered RG-00…RG-15 inventory, derived summary, and deterministic unique evidence bindings.
- Canonical semantic calculators now load schema-valid profile values bound to the manifest version; invalid/mismatched profiles fail closed, and FMEA/BRS/RPN/QBR thresholds are no longer duplicated in runtime code.
- Legacy `policy.py` authority has been migrated out of the runtime path; the canonical `ToolBroker` is now the only policy implementation, with historical code retained as non-authoritative migration text.
- Canonical executable semantic profiles for RPN, corrected FMEA→QBR mapping, QBR mode adjustments, and unknown-preserving BRS scoring.
- Public seeded qualification corpus now executes through a static, deterministic runner into `QRL-*` typed replay evidence; it records observed case outcomes and measurements as `public_seeded`/`unverified` and cannot mint private qualification or GA status.
- Private qualification ingestion now verifies a signed manifest, an absolute/file locator, exact time-slice membership, case digests, corpus identity, and framework binding before emitting a payload-free `PQR-*` receipt; qualification evidence and release reports must bind to and re-verify that receipt.
- Qualification evidence now also binds the exact current control-bundle root; release evaluation refuses private metrics when the current root is absent or differs, preventing signed time-slice evidence from being replayed against another bundle.
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
- Signed release evidence now requires an externally signed `KRG-*` trust-key registry: role public keys, key IDs, framework, current bundle, validity, revocation state, and authority signature are verified before metrics can contribute; direct caller-supplied role keys fail closed, and the registry ID binds the release report.
- Independent judge packets now bind the judge provider version, exact HTTPS endpoint, adapter profile, and configuration digest to the canonical provider allowlist before packet identity or verdict evidence can be consumed; the local `judge.test` descriptor remains `pending`.
- External signer/key custody now has a typed fail-closed protocol: canonical payloads cross only an absolute, non-symlink AF_UNIX transport, request/response schemas bind purpose/key/bundle/digest, the client snapshots requests before transport, and Ed25519 verification is performed against the original bytes. No private key enters this client, and no local signer service is available to authorize release evidence.
- Bundle-bound supply-chain, vulnerability, and provenance builders can now delegate signing to the external `SignerClient`; signer outages, malformed authority inputs, and mixed local/external key paths fail closed, while private-key helpers remain fixture-only compatibility paths.
- Host attestations and trusted key registries now use the same external signer boundary with exact framework/bundle/key binding; framework mismatches and mixed local/external signing fail closed before authority-bearing records are emitted.
- Qualification manifests and evidence now persist framework/bundle scope; their external signer path rejects scope mismatch and the release evaluator requires the manifest to bind the current bundle.
- Blind judge packets/verdicts can persist framework/bundle scope in their content IDs; external judge signing requires that scope, and release qualification rejects verdicts whose scope is absent or mismatched.
- Supply-chain attestation, vulnerability-scan, and provenance records now persist the canonical framework version; producer signing, verified-scan attachment, canonical bundle binding, and RG-13 evaluation reject scope drift.
- Pilot preparation now requires all five roadmap drills, non-empty drill evidence, and schema-bound shadow/canary profile plus terminal-state invariants.

## Verification gates

Fresh evidence for this cycle:

- `.venv/bin/vheatm-validate --root .` — pass.
- `.venv/bin/pytest -o addopts='' -q` — 317 passed in 67.81s.
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
- Trust-registry regression — a signed registry resolves only active, in-window role keys bound to the exact framework/bundle; missing authority, wrong bundle, revoked/expired keys, and direct caller keys leave signed evidence unknown. Registry identity is included in release evidence bindings, while the authority root remains an external prerequisite.
- Judge-provider binding regression — an unallowlisted judge provider is rejected before packet identity is created; packet replay/verification rechecks version, endpoint, adapter profile, and configuration binding. Targeted judge/release tests pass, while external judge qualification remains unavailable.
- Independent-judge runtime boundary — the local callback is used only as the spawn-process test seam; packet identity, signed verdict verification, and the trusted registry remain mandatory before qualification consumption. It is not treated as an external judge deployment or qualification shortcut.
- Signer/supply-chain boundary — eight focused tests cover content-addressed requests, no private-key material, response binding, crypto verification, bounded Unix-socket framing, unavailable-service fail-closed behavior, transport mutation, and external signing of all three bundle-bound supply-chain artifact types; the external service/authority/key-rotation handoff remains unavailable.
- Authority-producer boundary — host-attestation and trust-registry producers delegate through `SignerClient`; five focused regressions cover host/trust signing, exact framework binding, and mixed-key rejection. The external service, authority root, rotation, and deployment custody remain unavailable.
- Qualification/judge producer boundary — qualification manifest/evidence and judge verdict external-signing paths bind purpose, framework, bundle, and key; release-evidence regressions cover scope propagation and mismatch rejection. Operational signer custody and external qualification remain unavailable.
- Supply-chain scope boundary — attestation, vulnerability, and provenance schemas persist `framework_version`; external signer mismatch, foreign verified-scan attachment, and evaluator mismatch regressions remain fail-closed. Operational signer/scanner authority remains unavailable.
- Pilot boundary — provider-outage drill, non-empty drill evidence, read-only/tool-enabled profile flags, and complete/rollback payload requirements are enforced by runtime and `pilot-run.schema.json`.
- `.venv/bin/vheatm-validate --root .` and `.venv/bin/vheatm-doctor --root .` — pass; all module digests match.
- `uv build --wheel --sdist` — pass; both wheel and sdist contain the updated supply-chain schemas/runtime.
- Low-risk evaluate/route — pass; selected 15, unselected 7, unresolved 0, 3374/4096 estimated tokens, `completion_blocked=false`.

## Latest prerequisite probe (2026-08-02)

- A real Trivy `0.70.0` filesystem scan was run against the checkout with the refreshed vulnerability DB, both with and without `--ignore-unfixed`; both reports contained zero vulnerability records, including zero critical/high findings. Candidate report digests were `1fa3dc151bb5eec2ae7fa33724bf4d7a327dfb4f730aa80aa667a49d576` (ignored-unfixed run) and `0aa84c9bc4ca5e3ee1af3f0088873c48e663990e578dd987a93849ff692e11ec` (complete run). The output remains untrusted candidate evidence because no scanner signing key, provenance attestation, or externally signed trust registry was supplied; RG-13 therefore remains unknown.
- The default workspace host has `/usr/bin/bwrap` and `kernel.unprivileged_userns_clone=1`, but its exact required namespace preflight fails with `Operation not permitted`; no host metric is derived there. A separate privileged Docker qualification environment ran the exact reference-monitor flags successfully and produced a typed candidate HQR: `HQR-EAD766493FB21ABE113EC1D9443CB3D5754EC2B3CD0B7FB06EFFB058F0EEB6E5`, `status=complete`, `reference_monitor_status=observed`, 3/3 timeout observations, `hard_stop_p99_seconds=0.12605191`, JSON digest `91ad21ea0b25896e3c08f14f94a97483151bbee6d653956e734cbeaace845446`. A locally generated ephemeral key also verified HAT `HAT-64B949EEF67AA604CA9D1ABCEC1C96822F3EA9C81A0CE650068699D4D6AD0A0A`; it is not trusted host authority evidence.
- No qualified provider endpoint, private/time-sliced corpus, independent judge key/service, external authority root, operational signer/key-custody service, or successful shadow/canary observation was available in the workspace; each remains fail-closed.

## Explicitly not complete

Open release work is intentionally evidence-dependent: external key custody/signing service and authority root/registry, trusted scanner signature/provenance, private/time-sliced gold data, independently qualified judge/provider services, independently attested host-level namespace capability and hard-stop latency, and a successful shadow/canary observation run are not fabricated here. The original V16 archive itself remains unavailable, but its limitation is now explicitly recorded as an extracted-corpus re-baseline rather than an unqualified archive hash. The seeded runner is a replayable local test artifact, not a private or independently judged qualification source; its five-class authorization matrix does not establish host-level p99 hard-stop evidence. The new host runner is a real local probe, and the new HAT, KRG, judge-provider descriptor, and signer-service boundaries are fail-closed seams, but this checkout has no externally trusted host/release authority and therefore cannot authorize RG-09 or GA. The implementation now has enforcing/verifying seams and typed records for each; no production `complete`, `attested`, canary, or GA claim is authorized until RG-00…RG-15 are independently evidenced.
