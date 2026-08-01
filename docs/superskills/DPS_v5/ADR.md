# Architecture Decision Records

## ADR-1 — Bound activation and typed execution kernel

**Status:** ✅ ACCEPTED
**Date:** 2026-08-01
**Deciders:** VHEATM maintainers
**Tags:** `authority-kernel` `typed-execution` `provenance`
**Change Classification:** `DESIGN CHANGE`
**Review date:** 2026-09-01 — re-evaluate when a second runtime entry point consumes context v2 or 1,000 plan revisions have been replayed.
**Supersedes:** —
**Superseded by:** —

**DECISION TYPE:** `CONSTRAINT-FORCED`
**CONFIDENCE:** `HIGH` — direct mutation and regression tests cover the trust-boundary invariants.
**LAST CONFIRMED:** 2026-08-01 — `IMPLEMENTATION`
**VOLATILITY:** `WATCHFUL` — the authority model is revisited when sandbox enforcement, signing, or a second provider crosses the runtime boundary.

### Context

The V17 plan cache could be altered by a caller after evaluation, raw artifact parsing could clear taint, and reports could claim passing gates without a bound module invocation or typed output. The original context contract also accepted an empty object and could not represent late findings that change activation obligations.

### Decision

Make activation plans content-bound to the canonical manifest, normalized context, evaluator build, and revision metadata; recompute them at router, aggregator, and report trust boundaries. Keep raw sources tainted until an explicit validation receipt exists. Route modules through typed output contracts, bind `ModuleRun` records to module/instruction digests, and derive gate results only from validated runs and decision artifacts. Add a schema-v2 context adapter plus immutable, parent-bound plan revisions for late facts while retaining v1 compatibility aliases.

### Options Considered

- Trust caller-provided activation states and report gate results: rejected because it creates false assurance at the authority boundary.
- Copy all legacy prose into runtime modules: rejected because it exceeds the disclosure budget and still does not prove execution.
- Require a full SQLite/CAS/session implementation before these controls: rejected for this slice; it would delay containment of the already observed P0 failures.

### Impact

Schemas changed: `audit-context`, `gate-plan`, `module-contract`, `module-selection`, `audit-report`, provenance, artifact, module-run, failure, tool, and validation-receipt schemas.
Components changed: evaluator, router, execution aggregator, report validator, provenance registry, structural probe, and module contracts.
Breaking change: **YES** for unbound external plans and reports without typed execution; v1 contexts remain supported through the adapter.

IMPACT RADIUS: **MODERATE**
Cascades: `context → plan → selection → ModuleRun/artifacts → gate results → report`.
Cascade Review: ✅ Done

### Consequences

- Plan tampering, missing invocation, forged output payloads, tainted evidence, and unbound selection are fail-closed.
- Module contracts now expose reusable typed output schemas without creating one schema per module.
- Context v2 can derive mandatory findings from its ledger and create a child plan for late facts.
- SQLite WAL/CAS persistence, subject/session roots, brokered Python analyzer adapters, isolated independent-judge/HITL records, and a fail-closed local reference-monitor seam now exist as local-first slices. External key custody, private qualification corpus, and production provider integrations remain release-gated.

### Evidence

- [verified 2026-08-01] `.venv/bin/vheatm-validate --root .` passed.
- [verified 2026-08-01] `.venv/bin/pytest -o addopts=''` passed with 174 tests.
- [verified 2026-08-01] v2 low-risk evaluation and context/plan routing both returned exit 0 with 15 active, 7 inactive, 0 unknown, and 3374/4096 estimated tokens.
- [verified 2026-08-01] Mutation tests reject activation-state edits, unbound plans, missing validation receipts, forged artifacts, missing module runs, and direct aggregator plan spoofing.

### Owner

**VHEATM maintainers**

### Known Debts (PATTERN-DEBT)

PATTERN-DEBT entries introduced or affected by this change: none registered. Deferred architectural work is listed under Consequences and is tracked by the V17 roadmap, not silently treated as complete.

### Next Cycle Trigger

Start the next cycle when a reference-monitor sandbox, signing/key service, or external provider is introduced; each requires a new trust-boundary ADR plus crash/recovery, isolation, and release-gate evidence.

### Cycle Retrospective

- The main false-assurance risk was at trust boundaries, not in the activation parser itself; recomputation must happen at every consumer.
- Updating module contracts required regenerating every registry digest; registry integrity is part of runtime correctness.
- A validation receipt must be modeled separately from source and claim records; changing taint state alone is not evidence.
- The v1 adapter must preserve unknown rather than infer missing critical declarations.
- The next cycle should avoid presenting the context-v2 adapter as a complete session model until subject snapshots and CAS roots are implemented.

## ADR-2 — Local-first typed execution, adjudication, and release-evidence plane

**Status:** ACCEPTED
**Date:** 2026-08-01
**Deciders:** VHEATM maintainers
**Tags:** `execution` `adjudication` `migration` `release-gates`
**Change Classification:** `DESIGN CHANGE`
**Review date:** 2026-09-01 — or earlier when a reference-monitor action adapter, signing/key service, external analyzer provider, or RG-13 evidence pipeline is introduced.

### Context

The v17 kernel established canonical bundles, typed plans and artifacts, strict activation, provenance boundaries, and deterministic routing. The remaining roadmap slices require durable session state, brokered analyzer evidence, independent adjudication, corrected legacy capability coverage, release-gate evaluation, supply-chain evidence, and a pilot boundary. These capabilities must be useful locally without implying that local tests are production qualification.

### Decision

Implement the next tranche as a local-first typed control plane:

1. SQLite WAL plus content-addressed filesystem storage provides immutable session objects, append-only event chains, replay, resume, and idempotency.
2. Analyzer adapters are brokered and read-only; source text and analyzer output remain tainted until a separate deterministic verifier emits a validation receipt bound to the source snapshot and bundle.
3. Independent judge packets use distinct source/judge contexts and provider/model/config identities, blind ordering, hard divergence handling, and explicit HITL escalation. Provider timeout or hard failure blocks completion.
4. A capability ledger covers the complete preserved 33-file legacy corpus with explicit dispositions; missing or corrected capability records are machine-visible rather than silently inferred.
5. Evaluation and pilot records are schema-bound. Release predicates RG-00 through RG-15 fail closed on missing evidence; shadow/canary records cannot claim GA eligibility without all gates passing.
6. Supply-chain output is explicit about unsigned, unlocked, partial, or otherwise incomplete evidence. No local implementation claims a production sandbox, signing service, private gold corpus, external provider, or GA release.

### Options Considered

- Distributed services first: rejected; it would add deployment and failure complexity before local contracts and evidence boundaries were stable.
- Treat analyzer or model output as trusted evidence: rejected; this would collapse epistemic status, taint, and confidence boundaries.
- Mark the 11 uncovered legacy files as migrated: rejected; the ledger must preserve `missing` until a reviewed owner and contract exist.
- Infer GA readiness from unit tests: rejected; qualification metrics, private/time-sliced corpora, signing, and operational evidence remain release-gated.

### Impact

Components changed: session store, analyzer adapters, judge/HITL, capability ledger, evaluation/release-gate, supply-chain attestation, pilot schemas, bundle packaging, validator, and registry terminology.
Breaking change: **YES**. The canonical bundle now includes the evaluated corpus and preserved legacy corpus; registry coverage terminology is explicit about gate ownership.
IMPACT RADIUS: **WIDE**
Cascades: `bundle → validator → plan/route → evidence → release/pilot`.
Cascade Review: ✅ Done — full verification suite, low-risk evaluate/route path, package smoke checks, and unsafe-execution scan were rerun for this tranche.

### Consequences

Positive:

- Runtime state and evidence have durable local boundaries instead of process-memory-only behavior.
- Analyzer and judge outputs can be audited without promoting unverified text to authoritative findings.
- Migration coverage, release readiness, and pilot safety are visible as typed records and fail-closed predicates.

Known limitations:

- Production qualification of the action reference monitor and external analyzer providers, plus private/time-sliced gold corpus, vulnerability evidence, signing/key custody, and canary operations, remains unavailable; local enforcement seams and adapters are implemented but do not prove production readiness.
- The release evaluator can honestly report `unknown`/`fail`, but it does not manufacture qualification metrics.
- The public seeded corpus has an executable static runner that emits replayable `QRL-*` records with observed measurements while retaining `public_seeded` visibility and `unverified` evidence state; it is explicitly not a substitute for private gold data or independent adjudication.

### Evidence

- [verified 2026-08-01] `vheatm-validate --root .` passes.
- [verified 2026-08-01] `pytest -o addopts=''` passes the complete suite.
- [verified 2026-08-01] low-risk evaluation and routing agree, with no unresolved activations or budget overflow.
- [verified 2026-08-01] wheel/sdist build and offline installed CLI smoke checks pass.
- [verified 2026-08-01] source scan finds no runtime `eval`, `exec`, shell interpolation, or target-code import/execution; the explicit subprocess boundary is now isolated in the digest-bound sandbox adapter.

### Owner and Known Debts

**Owner:** VHEATM maintainers

Known pattern debt: none newly opened; the pattern-debt registry has no `OPEN` entries. The limitations above are intentional release qualification debt tracked by this ADR and the v17 lifecycle plan.

### Next Cycle Trigger

Start the next ADR when the first reference-monitor action boundary, signing/key service, external provider, or RG-13 locked/vulnerability/signed evidence path is implemented.

### Cycle Retrospective

- Local-first persistence exposed the correct seam for later crash and fault-injection qualification.
- Separate analyzer verification and judge adjudication preserve the distinction between candidate output and authoritative evidence.
- The capability ledger makes incomplete migration measurable rather than rhetorical.
- Release and pilot records now prevent local implementation status from being mistaken for GA qualification.
- The next cycle should prioritize real enforcement and measured qualification evidence, not additional status labels.

## ADR-3 — Pinned standards baseline and lock-bound supply-chain evidence

**Status:** ACCEPTED
**Date:** 2026-08-01
**Deciders:** VHEATM maintainers
**Tags:** `standards` `supply-chain` `release-evidence`
**Change Classification:** `DESIGN CHANGE`
**Review date:** 2026-09-01 — or earlier when a signing/key service, vulnerability evidence feed, or standards revision is introduced.
**Supersedes:** —
**Superseded by:** —

**DECISION TYPE:** `CONSTRAINT-FORCED`
**CONFIDENCE:** `HIGH` — schema, canonical bundle, lock consistency, attestation, and packaging checks cover the changed boundary.
**LAST CONFIRMED:** 2026-08-01 — `IMPLEMENTATION`
**VOLATILITY:** `WATCHFUL` — NIST AI RMF is under revision and community/experimental guidance must not silently become normative.

### Context

RG-13 had a canonical SBOM shape but no repository lock binding, while the roadmap's standards baseline existed only as prose. A present-but-unvalidated lock or an evolving guidance document could create false release evidence. The repository also uses a pre-release MCP dependency, so the resolution policy must be explicit.

### Decision

Add `policies/standards-baseline.yaml` and its schema as canonical control-plane policy. Each reference records its namespace, status, authority, source, role, review trigger, and an invariant that no entry authorizes certification claims; normative entries must be pinned, while community/draft/experimental entries remain visibly non-normative. Generate `uv.lock` with pre-release resolution explicitly enabled, include it in the canonical bundle and sdist/wheel assets, require it in repository validation, and bind its SHA-256 digest into supply-chain attestation. CI runs `uv lock --check --prerelease=allow`. Signing, key custody, vulnerability scanning, and release eligibility remain separate gates.

### Options Considered

- Keep standards and dependency versions in prose: rejected because canonical validators and release evidence could not detect drift.
- Use an unpinned `requirements.txt`: rejected because it does not bind the full resolved graph or package hashes.
- Mark a local HMAC key or lock presence as a signed release: rejected because key custody and provenance verification require an external release trust boundary.

### Impact

Schemas changed: `standards-baseline.schema.json`, `supply-chain-attestation.schema.json`.
Components changed: canonical bundle, setup packaging, validator, supply-chain attestation, release workflow, and release evidence tests.
Breaking change: **YES** for repositories that omit the canonical standards policy or `uv.lock`.

IMPACT RADIUS: **WIDE**
Cascades: `standards/lock → bundle root → validator → SBOM/attestation → RG-13`.
Cascade Review: ✅ Done

### Consequences

- Standards drift and lock drift now alter the bundle root and are visible to validation/CI.
- Supply-chain evidence can truthfully report a verified lock digest while remaining `partial` until signing and vulnerability evidence exist.
- The lock includes the MCP pre-release resolution and therefore must be reviewed when that dependency moves to a stable release.

Known limitations: key custody/signing service, verified provenance and vulnerability feeds, private/time-sliced gold data, and successful external-provider/pilot operations remain external evidence obligations. The repository now contains verifiers and typed records for these boundaries; their presence is not release evidence by itself.

### Evidence

- [verified 2026-08-01] `uv lock --prerelease=allow` resolved the graph and `uv lock --check --prerelease=allow` passed.
- [verified 2026-08-01] `vheatm-validate --root .` passed with the standards policy and lock required.
- [verified 2026-08-01] release evidence, bundle, validator, and blocker-focused tests passed; the full suite passed with 187 tests.
- [verified 2026-08-01] `uv build --wheel --sdist` included `uv.lock`, the standards policy, and the standards schema in package assets.

### Owner

**VHEATM maintainers**

### Known Debts (PATTERN-DEBT)

PATTERN-DEBT entries introduced or affected by this change: none registered.

### Next Cycle Trigger

Start the next supply-chain ADR when a signing/key service or vulnerability evidence feed is added, or when `uv.lock` changes more than once between release-candidate builds.

### Cycle Retrospective

- The pre-release MCP extra made lock generation fail unless the resolution policy was explicit; this must remain visible in CI.
- A canonical SBOM without a canonical lock is inventory, not reproducibility evidence.
- Standards references need namespace and review semantics because current guidance can be voluntary, community, draft, or experimental.
- Lock verification improves RG-13 evidence but does not reduce the independent signing/key or CVE blockers.

## ADR-4 — Enforced reference monitor and signed qualification evidence boundaries

**Status:** ACCEPTED
**Date:** 2026-08-01
**Deciders:** VHEATM maintainers
**Tags:** `sandbox` `supply-chain` `qualification` `provider-boundary` `semantic-migration`
**Change Classification:** `DESIGN CHANGE`
**Review date:** 2026-09-01 — or earlier when a production key service, allowlisted provider, private gold vault, or kernel sandbox profile is connected.

**DECISION TYPE:** `CONSTRAINT-FORCED`
**CONFIDENCE:** `HIGH` for local contract behavior; `NOT_PRODUCTION_QUALIFIED` for host/provider operations not available in this checkout.
**LAST CONFIRMED:** 2026-08-01 — `IMPLEMENTATION`
**VOLATILITY:** `WATCHFUL` — bubblewrap/kernel capabilities, provider contracts, vulnerability feeds, and private corpus custody are external trust boundaries.

### Context

The previous local-first kernel only evaluated a `sandboxed` request flag and emitted unsigned/partial supply-chain evidence. FMEA/BRS/QBR semantics existed in legacy instructions but had no canonical executable profile. A typed record without an enforcing adapter or independent evidence could be mistaken for a completed release blocker.

### Decision

1. Execute requests cross a digest-bound bubblewrap reference monitor. The monitor uses a read-only workspace bind, isolated namespaces including mandatory network isolation, cleared environment, dropped capabilities, bounded resources, and a preflight probe. Missing broker approval, malformed scope, backend drift, or unavailable namespace support returns `blocked`; there is no host fallback.
2. Supply-chain attestations, vulnerability scans, provenance statements, private/time-sliced qualification manifests, and qualification measurements use Ed25519 signatures, content-addressed immutable identities, target binding, and explicit `unverified`/`partial`/`unknown` states. Release metrics derive from verified typed records when present and cannot be overridden by contradictory shortcut booleans.
3. External analyzer providers receive only snapshot metadata through an injected brokered transport. Policy denial, outage, identity mismatch, or invalid snapshot binding remains `blocked`/`unknown`; the adapter never opens a socket itself or promotes remote output beyond candidate epistemic status.
4. QBR, RPN, and BRS calculations load the canonical semantic profile. Detectability adjusts integrity/security risk but never blast radius; unknown SLA/regulatory inputs remain unknown rather than zero. Pilot readiness is distinct from completion, and completion requires evidence-backed observations with read-only confirmation.

### Options Considered

- Treat `sandboxed: true` as sufficient: rejected because a caller-controlled claim is not reference-monitor enforcement.
- Use an unsigned local key or mark scanner output verified on construction: rejected because custody and independent verification are separate evidence requirements.
- Send source contents to an external provider by default: rejected because unreviewed source is prohibited egress and provider output remains candidate evidence.
- Encode scoring formulas only in prose: rejected because semantic drift between FMEA/BRS/QBR consumers would be silent.

### Impact

Schemas changed: runtime policy, tool request, sandbox run, supply-chain attestation, vulnerability scan, provenance statement, qualification manifest/evidence, provider run, pilot observations, and semantic profiles.
Components changed: sandbox adapter, supply-chain verifier, qualification workflow, external provider adapter, release metric derivation, pilot lifecycle, canonical bundle, validator, and packaging.
Breaking change: **YES** for execute requests that omit a workspace path, and for repositories that omit the canonical semantic profile.
IMPACT RADIUS: **WIDE**
Cascades: `policy → broker → reference monitor → run evidence → release gates`; `private manifest → measurement evidence → RG-00…RG-15`; `FMEA/BRS → QBR → priority`.
Cascade Review: ✅ Local contract and fail-closed tests completed; production operations remain separately gated.

### Consequences

- The execute boundary now has a real enforcement seam and can honestly report host capability failure as blocked.
- Signed evidence can be independently verified and bound to the exact bundle/lock/corpus/provider target.
- Local fixtures still cannot satisfy production signing custody, private corpus access, provider qualification, CVE feed freshness, or a successful operational pilot.
- The runtime now uses `subprocess` only in the explicit sandbox adapter; the command remains exact-allowlisted and `shell=False`.

### Evidence

- [verified 2026-08-01] Sandbox, provider, qualification, semantic-profile, supply-chain, release, and pilot tests pass for the changed contracts.
- [verified 2026-08-01] In this host, bubblewrap preflight cannot create the required network namespace and therefore returns `blocked`; no fallback action is attempted.
- [verified 2026-08-01] Ed25519 tamper, target-binding, key-binding, and derived-count tests reject altered attestations/scans/manifests.
- [verified 2026-08-01] Typed release evidence overrides contradictory raw metrics and keeps RG-13 ineligible when signing/provenance/CVE evidence is incomplete.
- [verified 2026-08-01] Raw release metric objects cannot produce a passing gate; qualification and supply-chain records must verify cryptographically, and the report digest binds their content-addressed IDs.
- [verified 2026-08-01] External provider execution uses bounded HTTPS only after broker authorization, and pilot observations must resolve to completed content-addressed provider runs.
- [verified 2026-08-01] Qualification metrics are accepted only with referenced complete independent-judge verdicts, declared RG metric names, and release-specific sample floors; CLI ingest validates the typed schemas before verification.

### Owner and Known Debts

**Owner:** VHEATM maintainers

Known pattern debt: none newly opened. Release qualification debt remains: external key custody, vulnerability scanner feed, private time-sliced corpus, allowlisted provider deployment, a host with namespace enforcement, and shadow observations from an actual pilot.

### Next Cycle Trigger

Start the next cycle when any external prerequisite is available. Bind its identity/digest, add crash/isolation/replay evidence, execute RG measurements, and retain `unknown` or `blocked` on any missing observation.

## ADR-5 — Executable public seeded qualification replay

**Status:** ACCEPTED
**Date:** 2026-08-01
**Deciders:** VHEATM maintainers
**Tags:** `qualification` `determinism` `evaluation-corpus` `release-gates`
**Change Classification:** `DESIGN CHANGE`
**Review date:** 2026-09-01 — or earlier when a private gold corpus or independent qualification service is connected.
**Supersedes:** —
**Superseded by:** —

**DECISION TYPE:** `CONSTRAINT-FORCED`
**CONFIDENCE:** `HIGH` for local replay and schema/content binding; `NOT_PRODUCTION_QUALIFIED` for private and independently judged release claims.
**LAST CONFIRMED:** 2026-08-01 — `METRICS`
**VOLATILITY:** `WATCHFUL` — the seeded corpus, runner methods, and release metric definitions must remain bound to the canonical bundle.

### Context

The canonical ten-case evaluation corpus was schema-validated but had no executable path that produced replayable observations. Treating its expected labels or hand-written metric objects as qualification would leave a measurement gap and could create false RG evidence.

### Decision

Add a static-dispatch public qualification runner and `qualification-run` schema. The runner executes every canonical seeded case through real local control APIs, records content-addressed `QRL-*` output, derives only observed measurements, runs determinism at the corpus-declared 1,000 evaluations, and self-validates the typed record. Its visibility is `public_seeded` and its evidence state is permanently `unverified`; it cannot satisfy the signed private manifest, independent judge, supply-chain, or pilot gates.

### Options Considered

- Continue schema-only corpus validation: rejected because it cannot expose replay behavior or measured control outcomes.
- Convert the seeded run directly into `qualification-evidence`: rejected because public seeded cases are not private gold data and have no independent judge verdicts or signing custody.
- Dispatch case behavior through generated code or dynamic imports: rejected because canonical policy forbids model-generated execution and dynamic interpretation at the control boundary.

### Impact

Schemas changed: `qualification-run.schema.json`
Components changed: public qualification runner, validator, packaging entry points, lifecycle/ADR evidence.
Breaking change: NO

IMPACT RADIUS: **MODERATE**
Cascades: `eval corpus → static handlers → observed case results → typed measurements → replay record`; no path to GA status.
Cascade Review: ✅ Done — schema, repository validator, full tests, bundle/build checks, and tamper tests cover the changed boundary.

### Consequences

- The remaining local measurement gap is executable and repeatable: all ten seeded cases run, and the run can be independently re-hashed from its content.
- Measurements expose sample counts and conservative `confidence_lower: 0`; they are observations, not statistical qualification claims.
- The runner intentionally leaves private corpus, independent judge, signing/key custody, external provider, vulnerability, sandbox-host, and canary prerequisites unresolved.

### Evidence

- [verified 2026-08-01] `vheatm-validate --root .` passes with the new schema registered as required.
- [verified 2026-08-01] `pytest -o addopts=''` passes with 211 tests, including deterministic replay, all-case coverage, schema validation, and run tamper rejection.
- [verified 2026-08-01] `vheatm_control.qualification_runner` executes 10/10 cases and emits a `QRL-*` record with `public_seeded`/`unverified` state and 14 observed measurements; the determinism handler executes 1,000 evaluations.
- [verified 2026-08-01] Invalid corpus identity and mutated run content fail closed before the run can be treated as typed evidence.

### Owner and Known Debts (PATTERN-DEBT)

**Owner:** VHEATM maintainers

PATTERN-DEBT entries introduced or affected by this change: none registered. External release qualification debt remains intentionally open.

### Next Cycle Trigger

Start the next cycle when a private time-sliced corpus and independent judge service are available, or when the seeded runner's canonical case/method set changes; in either event rebind the bundle root and rerun all RG measurements.

### Cycle Retrospective

- Schema validation alone hid an important distinction between “corpus is well-formed” and “control behavior was observed.”
- A replay record must carry its own method and evidence references; otherwise a deterministic hash only proves serialization, not what was measured.
- Public seeded results are useful for regression and local RG diagnostics but cannot be promoted into private qualification by changing a status field.
- Running the full 1,000 determinism samples is cheap enough locally and removes an avoidable shortcut at the measurement boundary.

## ADR-6 — Fail-closed private corpus ingestion and receipt binding

**Status:** ACCEPTED
**Date:** 2026-08-01
**Deciders:** VHEATM maintainers
**Tags:** `qualification` `privacy` `time-slice` `content-addressing` `release-gates`
**Change Classification:** `DESIGN CHANGE`
**Review date:** 2026-09-01 — or earlier when the real private vault and independent qualification service are connected.
**Supersedes:** —
**Superseded by:** —

**DECISION TYPE:** `CONSTRAINT-FORCED`
**CONFIDENCE:** `HIGH` for local manifest/corpus integrity and non-disclosing receipt binding; `NOT_PRODUCTION_QUALIFIED` for private gold data or release claims.
**LAST CONFIRMED:** 2026-08-01 — `METRICS`
**VOLATILITY:** `WATCHFUL` — the private corpus contract, key custody, and vault boundary must remain bound to the canonical framework and release policy.

### Context

The release evaluator previously had typed qualification manifests and measurements but no enforcing boundary that proved the measurements came from the exact private, time-sliced corpus named by the signed manifest. A caller could otherwise provide a plausible receipt or a complete-looking qualification record without demonstrating corpus access, slice membership, or payload integrity.

### Decision

Add a schema-validated private corpus ingester that accepts only a verified Ed25519 manifest and a matching absolute local/file locator. It checks the exact framework version and `[start, end)` time slice, unique case IDs, every case payload digest, the signed digest set, the corpus digest, and the content-addressed corpus identity. It emits only a payload-free `PQR-*` receipt. `qualification-evidence` now requires the receipt ID, and the release evaluator re-verifies the receipt against the verified manifest before deriving any qualification metrics or report binding.

Opaque external locators such as `vault://` remain unavailable in this environment and fail closed; a local fixture demonstrates the verifier seam but is not private qualification evidence.

### Options Considered

- Trust a receipt's `verification_state`: rejected because status fields are untrusted claims until the receipt identity and manifest binding are verified.
- Include private case payloads in release evidence: rejected because the receipt boundary must preserve non-disclosure and minimize release-surface exposure.
- Resolve relative paths from the process working directory: rejected because ambient working-directory state is not an authoritative locator and would weaken reproducibility.

### Impact

Schemas changed: `private-qualification-corpus.schema.json`, `private-corpus-receipt.schema.json`, `qualification-evidence.schema.json`, and the release-report binding enum.
Components changed: private qualification ingester, qualification evidence builder/verifier, release evaluator, repository validator, runtime invariant checks, and contract tests.
Breaking change: YES — callers constructing qualification evidence must provide a content-addressed private-corpus receipt ID.

IMPACT RADIUS: **MODERATE**
Cascades: `signed manifest → private corpus integrity checks → non-disclosing receipt → qualification evidence → release gate/report binding`; missing external corpus access remains `unknown`/blocked.
Cascade Review: ✅ Done — schema, signature, locator, time-slice, tamper, receipt-binding, release-gate, and full-suite checks cover the changed boundary.

### Consequences

- Private corpus integrity and release binding have an executable fail-closed seam without disclosing case payloads.
- Tampering, stale slices, unavailable vault locators, missing receipts, and receipt/evidence mismatches cannot produce verified qualification metrics.
- Symlinked or relative locators are rejected, and runtime invariants use explicit exceptions instead of optimization-removable `assert` enforcement.
- A local fixture proves contract behavior only; it does not satisfy private gold data provenance, independent judging, external key custody, or RG-00…RG-15 qualification.

### Evidence

- [verified 2026-08-01] `vheatm-validate --root .` passes with both private-corpus schemas registered as required.
- [verified 2026-08-01] `PYTHONPATH=src .venv/bin/pytest -o addopts=''` passes with 216 tests, including private corpus tamper/out-of-slice/symlink rejection and release-gate receipt enforcement.
- [verified 2026-08-01] Private corpus receipts are `PQR-*`, schema-valid, content-addressed, bound to the signed manifest/corpus/time slice, and contain `payload_disclosed: false`.
- [verified 2026-08-01] Removing the receipt from otherwise signed-looking release evidence leaves RG qualification gates non-eligible rather than manufacturing metrics.

### Owner and Known Debts (PATTERN-DEBT)

**Owner:** VHEATM maintainers

PATTERN-DEBT entries introduced or affected by this change: none registered. External release qualification debt remains intentionally open: private vault/gold corpus, independent judge, key custody, provider qualification, host namespace capability, fresh vulnerability evidence, and shadow/canary observations.

### Next Cycle Trigger

Start the next cycle when the real private vault or an approved independent qualification service is available. Bind its immutable locator and key identity, ingest a time slice, run the complete RG measurement matrix, and preserve `unknown`/`blocked` for every missing external prerequisite.

### Cycle Retrospective

- A typed record is not evidence until its source boundary is verified; the receipt makes that boundary explicit without exporting private payloads.
- Absolute locators and half-open time slices remove ambient path and boundary ambiguity from local verification.
- The correct completion state is an executable verifier plus honest external blockers, not a synthetic private corpus or GA report.

## ADR-7 — Typed semantic migration overlays remain candidate-only

**Status:** ACCEPTED
**Date:** 2026-08-01
**Deciders:** VHEATM maintainers
**Tags:** `semantic-migration` `unknown-safety` `taint` `temporal` `ai-rmf`
**Change Classification:** `DESIGN CHANGE`
**Review date:** 2026-09-01 — or earlier when UX research and the external qualification prerequisites are available.
**Supersedes:** —
**Superseded by:** —

**DECISION TYPE:** `CONSTRAINT-FORCED`
**CONFIDENCE:** `HIGH` for local contract behavior; `NOT_PRODUCTION_QUALIFIED` for user-impact, standards, or external operational claims.
**LAST CONFIRMED:** 2026-08-01 — `TESTS`
**VOLATILITY:** `WATCHFUL` — legacy semantics and external evidence boundaries must remain bound to canonical schemas and policy.

### Context

The capability ledger correctly preserved unresolved legacy behavior, but several high-value migration references still had no executable contract. Marking them corrected without a typed boundary would turn prose equivalence into an authority bypass. The remaining UX-04 capability also requires real user-research evidence that is not present in this workspace.

### Decision

Add schema-validated candidate records for signal/noise decisions, FAST/Standard/Full output migration, stakeholder ownership, cross-cutting L7 obligations, strict ordered temporal snapshots with all six L4 sublayers, AI-RMF governance/model provenance, and delta-only assurance maturity mapping. These builders use canonical static maps and preserve `unknown`, missing ownership, and tainted legacy output. Every record has `authority_eligible: false`; none can manufacture a gate result, certification, maturity score, or UX claim. The ledger marks 32 of 33 legacy files corrected/owned and leaves UX-04 missing until external user research is supplied.

### Options Considered

- Mark all legacy references corrected from unit-test coverage: rejected because implementation presence is not evidence of semantic equivalence or user impact.
- Infer enterprise owners, AI governance, or temporal order from nearby fields: rejected because missing or ambiguous declarations resolve to `unknown`.
- Treat migrated legacy output as canonical report data: rejected because compatibility output remains tainted and non-authoritative.

### Impact

Schemas changed: `signal-noise-decision.schema.json`, `legacy-output-migration.schema.json`, `stakeholder-record.schema.json`, `cross-cutting-scan.schema.json`, `temporal-scan.schema.json`, `ai-rmf-overlay.schema.json`, and `assurance-maturity-delta.schema.json`.
Components changed: migration capability builders, overlay builders, capability ledger, seeded evaluation corpus/runner, validator, and package bundle.
Breaking change: YES — callers must use typed records and cannot treat migration overlays as authoritative gate or release evidence.

IMPACT RADIUS: **MODERATE**
Cascades: `legacy reference → typed candidate record → schema/ledger/eval validation`; no overlay result enters `gate plan → gate result → release report` without an independent policy-approved evidence boundary.
Cascade Review: ✅ Done — each new record is schema-validated, content-addressed, tested, and represented by a seeded case where local behavior is deterministic.

### Consequences

- Seven formerly missing semantic capabilities now have executable local contracts and evaluation coverage; UX-04 remains an honest external blocker.
- Enterprise L7.11, strict temporal ordering, AI-RMF missing governance, and assurance delta-only behavior are explicit and regression-tested.
- Public seeded migration cases improve regression coverage but remain `public_seeded`/`unverified`; they do not satisfy private gold, independent judge, provider, signing, vulnerability, sandbox-host, or pilot gates.

### Evidence

- [verified 2026-08-01] Repository validation and targeted migration/overlay/ledger/qualification tests pass after the slice.
- [verified 2026-08-01] The seeded runner dispatches all migration cases through static typed builders; no keyword or model-generated routing is used.
- [verified 2026-08-01] The capability ledger validates with exactly one remaining `missing` disposition: UX-04.

### Owner and Known Debts (PATTERN-DEBT)

**Owner:** VHEATM maintainers

PATTERN-DEBT entries introduced or affected by this change: none registered. External release qualification debt remains intentionally open: user research, private vault/gold corpus, independent judge, key custody, provider qualification, host namespace capability, fresh vulnerability evidence, and shadow/canary observations.

### Next Cycle Trigger

Start the next cycle when UX research or any external qualification prerequisite becomes available. Bind its immutable source/key identity, add the evidence record, rerun the complete RG matrix, and retain `unknown`/`blocked` for every missing prerequisite.

### Cycle Retrospective

- A migration capability is only closed when its input, output, failure semantics, and authority boundary are executable and testable.
- Overlay completeness is useful for planning, but candidate overlays must stay outside release authority until independently validated.
- The final missing capability is a data-availability blocker, not a reason to weaken the policy.

## ADR-8 — Sandbox outcomes must bind reference-monitor authorization to the executed action

**Status:** ACCEPTED
**Date:** 2026-08-01
**Deciders:** VHEATM maintainers
**Tags:** `reference-monitor` `sandbox` `tool-receipt` `fail-closed` `taint`
**Change Classification:** `SECURITY CHANGE`
**Review date:** 2026-09-01 — or earlier when host-level namespace qualification is available.
**Supersedes:** —
**Superseded by:** —

**DECISION TYPE:** `CONSTRAINT-FORCED`
**CONFIDENCE:** `HIGH` for local authorization binding; `NOT_PRODUCTION_QUALIFIED` for host capability and external operational claims.
**LAST CONFIRMED:** 2026-08-01 — `TESTS`, `VALIDATION`, `SPECIALIST REVIEW`
**VOLATILITY:** `WATCHFUL` — the host reference-monitor backend and external qualification evidence remain deployment-specific.

### Context

The sandbox record already committed the request, backend digest, controls, and outcome, but a successful or failed outcome did not prove that the reference monitor authorized that exact action. A broker callback with an incomplete or mismatched decision could therefore weaken the evidence boundary even when execution was blocked locally. This is a security-relevant gap under RG-08/RG-09 and violates the rule that tainted execution claims remain non-authoritative until explicitly bound.

### Decision

Make the sandbox boundary validate a schema-conforming policy decision before any backend action and emit a content-addressed tool receipt bound to the request, tool class, decision, and action digest. The `sandbox-run` record now carries the policy-decision digest, action digest, and receipt. `completed` and `failed` outcomes require an `allow` decision with all three bindings; `blocked` outcomes may preserve a valid deny or allow/preflight receipt, while broker failures and malformed authorization remain fail-closed with no execution claim. The receipt and decision are validated at the reference-monitor boundary rather than inferred after execution.

### Options Considered

- Trust the broker's boolean decision and reconstruct evidence later: rejected because it does not prove request/decision/action identity at the execution boundary.
- Accept any mapping returned by a test or provider broker: rejected because malformed decisions would enter the receipt path and blur `unknown` with `allow`.
- Require a receipt even when the broker itself is unavailable: rejected because pre-broker failures have no authorization event; they must remain blocked with an explicit fail-closed control.

### Impact

Schemas changed: `sandbox-run.schema.json` now requires nullable authorization fields and requires non-null authorization for completed/failed outcomes.
Components changed: `sandbox.py` reference-monitor executor and sandbox record builder; sandbox regression tests.
Breaking change: YES — direct callers that claim execution must provide a schema-valid allow decision and matching tool receipt.

IMPACT RADIUS: **HIGH**
Cascades: `policy decision → tool receipt → action digest → sandbox outcome`; no completed/failed sandbox result can enter release evidence without this binding. The host namespace capability itself is still an external qualification prerequisite and is not manufactured by this change.
Cascade Review: ✅ Done — direct builder tests, executor preflight behavior, schema validation, and global action-boundary inspection cover the changed path.

### Consequences

- Local sandbox records can distinguish an authorized action from a blocked or unavailable reference monitor without exporting command output as authority.
- Malformed broker decisions fail closed before backend launch, preserving `unknown`/`blocked` semantics.
- The change does not prove host-level namespace isolation, external key custody, provider qualification, private-corpus correctness, fresh vulnerability evidence, or shadow/canary success; those remain open blockers.

### Evidence

- [verified 2026-08-01] RED tests failed before the authorization fields/guard existed; targeted sandbox and broker verification is green at 20 passed.
- [verified 2026-08-01] Full repository verification is green at 234 passed, with repository validation and `git diff --check` clean.
- [verified 2026-08-01] Specialist STRIDE review and pattern-globalization scan found no remaining sandbox action boundary that can claim completed/failed execution without authorization binding.
- [verified 2026-08-01] Public seeded qualification remains 17/17 deterministic and `public_seeded`/`unverified`; this slice does not promote it to private or independent evidence.

### Owner and Known Debts (PATTERN-DEBT)

**Owner:** VHEATM maintainers

PATTERN-DEBT entries introduced or affected by this change: none registered. External release qualification debt remains intentionally open: host namespace capability, private vault/gold corpus, independent judge, key custody, provider qualification, fresh vulnerability evidence, shadow/canary observations, and UX research.

### Next Cycle Trigger

Start the next cycle when a qualified host reference monitor and the remaining external evidence providers are available. Bind their immutable identities and receipts, rerun RG-00…RG-15, and retain `unknown`/`blocked` for every prerequisite that is still unavailable.

### Cycle Retrospective

- A sandbox status is not execution evidence until the authorization decision and exact action are content-addressed together.
- Schema validity and semantic binding are separate controls; both are required at the reference-monitor boundary.
- Fail-closed local behavior can close a proof gap without pretending that unavailable host or external qualification exists.

## ADR-9 — Every brokered action adapter must validate the shared decision contract

**Status:** ACCEPTED
**Date:** 2026-08-01
**Deciders:** VHEATM maintainers
**Tags:** `tool-broker` `provider` `receipt` `schema-boundary` `fail-closed`
**Change Classification:** `SECURITY CHANGE`
**Review date:** 2026-09-01 — or earlier when external provider qualification is available.
**Supersedes:** —
**Superseded by:** —

**DECISION TYPE:** `CONSTRAINT-FORCED`
**CONFIDENCE:** `HIGH` for local broker/provider receipt behavior; `NOT_PRODUCTION_QUALIFIED` for external provider identity, availability, and host enforcement.
**LAST CONFIRMED:** 2026-08-01 — `TESTS`, `VALIDATION`, `SPECIALIST REVIEW`
**VOLATILITY:** `WATCHFUL` — provider policy and external transport allowlists remain deployment-specific.

### Context

The sandbox had a local semantic decision guard, but the shared receipt builder accepted a broker-like mapping without checking the canonical decision schema, request schema version, or approval binding. The external analyzer adapter could therefore accept malformed authorization and proceed to its transport, or raise an untyped exception instead of producing a blocked provider record. This violated the roadmap's single broker/receipt boundary and made RG-08/RG-09 evidence inconsistent across action adapters.

### Decision

Centralize semantic policy-decision validation in `tool_broker.validate_policy_decision` and require `build_tool_receipt` to invoke it. A non-read `allow` decision must carry a valid approval-token identity; every decision must bind schema version, request ID, decision value, reason, controls, and timestamp. The sandbox reuses this guard. Provider runs validate the original network request, receipt identity, request/action digests, and allow status before a completed outcome; authorization failures return a typed `blocked` run with a null receipt, never a transport call or fabricated authorization event. The tool-request schema now requires `schema_version`.

### Options Considered

- Keep per-adapter decision checks: rejected because drift already existed between sandbox and provider boundaries.
- Treat a malformed provider decision as provider outage after sending the request: rejected because authorization failure must precede transport and must not be conflated with remote outage.
- Invent a deny receipt when the broker returned no valid decision: rejected because a receipt is evidence of an observed authorization event; pre-authorization failure is represented as a null receipt and blocked status.

### Impact

Schemas changed: `tool-request.schema.json` requires canonical versioning; `provider-run.schema.json` permits null receipts only for blocked/unknown authorization paths and requires an allowed object receipt for completed runs.
Components changed: shared tool broker receipt guard, sandbox adapter, external provider adapter, and provider/pilot contract fixtures.
Breaking change: YES — custom broker callbacks must return the complete canonical decision shape, and completed provider runs must include a content-valid network receipt.

IMPACT RADIUS: **HIGH**
Cascades: `broker decision → shared semantic guard → content-addressed receipt → adapter action`; all current receipt-producing action boundaries now share the same guard. External provider qualification remains an independent prerequisite.
Cascade Review: ✅ Done — broker, sandbox, analyzer, provider, pilot, schema, and malformed-callback tests were inspected and exercised.

### Consequences

- A malformed or incomplete broker callback cannot authorize provider transport or sandbox execution.
- Provider authorization outages are distinguishable from remote provider outages and preserve `blocked`/`unknown` semantics without false evidence.
- The legacy `policy.py` implementation remains a separate authority surface and is now an explicitly tracked next blocker for migration to the canonical broker.

### Evidence

- [verified 2026-08-01] RED tests failed for missing tool-request schema version and malformed provider decision before the shared guard and nullable blocked receipt existed.
- [verified 2026-08-01] Targeted broker/sandbox/provider/analyzer/pilot verification passed at 32 tests; full repository verification passed at 236 tests.
- [verified 2026-08-01] Repository validation passed; malformed provider authorization did not call transport and emitted schema-valid blocked evidence.

### Owner and Known Debts (PATTERN-DEBT)

**Owner:** VHEATM maintainers

PATTERN-DEBT entries introduced or affected by this change: none registered. Next local debt is removal or non-authoritative migration of the legacy `src/vheatm_control/policy.py` authority surface. External debt remains provider qualification, private corpus/judge, key custody, vulnerability feed, host namespace capability, shadow/canary observations, and UX research.

### Next Cycle Trigger

Start the next cycle by routing all remaining policy callers through `ToolBroker`, preserving legacy API material only as an explicit non-authoritative compatibility/migration surface. Then rerun the full RG-00…RG-15 contract suite and retain external blockers as `unknown`/`blocked`.

### Cycle Retrospective

- A shared receipt helper is a real trust boundary only when it validates the decision semantics, not just request ID and allow/deny.
- Authorization failure must have a typed outcome that cannot be confused with a provider outage or a valid deny receipt.
- Globalizing the guard across sandbox and provider adapters exposed the duplicate legacy policy authority as the next architectural blocker.

## ADR-10 — Retire the duplicate policy engine from the runtime authority path

**Status:** ACCEPTED
**Date:** 2026-08-01
**Deciders:** VHEATM maintainers
**Tags:** `policy-authority` `tool-broker` `migration` `single-source-of-truth`
**Change Classification:** `ARCHITECTURE CHANGE`
**Review date:** 2026-09-01 — or earlier when a compatibility consumer requires a reviewed adapter.
**Supersedes:** —
**Superseded by:** —

**DECISION TYPE:** `CONSTRAINT-FORCED`
**CONFIDENCE:** `HIGH` for runtime authority consolidation; `WATCHFUL` for downstream callers of the retired API.
**LAST CONFIRMED:** 2026-08-01 — `TESTS`, `VALIDATION`, `SPECIALIST REVIEW`
**VOLATILITY:** `WATCHFUL` — external integrations may still need an explicit reviewed adapter.

### Context

The approved roadmap requires one policy authority, but `src/vheatm_control/policy.py` still contained an independent `PolicyEngine`, approval verifier, ledger, and guarded executor alongside `tool_broker.ToolBroker`. Even though current runtime adapters used the broker, the legacy module remained importable and could produce decisions with different request/scope/approval semantics. That is an authority-split blocker and makes a passing test suite insufficient evidence of policy consistency.

### Decision

Make `ToolBroker` the only runtime policy implementation. Replace `src/vheatm_control/policy.py` with a compatibility export surface for the canonical broker and explicit retired-name errors; move the former implementation to `docs/migration/legacy-policy.py.txt` as non-authoritative provenance material. Migrate contract tests to instantiate the canonical broker and validate its decision/schema directly. No runtime module may import or execute the archived policy implementation.

### Options Considered

- Keep both engines and document that callers should prefer the broker: rejected because importability itself preserves an authority fork and future callers can select the weaker path.
- Delete the legacy module and archive: rejected because migration comparison and downstream diagnosis need the historical material preserved outside runtime packaging.
- Make `ToolBroker` silently emulate every old API: rejected because it would preserve ambiguous semantics and hide the required migration boundary.

### Impact

Runtime changed: `src/vheatm_control/policy.py` is now a canonical broker shim; the old implementation is outside the runtime package under `docs/migration`.
Tests changed: policy and contract tests now exercise `ToolBroker`, token receipts, and explicit retired API behavior.
Breaking change: YES — imports of `PolicyEngine`, `ApprovalVerifier`, `GuardedExecutor`, and related legacy names must migrate to `ToolBroker`/sandbox APIs.

IMPACT RADIUS: **HIGH**
Cascades: `policy authority → approval decision → action receipt → sandbox/provider enforcement`; the runtime now has one implementation and one semantic decision contract.
Cascade Review: ✅ Done — source import scan, package/runtime path inspection, schema validation, and full tests cover the migration boundary.

### Consequences

- Future policy changes have one implementation, one schema boundary, and one receipt contract to review.
- Legacy behavior remains available for provenance comparison but cannot be imported as runtime authority or enter the canonical bundle through the Python package.
- Downstream callers using the retired API will fail explicitly and must migrate; this is intentional rather than silently adapting divergent semantics.

### Evidence

- [verified 2026-08-01] Runtime/source scan finds no non-test imports of `PolicyEngine`, `ApprovalVerifier`, `GuardedExecutor`, or `sign_approval_token` outside the archived migration text.
- [verified 2026-08-01] Policy/contract tests pass against `ToolBroker`; full repository verification passes at 231 tests and repository validation passes.
- [verified 2026-08-01] The archived implementation is `.txt` migration material and the shim exposes canonical broker symbols only.

### Owner and Known Debts (PATTERN-DEBT)

**Owner:** VHEATM maintainers

PATTERN-DEBT entries introduced or affected by this change: none registered. Remaining local work is independent RG measurement breadth and real qualification evidence; external debt remains private corpus/judge, key custody, vulnerability feed, provider qualification, host namespace capability, shadow/canary observations, and UX research.

### Next Cycle Trigger

Start the next cycle by expanding independent RG-00…RG-15 measurement coverage and auditing every release/pilot claim against verified evidence, while retaining `unknown`/`blocked` for unavailable external prerequisites.

### Cycle Retrospective

- A compatibility module is safe only when it cannot create a second authority decision.
- Archiving legacy code as non-runtime text preserves provenance without preserving an executable bypass.
- Removing duplicate policy tests reduces count but improves evidence quality because the remaining tests exercise the canonical authority.

## ADR-11 — Enforce typed evidence schemas at every evaluator entry point

**Status:** ✅ ACCEPTED
**Date:** 2026-08-01
**Deciders:** VHEATM maintainers
**Tags:** `release-gates` `schema-boundary` `qualification` `supply-chain`
**Change Classification:** `IMPLEMENTATION BUG`
**Review date:** 2026-09-01 — or earlier when a new typed release-evidence document or external evidence ingestion path is introduced.
**Supersedes:** —
**Superseded by:** —

**DECISION TYPE:** `CONSTRAINT-FORCED`
**CONFIDENCE:** `HIGH` for local fail-closed behavior; `NOT_PRODUCTION_QUALIFIED` for external evidence custody and independent release operations.
**LAST CONFIRMED:** 2026-08-01 — `TESTS`, `VALIDATION`, `PACKAGE BUILD`
**VOLATILITY:** `WATCHFUL` — typed evidence schemas and external release feeds can evolve, but schema and signature checks must remain coupled.

### Context

The release CLI validated typed evidence schemas before invoking the evaluator, but callers of the direct `evaluate_release_gates()` and `derive_verified_evidence_metrics()` APIs bypassed that boundary. Cryptographic identity and signature verification alone did not reject a signed document with an undeclared field, and the schema validators did not enforce declared date-time formats. This allowed schema-invalid signed material to be treated as verified release evidence by an in-process caller.

### Decision

Centralize typed evidence schema validation in the evaluation module and invoke it before any cryptographic verifier at every evaluator entry point. Validate qualification manifest, private corpus receipt, qualification evidence, supply-chain attestation, vulnerability scan, provenance statement, and independent judge verdict records with the canonical JSON Schemas and `FormatChecker`. Qualification schema errors discard all qualification metrics and leave affected gates `unknown`; supply-chain schema errors inject only explicit blocking values so RG-13 cannot pass. The CLI uses the same helper, raw caller metrics remain ignored, and malformed evidence never becomes production GA evidence.

### Options Considered

- Rely on the CLI preflight: rejected because Python API callers would retain a weaker trust boundary.
- Extend each cryptographic verifier with ad-hoc schema checks: rejected because schema coverage would diverge across document types and entry points.
- Raise an exception for every malformed supply record: rejected because the release report contract must remain typed and fail-closed rather than disappear at the API boundary.

### Impact

Schemas changed: none; existing canonical qualification, judge, supply-chain, vulnerability, provenance, and release-report schemas are now enforced consistently.
Components changed: `evaluation.py`, release-evidence regression fixtures/tests, lifecycle verification record.
Breaking change: **YES** for direct evaluator callers that previously supplied signed but schema-invalid documents.

IMPACT RADIUS: **MODERATE**
Cascades: `typed evidence → schema boundary → cryptographic verification → RG-00…RG-15 metrics → release report`.
Cascade Review: ✅ Done — targeted RED/GREEN, release-evidence regression suite, full suite, repository validation, evaluate/route, public replay, bundle, lock, and package build all passed.

### Consequences

- Direct and CLI evaluator paths now share one schema and format-validation boundary.
- A valid signature cannot promote undeclared, malformed, or format-invalid fields into release metrics.
- Existing local mechanism fixtures must themselves be schema-valid; this does not change their status into independent or production qualification.
- External key custody, private/time-sliced gold data, independent judging, vulnerability feed, provider qualification, host namespace capability, shadow/canary observation, and UX research remain open blockers.

### Evidence

- [verified 2026-08-01] RED test demonstrated that a signed qualification document with an extra field incorrectly produced `ga_eligible=True`; the regression now blocks it and leaves qualification gates unknown.
- [verified 2026-08-01] `.venv/bin/vheatm-validate --root .` passed and `.venv/bin/pytest -q -o addopts=''` passed with 231 tests.
- [verified 2026-08-01] Low-risk evaluate/route completed with 15 selected, 7 unselected, and 0 unresolved modules; public replay completed 17/17 with `public_seeded`/`unverified` state.
- [verified 2026-08-01] `uv lock --check --prerelease=allow`, `uv build --wheel --sdist`, bundle generation, and `git diff --check` passed.

### Owner

**VHEATM maintainers**

### Known Debts (PATTERN-DEBT)

PATTERN-DEBT entries introduced or affected by this change: none registered. External release evidence remains unavailable and must stay `unknown`/`blocked` until supplied through the verified boundary.

### Next Cycle Trigger

Start the next cycle when a new typed release-evidence schema/field is added or an external qualification/supply-chain feed is connected; add its boundary regression and rerun the complete RG-00…RG-15 suite before accepting any new metric.

### Cycle Retrospective

- A signature proves authorship and content integrity, not conformance to the canonical document contract.
- CLI-only validation is not a trust boundary when the library exposes a direct evaluator API.
- Schema-invalid local fixtures surfaced immediately once the direct boundary used the same uppercase content-addressed ID rules as the canonical schemas.
- Fail-closed reports are more useful than exceptions for malformed supply evidence because they preserve explicit RG-13 failure semantics.

## ADR-12 — Bind critical qualification trials to private corpus populations

**Status:** ✅ ACCEPTED
**Date:** 2026-08-01
**Deciders:** VHEATM maintainers
**Tags:** `qualification` `private-corpus` `release-gates` `measurement-integrity`
**Change Classification:** `IMPLEMENTATION BUG`
**Review date:** 2026-09-01 — or earlier when a new critical metric, sample basis, or private qualification feed is introduced.
**Supersedes:** —
**Superseded by:** —

**DECISION TYPE:** `CONSTRAINT-FORCED`
**CONFIDENCE:** `HIGH` for local population-binding behavior; `NOT_PRODUCTION_QUALIFIED` for the statistical validity and provenance of unavailable external gold data.
**LAST CONFIRMED:** 2026-08-01 — `TESTS`, `VALIDATION`, `REPLAY`
**VOLATILITY:** `WATCHFUL` — metric populations and preregistered statistical methods must remain explicit as RG definitions evolve.

### Context

The signed qualification evidence schema carried a `sample_count`, but the evaluator trusted that number without checking what population the samples represented. A one-case private receipt could therefore carry a signed claim of 300 critical recall, ASR, or unsafe-action trials and satisfy the release sample floor. A signature and content-addressed identity preserve integrity of the claim; they do not prove population coverage.

### Decision

Add canonical `sample_basis` semantics to every qualification measurement. Determinism uses `repeated_evaluation`; critical recall, critical miss count, critical-family ASR, and critical unsafe-action metrics use `private_case_trials`; other measurements use `private_corpus_observation`. The evaluator requires every measurement to use its canonical basis, reference the verified private receipt, and, for private-case metrics, have `sample_count` no greater than the receipt's verified `case_count`. Known bounded rates/CI values must remain in `[0, 1]`, counts/timings must remain non-negative, integer metrics must remain integer counts, and confidence lower bounds must remain in `[0, 1]`. Violations discard all qualification metrics and leave affected gates `unknown`. This binds population coverage without claiming that a local fixture or receipt proves independence, statistical method correctness, or production qualification.

### Options Considered

- Trust signed `sample_count` as sufficient: rejected because signed self-assertion does not establish the sampled population.
- Require every metric to equal private `case_count`: rejected because determinism and performance metrics legitimately use repeated evaluations rather than distinct private cases.
- Use public seeded replay to fill private population gaps: rejected because public replay remains `public_seeded`/`unverified` and cannot satisfy private gold evidence.

### Impact

Schemas changed: `qualification-evidence.schema.json` adds required `sample_basis` and bounds `confidence_lower` to `[0, 1]`.
Components changed: qualification builder/verifier, release evaluator, private-corpus binding, release-evidence fixtures/tests, lifecycle record.
Breaking change: **YES** for qualification evidence that omits sample population semantics or overstates critical private-case coverage.

IMPACT RADIUS: **WIDE**
Cascades: `private receipt.case_count → measurement.sample_basis/sample_count → verified qualification metrics → RG-00…RG-15`.
Cascade Review: ✅ Done — RED/GREEN oversize-claim test, full suite, validator, package/schema boundary, and seeded replay checks cover the changed path.

### Consequences

- A small private corpus can no longer satisfy a large critical trial floor by declaration alone.
- The measurement contract makes repeated-evaluation versus private-case populations visible and reviewable.
- The check is population binding, not an independent statistical qualification; external gold provenance, judge independence, and preregistered CI computation remain required.
- Existing local mechanism fixtures now use 300 private cases for critical release metrics and remain test fixtures, not production evidence.

### Evidence

- [verified 2026-08-01] RED test showed a one-case receipt with signed 300-trial critical metrics could pass RG-05; the corrected evaluator returns `unknown` with a population-binding diagnostic.
- [verified 2026-08-01] RED test showed signed `critical_recall_lower_ci=2.0` could pass RG-05; the corrected qualification verifier rejects out-of-domain metric values before derivation.
- [verified 2026-08-01] `.venv/bin/vheatm-validate --root .` passed and `.venv/bin/pytest -q -o addopts=''` passed with 232 tests.
- [verified 2026-08-01] Qualification, private receipt, release-gate, and schema contract tests pass; public seeded replay remains explicitly `public_seeded`/`unverified`.

### Owner

**VHEATM maintainers**

### Known Debts (PATTERN-DEBT)

PATTERN-DEBT entries introduced or affected by this change: none registered. Remaining qualification debt is external private gold provenance, independent adjudication, statistical CI computation, signing custody, and operational pilot evidence.

### Next Cycle Trigger

Start the next cycle when a new critical RG metric/sample basis is added or an external private qualification feed is connected; require its population rule, boundary regression, and complete RG-00…RG-15 verification before accepting metrics.

### Cycle Retrospective

- A signed sample count is still only a claim until its population is bound to an immutable receipt.
- Different metrics need different population semantics; applying one corpus-count rule to determinism would be incorrect.
- Threshold predicates do not define physical metric domains; bounded rates/CI and non-negative count/timing rules must be frozen separately.
- The smallest useful regression is a one-case receipt with an oversized critical claim because it directly exercises the false-assurance path.
- Population binding narrows the blocker but deliberately does not pretend to prove independent sampling or confidence-interval correctness.
