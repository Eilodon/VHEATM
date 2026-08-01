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

## ADR-13 — Bind qualification evidence to blind judge packets and exact case coverage

**Status:** ✅ ACCEPTED
**Date:** 2026-08-01
**Deciders:** VHEATM maintainers
**Tags:** `qualification` `independent-judge` `private-corpus` `release-gates`
**Change Classification:** `IMPLEMENTATION BUG`
**Review date:** 2026-09-01 — or earlier when the external judge service, packet schema, or private-case sampling contract changes.
**Supersedes:** —
**Superseded by:** —

**DECISION TYPE:** `CONSTRAINT-FORCED`
**CONFIDENCE:** `HIGH` for local packet/evidence binding; `NOT_PRODUCTION_QUALIFIED` for unavailable external judge independence, custody, and statistical adjudication.
**LAST CONFIRMED:** 2026-08-01 — `TESTS`, `VALIDATION`, `REPLAY`
**VOLATILITY:** `WATCHFUL` — provider/model isolation, packet ordering, and private sampling must remain explicit as qualification contracts evolve.

### Context

The release evaluator required a signed, content-addressed judge verdict, but the verdict could be supplied without its corresponding blind packet. Even when a packet sidecar was present, a signed verdict could be reconstructed with a different `config_digest` or with decision item IDs that were not the packet's private cases. A receipt population count alone therefore did not prove that the critical cases used by RG-05/RG-08 had actually been independently judged.

### Decision

Treat the blind packet as a first-class typed release-evidence record. Validate every supplied packet against `judge-packet.schema.json` and its content identity; include packet IDs in release-report evidence bindings. For every verdict referenced by qualification evidence, require the referenced packet, validate the verdict identity, bind request/provider/model/config/order fields exactly, and require decision item IDs to cover the packet items in the packet's randomized order. For critical metrics whose canonical basis is `private_case_trials`, count only decision IDs that intersect the verified private receipt's case references; if that independently judged coverage is below `sample_count`, discard all qualification metrics and leave affected gates `unknown`.

### Options Considered

- Trust verdict IDs without packets: rejected because a content-addressed verdict does not prove what was shown to the judge.
- Infer judge coverage from the private receipt `case_count`: rejected because population availability is not adjudication evidence.
- Accept arbitrary verdict decision IDs: rejected because a signed verdict could claim private cases that were not in the blind packet.
- Use public seeded replay as the independent judge: rejected because replay is deterministic local evidence, not independent provider/model/context separation or private gold qualification.

### Impact

Schemas changed: `release-gate-report.schema.json` recognizes `independent_judge_packet` evidence bindings; the existing canonical `judge-packet.schema.json` is now enforced at release-evidence ingestion.
Components changed: judge binding API, release evaluator, release-report binding derivation, judge/release regression fixtures and tests, lifecycle record.
Breaking change: **YES** for release evidence that omits packet sidecars, mismatches packet/verdict identity, or claims more critical private trials than the packet actually covers.

IMPACT RADIUS: **WIDE**
Cascades: `blind packet → verdict identity/binding → private case coverage → verified qualification metrics → RG-05/RG-08 → release report evidence bindings`.
Cascade Review: ✅ Done — targeted packet binding and partial-coverage regressions, full suite, validator, seeded replay, bundle, lock, and package-build checks are required before integration.

### Consequences

- A judge verdict cannot become qualification evidence merely because its signature/content ID is valid; the packet and exact item coverage are part of the trust boundary.
- Local fixtures must construct packets over the same private receipt case IDs used by critical measurements.
- The implementation proves local fail-closed binding only; it does not create private gold data, external provider qualification, independent judge custody, valid confidence intervals, or production release evidence.
- Missing external judge service and private corpus evidence remain `unknown`/blocked, never synthetic `complete`.

### Evidence

- [verified 2026-08-01] RED regression with an empty packet sidecar leaves RG-05 `unknown` even when the signed verdict is present.
- [verified 2026-08-01] RED regression with one independently judged case and a 300-case critical claim leaves RG-05 `unknown` with a private-case coverage diagnostic.
- [verified 2026-08-01] RED regression with a re-signed verdict whose `config_digest` differs from its packet leaves RG-05 `unknown`.
- [verified 2026-08-01] Verdict binding regression rejects decision IDs that do not exactly cover packet items in randomized order.

### Owner

**VHEATM maintainers**

### Known Debts (PATTERN-DEBT)

PATTERN-DEBT entries introduced or affected by this change: none registered. External independent judge, private gold corpus, key custody, statistical method validation, provider qualification, fresh vulnerability evidence, host namespace capability, and shadow/canary evidence remain open.

### Next Cycle Trigger

Start the next cycle when the external judge adapter or private qualification feed is connected, or when packet/verdict schemas gain a new identity-bearing field; add its binding regression and rerun the complete RG-00…RG-15 contract suite.

### Cycle Retrospective

- A verdict's content identity answers “which verdict,” not “what context and cases were judged.”
- Packet sidecars must be included in the report's immutable evidence binding set or they can disappear from downstream provenance.
- Exact packet-item coverage is the smallest reliable local proof that critical private-case counts correspond to independently adjudicated cases.
- This closes a local evidence-integrity gap without pretending that a synthetic fixture is an external qualification result.

## ADR-14 — Re-verify provider authorization chains before pilot completion

**Status:** ✅ ACCEPTED
**Date:** 2026-08-01
**Deciders:** VHEATM maintainers
**Tags:** `pilot` `external-provider` `reference-monitor` `release-gates`
**Change Classification:** `IMPLEMENTATION BUG`
**Review date:** 2026-09-01 — or earlier when provider-run or network-receipt schemas change.
**Supersedes:** —
**Superseded by:** —

**DECISION TYPE:** `CONSTRAINT-FORCED`
**CONFIDENCE:** `HIGH` for local receipt-chain re-verification; `NOT_PRODUCTION_QUALIFIED` for external provider allowlisting and operational pilot evidence.
**LAST CONFIRMED:** 2026-08-01 — `TESTS`, `VALIDATION`, `PACKAGE BUILD`
**VOLATILITY:** `WATCHFUL` — provider request fields, broker controls, and pilot observation contracts are trust-boundary inputs.

### Context

`complete_pilot()` checked a provider run's content ID, completed status, response object, and `network_receipt.decision == allow`. Because the provider run ID is content-addressed, a caller could alter the embedded receipt action digest and recompute the run ID; pilot completion then accepted a record whose receipt no longer matched the brokered network request. The provider builder performed the stronger request/receipt checks, but persisted pilot inputs were not re-verified at the later boundary.

### Decision

Persist the canonical redacted network request inside every provider run. Centralize network-request and receipt-chain checks in `verify_provider_run()`: validate the HTTPS/redacted network request, receipt identity, request/action digests, reconstructed broker decision semantics, status/epistemic state, response digest, and completed-response requirement. `complete_pilot()` must call this verifier before accepting any provider run; a malformed or rebound receipt remains a typed pilot error and cannot become completed shadow/canary evidence.

### Options Considered

- Trust the provider-run content ID: rejected because an attacker can re-content-address a tampered record.
- Recheck only `decision == allow`: rejected because allow is not bound to destination, request digest, or action digest.
- Reuse only builder-time validation: rejected because pilot consumes persisted/untrusted records at a later boundary.
- Accept a completed run without the redacted network request: rejected because the receipt's digests cannot be independently recomputed against the authorized action.

### Impact

Schemas changed: `provider-run.schema.json` now requires the redacted canonical network request.
Components changed: provider-run builder/verifier, pilot completion boundary, provider-run schema, pilot regression fixture, lifecycle record.
Breaking change: **YES** for persisted provider runs that omit the network request or cannot reproduce their receipt authorization chain.

IMPACT RADIUS: **WIDE**
Cascades: `network request → broker decision → tool receipt → provider run → pilot observation → shadow/canary completion`.
Cascade Review: ✅ Done — RED tampered-receipt regression, targeted provider/pilot tests, full suite, validator, bundle, lock, and package build cover the changed chain.

### Consequences

- Pilot completion no longer promotes a self-rehashed provider record into evidence without rechecking the authorization chain.
- Provider runs remain metadata-only; the persisted request contains no source payload, only the approved network metadata and redaction declaration.
- Local verification still does not qualify an external provider, prove host enforcement, or create a successful operational pilot; those external facts remain unavailable and fail-closed.

### Evidence

- [verified 2026-08-01] RED regression showed a tampered `action_digest` with a recomputed `PRV-*` ID was accepted by the old pilot boundary.
- [verified 2026-08-01] GREEN targeted provider/pilot tests passed after `verify_provider_run()` was required by completion.
- [verified 2026-08-01] Full repository verification remains required before integration; no pilot `complete` claim is minted for unavailable external evidence.

### Owner

**VHEATM maintainers**

### Known Debts (PATTERN-DEBT)

PATTERN-DEBT entries introduced or affected by this change: none registered. External provider allowlisting, key custody, fresh vulnerability evidence, host namespace capability, private qualification, independent judging, and successful shadow/canary observation remain open.

### Next Cycle Trigger

Start the next cycle when an external provider-run feed or operational pilot store is connected, or when the provider/network schemas gain a new identity-bearing field; add its persisted-record regression and rerun RG-00…RG-15 checks.

### Cycle Retrospective

- Content-addressing detects accidental mutation but does not establish that the content was authorized.
- Every persisted execution record needs a later semantic re-verification boundary, not only a builder-time check.
- Storing only redacted network metadata gives the pilot verifier enough material to recompute authorization without leaking source payloads.

## ADR-15 — Re-evaluate signed release evidence before enabling canary

**Status:** ✅ ACCEPTED
**Date:** 2026-08-01
**Deciders:** VHEATM maintainers
**Tags:** `pilot` `release-gates` `supply-chain` `qualification`
**Change Classification:** `IMPLEMENTATION BUG`
**Review date:** 2026-09-01 — or earlier when release-report evidence inputs or pilot authorization changes.
**Supersedes:** —
**Superseded by:** —

**DECISION TYPE:** `CONSTRAINT-FORCED`
**CONFIDENCE:** `HIGH` for local canary fail-closed behavior; `NOT_PRODUCTION_QUALIFIED` for unavailable external evidence and operational rollout.
**LAST CONFIRMED:** 2026-08-01 — `TESTS`, `VALIDATION`, `REPLAY`
**VOLATILITY:** `WATCHFUL` — release evidence keys, bundle roots, and RG-00…RG-15 contracts are release-bound inputs.

### Context

`prepare_pilot(profile="canary")` previously trusted a self-consistent `release_report`: a caller could replace every gate with `pass`, add a plausible evidence binding, recompute `report_id`, and satisfy the canary readiness checks without supplying or re-verifying the qualification and supply-chain records that generated those claims. A content-addressed report proves internal consistency, not evidence provenance.

### Decision

Canary preparation must receive the original typed `release_evidence`, verification public keys/key IDs, and the expected current bundle root. It re-runs `evaluate_release_gates()` using the report framework version and evaluation timestamp, then requires byte-for-byte semantic equality with the supplied report. Missing keys/evidence, invalid signatures, stale bundle binding, or any gate/report mismatch fail closed. Shadow preparation remains available as read-only readiness but cannot be upgraded to canary without this re-verification input.

### Options Considered

- Trust `report_id` and `ga_eligible`: rejected because both are recomputable from caller-controlled content.
- Trust evidence binding IDs without loading evidence: rejected because IDs do not verify signatures, schemas, freshness, or bundle binding.
- Add a boolean `verified` flag to the report: rejected because a self-declared flag is not authority.
- Re-evaluate only after canary starts: rejected because tool-enabled rollout must be authorized before activation.

### Impact

Schemas changed: none; the existing release-report and typed evidence contracts are now required at the canary preparation boundary.
Components changed: pilot preparation API, pilot regression test, lifecycle record.
Breaking change: **YES** for callers that request canary without the evidence/key/bundle inputs required for independent re-evaluation.

IMPACT RADIUS: **WIDE**
Cascades: `typed release evidence → evaluator verification → RG-00…RG-15 report → canary authorization`.
Cascade Review: ✅ Done — RED self-declared all-pass report, GREEN canary rejection, shadow compatibility tests, full suite, validator, replay, bundle, lock, and build checks cover the path.

### Consequences

- A canary-ready record can no longer be minted from a forged report alone.
- External qualification remains external: this boundary verifies supplied evidence but does not manufacture private gold, key custody, provider allowlisting, or successful live observations.
- Shadow remains read-only and may be prepared with incomplete evidence, but its status cannot be promoted to canary without re-evaluation.

### Evidence

- [verified 2026-08-01] RED regression showed a self-declared 16-pass report with recomputed identity and fake evidence binding could reach the old canary path.
- [verified 2026-08-01] GREEN regression now requires re-evaluation inputs and rejects that forged report; existing shadow and failed-canary tests remain green.

### Owner

**VHEATM maintainers**

### Known Debts (PATTERN-DEBT)

PATTERN-DEBT entries introduced or affected by this change: none registered. External key custody, private/time-sliced qualification, allowlisted provider qualification, fresh vulnerability scan, host namespace capability, and successful shadow/canary observation remain open.

### Next Cycle Trigger

Start the next cycle when a real release-evidence store or canary controller is connected; bind its authorization record to the same evaluator output and rerun the complete RG-00…RG-15 suite.

### Cycle Retrospective

- A report's content ID is an integrity check, not an attestation of its inputs.
- Tool-enabled rollout needs an evidence re-verification boundary before activation, not merely a readiness check after claims are assembled.
- Reusing the canonical evaluator keeps canary policy aligned with release policy and avoids a second gate authority.

## ADR-16 — Enforce canonical release-report identity at evaluator and pilot boundaries

**Status:** ✅ ACCEPTED
**Date:** 2026-08-01
**Deciders:** VHEATM maintainers
**Tags:** `release-gates` `pilot` `content-addressing` `schema-validation`
**Change Classification:** `IMPLEMENTATION BUG`
**Review date:** 2026-09-01 — re-evaluate when the release-report schema or identity fields change.
**Supersedes:** —
**Superseded by:** —

**DECISION TYPE:** `CONSTRAINT-FORCED`
**CONFIDENCE:** `HIGH` for local report-integrity enforcement; `NOT_PRODUCTION_QUALIFIED` for external release evidence and rollout.
**LAST CONFIRMED:** 2026-08-01 — `IMPLEMENTATION`, `REVIEW`, `TESTS`
**VOLATILITY:** `WATCHFUL` — report identity fields, gate inventory, and canonical schemas are release-bound inputs.

### Context

The release evaluator validated typed input evidence but did not validate its own emitted report at the boundary. Pilot preparation separately trusted a report whose ID was internally consistent, even when required fields were missing or gate IDs were duplicated. The report ID also omitted `schema_version` and `evaluated_at`, allowing different report contents to share one identity. Duplicate evidence records could make the generated report violate its own `uniqueItems` contract instead of returning the intended typed unknown state.

### Decision

Add one shared `validate_release_report()` boundary. It validates the canonical release-report schema and date-time formats, checks the report ID against all identity-bearing fields including schema version and evaluation timestamp, requires exactly the ordered RG-00…RG-15 set, and derives the summary from gate statuses. Every evaluator output and every shadow/canary preparation input passes this guard. Evidence binding derivation is set-like and deterministic, so duplicate input IDs remain visible to qualification verification without producing an invalid report envelope.

### Options Considered

- Trust the report ID and `ga_eligible`: rejected because both can be recomputed from malformed caller content.
- Validate only canary reports: rejected because shadow reports and direct evaluator callers are still persisted evidence inputs.
- Relax `uniqueItems` in the report schema: rejected because duplicate evidence IDs obscure provenance and weaken the typed contract.
- Keep evaluation time outside report identity: rejected because an immutable report must distinguish otherwise identical evaluations at different times.

### Impact

Schemas changed: none; existing `release-gate-report.schema.json` is now enforced at all report acceptance paths.
Components changed: release evaluator, report identity derivation, pilot preparation, release-evidence and pilot regressions.
Breaking change: **YES** for malformed, duplicate-gate, non-RFC-3339, or stale-content release reports.

IMPACT RADIUS:
BLAST RADIUS: WIDE
Cascades: `typed evidence → RG-00…RG-15 evaluator → canonical release report → shadow/canary preparation`.
Cascade Review: ✅ Done — evaluator, CLI output, shadow, canary, duplicate-evidence, identity, and schema paths were searched and tested.

### Consequences

- A report cannot enter pilot state unless its schema, gate inventory, derived summary, timestamp, and identity agree.
- Re-evaluation at a different timestamp creates a distinct report ID, making persisted pilot provenance unambiguous.
- Duplicate packet IDs still produce a typed unknown qualification result rather than an invalid report or a passing shortcut.
- External signing, private corpus, vulnerability feed, provider qualification, host namespace, and operational canary evidence remain unavailable and fail-closed.

### Evidence

- [verified 2026-08-01] RED evaluator regression showed a non-RFC-3339 timestamp was accepted before the shared validator.
- [verified 2026-08-01] RED pilot regression showed a schema-invalid shadow report was accepted before the shared validator.
- [verified 2026-08-01] RED identity regression showed reports at different evaluation timestamps shared one report ID.
- [verified 2026-08-01] GREEN release/pilot contract suite passes with duplicate packet evidence remaining `unknown` and malformed reports rejected.

### Owner

**VHEATM maintainers**

### Known Debts (PATTERN-DEBT)

PATTERN-DEBT entries introduced or affected by this change: none registered. External release qualification and operational pilot evidence remain open.

### Next Cycle Trigger

Start the next cycle when the release-report schema adds an identity-bearing field or a live evidence store supplies a persisted report; add the field/store binding regression before accepting the new report shape.

### Cycle Retrospective

- A content-addressed ID is only as strong as the fields included in its identity projection.
- Generated outputs need the same schema boundary as untrusted inputs; otherwise strict schemas can fail inside the producer.
- Set-like evidence bindings preserve a valid report envelope, while the verifier still decides whether duplicate source records are acceptable.

## ADR-17 — Bind semantic scoring to the validated canonical profile

**Status:** ✅ ACCEPTED
**Date:** 2026-08-01
**Deciders:** VHEATM maintainers
**Tags:** `semantic-profile` `rpn` `fmea` `qbr` `brs` `fail-closed`
**Change Classification:** `IMPLEMENTATION BUG`
**Review date:** 2026-09-01 — or earlier when the semantic-profile schema, formulas, or manifest version changes.
**Supersedes:** —
**Superseded by:** —

**DECISION TYPE:** `CONSTRAINT-FORCED`
**CONFIDENCE:** `HIGH` for local canonical-profile binding; `NOT_PRODUCTION_QUALIFIED` for external qualification and operational rollout.
**LAST CONFIRMED:** 2026-08-01 — `IMPLEMENTATION`, `REVIEW`, `TESTS`, `VALIDATION`
**VOLATILITY:** `WATCHFUL` — semantic thresholds and mappings are policy-controlled, version-bound inputs.

### Context

ADR-4 required RPN, FMEA→QBR, QBR, and BRS calculations to load the canonical semantic profile. The runtime had the profile file and schema, but the calculators still carried duplicate thresholds, mappings, floors, and adjustments in Python. A policy edit could therefore validate successfully while having no effect on the authoritative calculation path.

### Decision

Centralize semantic-profile loading at the calculation boundary. Every RPN, FMEA→QBR, QBR, and BRS calculation loads the canonical YAML, validates it with the canonical JSON Schema and format checker, and requires its `framework_version` to match the canonical manifest. Thresholds, dimensions, mappings, adjustments, unknown floors, and escalation rules are read from that validated profile. Invalid, missing, or version-mismatched profiles raise a typed `SemanticProfileError` before a score is returned; BRS unknown inputs remain `unknown` with no fabricated score.

### Options Considered

- Keep formula constants in Python and validate the profile separately: rejected because policy edits would silently drift from runtime behavior.
- Load only YAML without schema validation or manifest binding: rejected because malformed or cross-framework policy could influence release semantics.
- Treat missing BRS inputs as zero: rejected because unknown is not false and would understate risk.
- Derive a second profile from tests or generated output: rejected because tests and generated artifacts cannot become policy authority.

### Impact

Schemas changed: `schemas/semantic-profiles.schema.json` now declares the RPN thresholds and the complete QBR/FMEA/BRS fields consumed by runtime; `policies/semantic-profiles.yaml` is the canonical value source.
Components changed: semantic profile loader and calculators, semantic-profile contract tests, lifecycle/knowledge records.
Breaking change: **YES** for missing, malformed, or framework-mismatched semantic profiles, and for callers relying on the retired hard-coded thresholds.

IMPACT RADIUS: **WIDE**
Cascades: `manifest/profile version → schema validation → FMEA/RPN/QBR/BRS calculation → migration/release interpretation`.
Cascade Review: ✅ Done — RED profile-override regression, GREEN invalid/mismatch/profile-consumption tests, schema validation, authority search, and full repository verification cover the changed path.

### Consequences

- A schema-valid policy change now changes the calculation path only when it is also bound to the active framework manifest.
- Semantic formulas have one runtime policy source; consumers cannot silently retain stale thresholds or mappings.
- Loading and validating the profile per calculation adds local I/O and schema-validation cost. This is accepted for correctness and fail-closed behavior; a future cache must remain invalidated by the canonical bundle root.
- Local semantic correctness does not qualify private data, independent judging, external providers, vulnerability freshness, host enforcement, or a successful pilot.

### Evidence

- [verified 2026-08-01] RED regression monkeypatched a non-default profile; the old RPN calculator ignored its thresholds and returned the hard-coded priority.
- [verified 2026-08-01] GREEN semantic-profile tests pass for profile consumption, invalid-profile blocking, manifest-version mismatch, corrected FMEA mapping, QBR adjustments, and unknown-preserving BRS.
- [verified 2026-08-01] Canonical control-plane validation passes; full-suite, replay, bundle, lock, and build verification remains required before integration.

### Owner

**VHEATM maintainers**

### Known Debts (PATTERN-DEBT)

PATTERN-DEBT entries introduced or affected by this change: none registered. External key custody, fresh vulnerability evidence, private/time-sliced qualification, allowlisted provider qualification, host namespace capability, independent judging, UX-04, and successful shadow/canary observation remain open.

### Next Cycle Trigger

Start the next cycle whenever the semantic-profile schema or manifest version changes, or when a cache is introduced; rerun the profile mutation suite, bundle-root binding checks, and RG-00…RG-15 evaluation before accepting the change.

### Cycle Retrospective

- A canonical policy file is not authoritative if consumers duplicate its semantics in code.
- A profile override test is a compact regression for policy/runtime drift: it must change every calculator that claims profile authority.
- Version binding prevents a valid profile from one framework generation from silently controlling another.

## ADR-18 — Require an independently signed judge verdict at the release boundary

**Status:** ✅ ACCEPTED
**Date:** 2026-08-01
**Deciders:** VHEATM maintainers
**Tags:** `independent-judge` `qualification` `signing` `release-gates`
**Change Classification:** `SECURITY HARDENING`
**Review date:** 2026-09-01 — or earlier when judge evidence, key custody, or qualification schemas change.
**Supersedes:** —
**Superseded by:** —

**DECISION TYPE:** `CONSTRAINT-FORCED`
**CONFIDENCE:** `HIGH` for local persisted-evidence rejection; `NOT_PRODUCTION_QUALIFIED` until an external judge signer/key-custody service supplies real evidence.
**LAST CONFIRMED:** 2026-08-01 — `IMPLEMENTATION`, `REVIEW`, `TESTS`, `VALIDATION`
**VOLATILITY:** `WATCHFUL` — judge signer identity and key custody are release-bound external inputs.

### Context

The blind judge packet and verdict were content-addressed and packet-bound, but a caller could construct the same `JVR-*` identity and label it `independent_candidate` without proving that a separate judge process produced it. The evaluator accepted that self-created verdict whenever the packet item IDs matched the private receipt. A distinct `independent_judge_id` string was metadata, not an authorization or provenance boundary.

### Decision

Persisted independent judge verdicts that contribute to qualification must carry an Ed25519 signature verified with a dedicated judge public key and key ID. The release evaluator verifies the signature before packet binding and metric population checks. The qualification verification key and judge verification key must be different public keys; missing, mismatched, or unsigned judge evidence leaves qualification metrics unavailable and the affected gates `unknown`. `run_independent_judge()` continues to emit an unsigned candidate; signing is a separate controlled step at the judge/key-custody boundary.

### Options Considered

- Trust `verdict_id`, packet identity, and `independent_judge_id`: rejected because all are reproducible caller-controlled content or labels.
- Reuse the qualification/evaluator signing key: rejected because it collapses evaluator and judge independence.
- Sign candidate verdicts inside the local runner with an embedded key: rejected because key custody would be in the runtime and would not establish independent authority.
- Accept unsigned verdicts and rely on process isolation alone: rejected because persisted evidence can be replaced after process completion.

### Impact

Schemas changed: `schemas/judge-verdict.schema.json` declares optional signature fields for unsigned runtime candidates and signed persisted verdicts.
Components changed: judge sign/verify helpers, release evaluator, evaluator CLI judge-key inputs, release evidence fixtures/tests.
Breaking change: **YES** for release evidence that supplies unsigned judge verdicts or reuses the qualification verification key.

IMPACT RADIUS: **WIDE**
Cascades: `judge process → signed verdict → qualification evidence → RG-04/RG-05/RG-07 → shadow/canary authorization`.
Cascade Review: ✅ Done — RED unsigned-verdict release regression, GREEN signature/tamper regression, distinct-key enforcement, schema validation, and full repository verification cover the boundary.

### Consequences

- A content-addressed verdict no longer becomes independent qualification evidence without a separate cryptographic signer.
- Local tests can prove signing and rejection behavior, but cannot mint production judge authority or private gold evidence.
- Shadow/canary and GA remain blocked when external judge key custody or private/time-sliced evidence is unavailable.
- Candidate verdicts remain useful for local process tests, but only signed verdicts are eligible for release-gate metric derivation.

### Evidence

- [verified 2026-08-01] RED release regression showed an unsigned, packet-bound `JVR-*` verdict made RG-05 pass under the old boundary.
- [verified 2026-08-01] GREEN tests verify signed verdict round-trip, tamper rejection, distinct qualification/judge keys, and unsigned release evidence remaining `unknown`.
- [verified 2026-08-01] No judge private key, private gold corpus, or production qualification claim is created by this change.

### Owner

**VHEATM maintainers**

### Known Debts (PATTERN-DEBT)

PATTERN-DEBT entries introduced or affected by this change: none registered. External judge key custody, private/time-sliced gold data, provider qualification, fresh vulnerability evidence, host namespace capability, UX-04, and successful shadow/canary observation remain open.

### Next Cycle Trigger

Start the next cycle when a production judge signer/key-custody service is connected or the verdict schema gains new identity-bearing fields; add a signer rotation/revocation regression and rerun RG-00…RG-15 before accepting new evidence.

### Cycle Retrospective

- Process isolation protects execution while it is running; it does not authenticate a persisted record after the process exits.
- Independence must be represented by a separate key boundary, not only different provider/model strings.
- Release evaluators must verify the strongest evidence boundary before deriving population coverage or threshold metrics.

## ADR-19 — Bind RG measurement methods to a canonical policy

**Status:** ✅ ACCEPTED
**Date:** 2026-08-01
**Deciders:** VHEATM maintainers
**Tags:** `qualification` `release-gates` `measurement-integrity` `fail-closed`
**Change Classification:** `SECURITY HARDENING`
**Review date:** 2026-09-01 — or earlier when an RG metric, confidence method, population rule, or qualification service changes.
**Supersedes:** —
**Superseded by:** —

**DECISION TYPE:** `CONSTRAINT-FORCED`
**CONFIDENCE:** `HIGH` for local method-identity enforcement; `NOT_PRODUCTION_QUALIFIED` until private data, independent judging, statistical review, and external key custody are available.
**LAST CONFIRMED:** 2026-08-01 — `IMPLEMENTATION`, `REVIEW`, `TESTS`, `VALIDATION`
**VOLATILITY:** `WATCHFUL` — measurement estimators and confidence methods are release-bound policy inputs.

### Context

Qualification measurements carried a 64-hex `method_digest`, but the runtime only checked its shape. A signed evidence document could therefore claim RG-05 or RG-08 values while naming no canonical estimator, confidence method, sample population, or minimum sample floor. The signature protected caller-authored bytes, not the measurement protocol.

### Decision

Add `policies/qualification-methods.yaml` and `schemas/qualification-methods.schema.json` as canonical, manifest-version-bound method policy. Every declared RG-00…RG-15 qualification metric has a unique method definition containing sample basis, estimator, confidence method, and minimum sample count. The method digest is the SHA-256 identity of that exact definition. Qualification verification rejects a missing/unknown method digest before signature-derived metrics are exposed; evaluator sample floors and sample-basis semantics are read from the same policy. The public seeded runner emits and validates the same canonical method digests.

### Options Considered

- Accept any well-formed SHA-256 method digest: rejected because formatting is not protocol identity.
- Keep method names and sample floors in evaluator Python: rejected because policy changes would silently drift from evidence validation.
- Trust the signed `confidence_lower` field as proof of statistical correctness: rejected because a signature authenticates a claim but does not independently recompute its estimator or prove its population.
- Use public seeded replay as private qualification: rejected because it remains `public_seeded`/`unverified` and has no independent gold/judge authority.

### Impact

Schemas changed: `schemas/qualification-methods.schema.json`.
Canonical policy changed: `policies/qualification-methods.yaml`.
Components changed: qualification method loader, qualification verifier, RG evaluator, public seeded runner, repository validator, bundle/package inventory, and regression tests.
Breaking change: **YES** for qualification evidence with arbitrary method digests or evidence produced under an undeclared measurement protocol.

IMPACT RADIUS: **WIDE**
Cascades: `method policy → method digest → typed qualification verification → RG sample floors/bases → release report → pilot authorization`.
Cascade Review: ✅ Done — direct release regression, direct method-policy test, public replay mutation test, validator/bundle checks, pattern-globalization scan, and full verification cover the changed boundary.

### Consequences

- A valid signature can no longer make an undeclared measurement protocol eligible for RG metrics.
- Policy edits intentionally change method identities and invalidate evidence that was produced under a different canonical protocol.
- The local verifier still does not recompute private outcomes or establish independent statistical validity; those remain external qualification prerequisites and fail closed.
- Loading the method policy at verification boundaries adds schema/I/O work. This is accepted for correctness; any future cache must be invalidated by the canonical bundle root.

### Evidence

- [verified 2026-08-01] RED release regression showed an arbitrary 64-hex method digest allowed RG-05 to pass.
- [verified 2026-08-01] GREEN tests reject the arbitrary digest, bind public seeded measurements to canonical method identities, and reject method-policy framework drift.
- [verified 2026-08-01] Full repository verification passed with 249 tests; canonical validator, low-risk evaluate/route, public replay, lock check, and wheel/sdist build all passed.
- [verified 2026-08-01] No private gold data, external signer, recomputed confidence interval, or GA evidence was created by this change.

### Owner

**VHEATM maintainers**

### Known Debts (PATTERN-DEBT)

PATTERN-DEBT entries introduced or affected by this change: none registered. External private/time-sliced gold data, independent judge custody, statistical method review, fresh vulnerability evidence, provider qualification, host namespace capability, UX-04, and successful shadow/canary observation remain open.

### Next Cycle Trigger

Start the next cycle when an RG metric/method changes or an external qualification service supplies recomputed observations; bind its method-policy digest and independent data population before accepting new evidence.

### Cycle Retrospective

- A content-addressed method label is not a method contract until it resolves to canonical estimator and population semantics.
- Measurement policy must be included in the same authority/bundle inventory as schemas and runtime policy.
- Canonical method binding narrows false assurance without pretending to provide unavailable data or statistical independence.

## ADR-20 — Bind RG-13 freshness and signing-role independence to canonical policy

**Status:** ✅ ACCEPTED
**Date:** 2026-08-01
**Deciders:** VHEATM maintainers
**Tags:** `supply-chain` `vulnerability` `freshness` `key-separation` `fail-closed`
**Change Classification:** `SECURITY HARDENING`
**Review date:** 2026-09-01 — or earlier when vulnerability-feed SLAs, signing roles, scanner identity, or release-time semantics change.
**Supersedes:** —
**Superseded by:** —

**DECISION TYPE:** `CONSTRAINT-FORCED`
**CONFIDENCE:** `HIGH` for local policy/evaluator enforcement; `NOT_PRODUCTION_QUALIFIED` until external scanner freshness, key custody, and release operations provide real evidence.
**LAST CONFIRMED:** 2026-08-01 — `IMPLEMENTATION`, `REVIEW`, `TESTS`, `VALIDATION`
**VOLATILITY:** `WATCHFUL` — vulnerability feeds, scanner coverage, and key-rotation requirements are external release inputs.

### Context

RG-13 verified signatures, bundle/lock bindings, and a derived critical-CVE count, but it did not bind the scan to the release evaluation time. A signed empty scan could therefore remain eligible after its evidence window had expired. The release evaluator also accepted one public key for release, vulnerability, and provenance records, collapsing the intended authority separation into labels.

### Decision

Add `policies/supply-chain-evidence.yaml` and its schema as canonical, manifest-bound policy. It freezes a seven-day maximum vulnerability-scan age, rejects scans generated after evaluation, and requires distinct public keys for the `supply_chain`, `vulnerability`, and `provenance` roles. The release evaluator loads and validates this policy at the evidence boundary, verifies cryptographic records, then enforces freshness and key separation before deriving RG-13 metrics. Freshness violations and role reuse produce an explicit RG-13 failure with the verification rationale; absent external evidence remains blocking.

### Options Considered

- Trust the scan signature and target lock digest without a time bound: rejected because authenticity does not establish currentness.
- Compare only the scan and attestation timestamps: rejected because neither is an evaluation-time policy or an upper-bound freshness guarantee.
- Require different key ID strings: rejected because labels do not prove distinct key material.
- Generate a local “fresh” scan or embedded signing keys: rejected because local artifacts cannot stand in for external scanner coverage or key custody.

### Impact

Schemas changed: `schemas/supply-chain-evidence.schema.json`.
Canonical policy changed: `policies/supply-chain-evidence.yaml`.
Components changed: supply-chain policy loader, vulnerability freshness verifier, RG-13 evaluator, validator, bundle/package inventory, and release evidence tests.
Breaking change: **YES** for RG-13 evidence that is older than the canonical window, future-dated relative to evaluation, or signed by reused role keys.

IMPACT RADIUS: **WIDE**
Cascades: `supply-chain policy → typed evidence verification → RG-13 → release report → pilot authorization`.
Cascade Review: ✅ Done — stale-scan and same-key RED regressions, policy/schema/manifest binding tests, full evaluator verification, and packaging checks cover the changed boundary.

### Consequences

- A valid signature no longer makes an old vulnerability result current.
- Public key bytes, rather than role-name metadata, establish signing-role separation.
- The seven-day value is a frozen release policy input, not evidence that a real external scanner has run or that its dependency coverage is complete.
- Policy loading at evaluation adds local I/O/schema cost; any future cache must be invalidated by the canonical bundle root and policy identity.
- External key custody, scanner feed freshness/coverage, private qualification data, provider qualification, host enforcement, and pilot success remain open and keep GA fail-closed.

### Evidence

- [verified 2026-08-01] RED release regression showed a signed scan generated nine days earlier still made RG-13 pass.
- [verified 2026-08-01] RED release regression showed one key could sign all three supply-chain roles and still make RG-13 pass.
- [verified 2026-08-01] GREEN tests enforce the canonical seven-day window, future-date rejection, distinct public-key material, policy schema, manifest binding, and diagnostic rationale.
- [verified 2026-08-01] No external scanner result, production key custody, or GA evidence was created by this change.

### Owner

**VHEATM maintainers**

### Known Debts (PATTERN-DEBT)

PATTERN-DEBT entries introduced or affected by this change: none registered. External scanner feed and coverage, key custody/rotation/revocation, private/time-sliced gold data, allowlisted provider qualification, host namespace capability, UX-04, and successful shadow/canary observation remain open.

### Next Cycle Trigger

Start the next cycle when a vulnerability feed, scanner allowlist/coverage contract, key-custody service, or freshness SLA changes; bind its signed authority and rerun RG-00…RG-15 before accepting new release evidence.

### Cycle Retrospective

- A signature authenticates a historical statement; it does not make that statement fresh.
- Independence must be checked against cryptographic key material, not only key IDs or role labels.
- Canonical release policy needs both a measurement rule and a time/authority boundary before a derived gate can pass.

## ADR-21 — Revalidate immutable pilot identity at every lifecycle transition

**Status:** ✅ ACCEPTED
**Date:** 2026-08-01
**Deciders:** VHEATM maintainers
**Tags:** `pilot` `content-addressing` `lifecycle` `fail-closed`
**Change Classification:** `SECURITY HARDENING`
**Review date:** 2026-09-01 — or earlier when pilot lifecycle fields, persistence, or external observation storage changes.
**Supersedes:** —
**Superseded by:** —

**DECISION TYPE:** `CONSTRAINT-FORCED`
**CONFIDENCE:** `HIGH` for local immutable-record enforcement; `NOT_PRODUCTION_QUALIFIED` until a real shadow/canary observation run and operational evidence exist.
**LAST CONFIRMED:** 2026-08-01 — `IMPLEMENTATION`, `REVIEW`, `TESTS`, `VALIDATION`
**VOLATILITY:** `WATCHFUL` — lifecycle records may gain external store, signer, or operational receipt fields.

### Context

`prepare_pilot()` content-addressed the pilot record, but `complete_pilot()` and `rollback_pilot()` trusted the caller-provided mapping after checking only its status. A caller could mutate `read_only` or `tools_enabled` on a `ready` pilot and then submit observations consistent with the altered profile. The record remained schema-shaped, but the lifecycle transition no longer referred to the prepared pilot revision.

### Decision

Add one `expected_pilot_id()` identity helper and require `_require_current_pilot()` at the start of every mutating lifecycle transition. Preparation, completion, and rollback all use the same immutable-content projection; a changed field, missing ID, or mismatched ID raises `PilotError` before provider runs, observations, or rollback effects are considered. New revision IDs continue to include the updated content, so transitions remain content-addressed without silently mutating history.

### Options Considered

- Trust `status == ready/complete`: rejected because mutable caller fields can change execution mode without changing status.
- Recompute identity only in `prepare_pilot()`: rejected because persisted records can be modified between preparation and completion/rollback.
- Sign local pilot records with an embedded key: rejected because local key material cannot establish operational pilot authority.
- Rebuild the entire pilot record from external storage: deferred; the local identity boundary must remain correct before an external store exists.

### Impact

Schemas changed: none.
Components changed: pilot lifecycle identity helper, preparation/completion/rollback transitions, pilot regression tests, lifecycle documentation.
Breaking change: **YES** for callers that mutate a prepared pilot mapping without recomputing its content-addressed revision.

IMPACT RADIUS: **WIDE**
Cascades: `pilot record → lifecycle transition → observations/provider runs → shadow/canary evidence`.
Cascade Review: ✅ Done — mutated-ready-pilot RED regression, shared-helper coverage for completion and rollback, full pilot contract tests, and release-gated pilot semantics cover the changed boundary.

### Consequences

- A pilot cannot change execution mode or scope between preparation and completion without creating a new revision and passing the transition boundary.
- Rollback is protected by the same identity check, preventing a caller from applying rollback to altered content while retaining the old ID.
- This proves local record integrity only; it does not prove an actual shadow/canary observation, host enforcement, provider qualification, or GA readiness.
- Identity recomputation is negligible local cost; future persisted-store lookups must retain the same immutable projection.

### Evidence

- [verified 2026-08-01] RED pilot regression showed a caller-mutated `ready` pilot could complete with `tools_enabled=true`.
- [verified 2026-08-01] GREEN test rejects the mutated pilot before provider-run/observation acceptance; existing pilot suite remains green.
- [verified 2026-08-01] No external pilot observation, canary authorization, or GA evidence was created by this change.

### Owner

**VHEATM maintainers**

### Known Debts (PATTERN-DEBT)

PATTERN-DEBT entries introduced or affected by this change: none registered. External shadow/canary observation, host namespace capability, provider qualification, key custody, private/time-sliced qualification, UX-04, and GA operational evidence remain open.

### Next Cycle Trigger

Start the next cycle when pilot records become externally persisted/signed or when a lifecycle field is added; add store/signer binding and rerun the mutation, rollback, and canary revalidation suite.

### Cycle Retrospective

- A content-addressed creation record is not immutable unless every later transition revalidates its identity.
- Status checks are authorization state, not record integrity.
- Shared identity projection prevents completion and rollback from drifting into separate trust models.

## ADR-22 — Enforce provider allowlist and qualification state at execution and pilot boundaries

**Status:** ✅ ACCEPTED
**Date:** 2026-08-01
**Deciders:** VHEATM maintainers
**Tags:** `providers` `allowlist` `pilot` `qualification` `fail-closed`
**Change Classification:** `SECURITY HARDENING`
**Review date:** 2026-09-01 — or earlier when an external provider, endpoint, version, configuration, or qualification authority is added.
**Supersedes:** —
**Superseded by:** —

**DECISION TYPE:** `CONSTRAINT-FORCED`
**CONFIDENCE:** `HIGH` for local descriptor/qualification-state enforcement; `NOT_PRODUCTION_QUALIFIED` because both allowlisted entries are intentionally `pending` and no external provider qualification is claimed.
**LAST CONFIRMED:** 2026-08-01 — `IMPLEMENTATION`, `REVIEW`, `TESTS`, `VALIDATION`
**VOLATILITY:** `VOLATILE` — provider identity, versions, endpoints, and qualification status are release-bound external inputs.

### Context

The provider adapter bound request, receipt, response, and config digests, but the descriptor itself was only shape-validated. Any syntactically valid provider ID/version could therefore produce a completed provider run when the broker allowed its network request. Pilot completion consumed that run without checking whether the provider was allowlisted or independently qualified. A valid receipt proved authorization for a request, not release eligibility of the provider implementation.

### Decision

Add `policies/provider-allowlist.yaml` and `schemas/provider-allowlist.schema.json` as canonical, manifest-bound policy. Each provider/version entry has an explicit `qualification_state` (`pending`, `qualified`, or `revoked`). Provider execution and persisted-run verification reject descriptors absent from the allowlist. Shadow completion may consume an allowlisted `pending` provider for contract observation; canary completion requires `qualified`, so the current local entries cannot authorize canary. No local fixture is marked qualified.

### Options Considered

- Treat a broker allow receipt as provider qualification: rejected because request authorization and provider trust are different claims.
- Allow every provider ID while relying on endpoint HTTPS: rejected because transport security does not establish provider identity, version, or evaluation authority.
- Mark local/test providers `qualified` to keep canary fixtures green: rejected because it would fabricate external qualification evidence.
- Hard-code provider IDs in Python: rejected because allowlist and qualification changes must be canonical policy mutations with bundle binding.

### Impact

Schemas changed: `schemas/provider-allowlist.schema.json`.
Canonical policy changed: `policies/provider-allowlist.yaml`.
Components changed: provider policy loader, adapter, persisted provider-run verifier, pilot completion, validator, bundle/package inventory, and provider/pilot tests.
Breaking change: **YES** for provider runs whose descriptor is absent, version-mismatched, or revoked; canary is additionally blocked for `pending` providers.

IMPACT RADIUS: **CRITICAL**
Cascades: `provider policy → adapter/persisted-run verification → pilot observation → canary authorization`.
Cascade Review: ✅ Done — untrusted-provider RED regression, policy/schema/manifest binding tests, shadow-pending acceptance, canary-pending rejection, and full provider/pilot verification cover the changed boundary.

### Consequences

- A valid network receipt cannot promote an unallowlisted provider into pilot evidence.
- Shadow remains useful for local read-only contract observation without being mislabeled as provider qualification.
- Canary remains fail-closed until an external authority changes a canonical entry to `qualified` and supplies corresponding evidence; this change does not do that.
- Policy loading adds a small schema/I/O cost at provider and persisted-run boundaries; any future cache must bind the canonical bundle root and policy identity.

### Evidence

- [verified 2026-08-01] RED pilot regression showed a syntactically valid `untrusted.vendor` run could complete with an allowed receipt.
- [verified 2026-08-01] GREEN tests reject unallowlisted descriptors and block canary use of the pending contract provider.
- [verified 2026-08-01] Both canonical providers remain `pending`; no external provider qualification or canary success was fabricated.

### Owner

**VHEATM maintainers**

### Known Debts (PATTERN-DEBT)

PATTERN-DEBT entries introduced or affected by this change: none registered. External provider allowlisting/qualification authority, endpoint identity, host enforcement, key custody, private/time-sliced qualification, UX-04, and successful shadow/canary observation remain open.

### Next Cycle Trigger

Start the next cycle when a real provider is proposed or a provider entry changes state; bind endpoint/config identity, qualification evidence, revocation/rotation rules, and rerun provider/pilot/release gates before setting `qualified`.

### Cycle Retrospective

- A network authorization receipt answers “may this request run?”; it does not answer “is this provider qualified for canary?”.
- Allowlist identity and qualification state need one canonical policy, while shadow and canary require different states.
- Keeping local provider entries pending preserves useful contract tests without laundering them into external evidence.

## ADR-23 — Bind and revalidate the sandbox backend at every launch

**Status:** ✅ ACCEPTED
**Date:** 2026-08-01
**Deciders:** VHEATM maintainers
**Tags:** `reference-monitor` `sandbox` `backend-integrity` `TOCTOU` `fail-closed`
**Change Classification:** `SECURITY HARDENING`
**Review date:** 2026-09-01 — or earlier when backend attestation, host deployment, or execute-request fields change.
**Supersedes:** —
**Superseded by:** —

**DECISION TYPE:** `CONSTRAINT-FORCED`
**CONFIDENCE:** `HIGH` for local digest/request/FD binding; `NOT_PRODUCTION_QUALIFIED` for host-level bubblewrap identity and namespace capability.
**LAST CONFIRMED:** 2026-08-01 — `IMPLEMENTATION`, `TESTS`, `VALIDATION`
**VOLATILITY:** `WATCHFUL` — backend binaries, host kernels, deployment paths, and external attestation remain deployment-specific.

### Context

The sandbox checked its configured backend digest only during executor construction. A later backend replacement could therefore reach preflight/action using a different executable. In addition, the execute request and approval receipt did not carry the executable digest, so the authorization action digest did not cover the reference-monitor binary itself. Re-opening the path after a hash check would leave a time-of-check/time-of-use window.

### Decision

Require `executable_digest` on every execute request. The sandbox rejects a request whose digest does not equal its configured backend before brokered execution, re-hashes the backend on every run, and opens one verified file descriptor that is passed to both preflight and action launch through `/proc/self/fd`. Completed and failed sandbox records require the request/backend digest equality; the shared request/action/approval digest consequently covers the backend identity. Backend drift, replacement, or unavailable file access remains a typed blocked result with no host fallback.

### Options Considered

- Check the backend only at executor construction: rejected because deployment files can change between construction and execution.
- Hash the path and reopen it for launch: rejected because replacement after the hash would remain a TOCTOU bypass.
- Put the digest only in the sandbox result: rejected because the broker approval would not authorize the exact backend used for the action.
- Claim that a local digest proves production bubblewrap provenance: rejected because trusted binary custody and host namespace qualification remain external evidence.

### Impact

Schemas changed: `tool-request.schema.json` requires `executable_digest` for execute requests.
Components changed: sandbox subprocess boundary, backend verification/FD binding, seeded broker request, tool-broker fixtures, sandbox regression tests, and lifecycle evidence.
Breaking change: **YES** for execute callers that omit or mismatch the backend digest.

IMPACT RADIUS: **HIGH**
Cascades: `backend bytes → execute request → approval token/action digest → verified FD → preflight/action → sandbox outcome`.
Cascade Review: ✅ Done — digest-drift RED regression, request-binding RED regression, focused broker/sandbox tests, full suite, validator, and package/replay gates cover the changed boundary.

### Consequences

- Approval now covers the executable identity as well as command, scope, environment flags, and other request fields.
- A backend replacement after executor construction cannot be launched through the verified reference-monitor path.
- FD binding narrows the local TOCTOU window without asserting that the host kernel actually provides the requested namespace isolation.
- Deployment still needs an independently trusted backend digest/attestation and a qualified host; local configuration alone cannot authorize GA or canary claims.

### Evidence

- [verified 2026-08-01] RED regression showed a changed backend was not classified as digest drift before the fix.
- [verified 2026-08-01] GREEN sandbox/broker tests pass with request-bound executable digests and FD-passed backend launches.
- [verified 2026-08-01] Full repository suite passes at 258 tests; canonical validator passes; no production host or GA evidence was created.

### Owner

**VHEATM maintainers**

### Known Debts (PATTERN-DEBT)

PATTERN-DEBT entries introduced or affected by this change: none registered. External backend provenance/attestation, host namespace capability, private qualification, key custody, provider qualification, fresh vulnerability evidence, UX research, and successful shadow/canary observation remain open.

### Next Cycle Trigger

Start the next cycle when a deployment supplies a trusted backend attestation or host qualification receipt; bind it to the canonical request/bundle and rerun the RG-08/RG-09 and full RG-00…RG-15 evidence matrix.

### Cycle Retrospective

- A backend digest is useful only when it participates in the authorization identity and is used for the same file that is executed.
- Revalidation and FD binding are complementary: the first catches drift, the second prevents reopening a changed path after verification.
- Local enforcement can close a code-path gap while production trust remains explicitly evidence-dependent.

## ADR-24 — Bind verified claims to their consuming gates

**Status:** ✅ ACCEPTED
**Date:** 2026-08-01
**Deciders:** VHEATM maintainers
**Tags:** `provenance` `claims` `gate-binding` `report-validation` `fail-closed`
**Change Classification:** `SECURITY HARDENING`
**Review date:** 2026-09-01 — or earlier when claim schemas, finding evidence, or report gate derivation changes.
**Supersedes:** —
**Superseded by:** —

**DECISION TYPE:** `CONSTRAINT-FORCED`
**CONFIDENCE:** `HIGH` for local content-addressed claim/report enforcement; `NOT_PRODUCTION_QUALIFIED` for the still-open external qualification and pilot evidence.
**LAST CONFIRMED:** 2026-08-01 — `IMPLEMENTATION`, `TESTS`, `VALIDATION`
**VOLATILITY:** `WATCHFUL` — gate taxonomy and evidence aggregation may add multi-gate claim use cases.

### Context

Claims were content-addressed to their text, source references, validation receipts, and evidence kind, but not to the gates for which they were relevant. A verified claim could therefore be copied into a different passing gate or finding while remaining schema-valid and cryptographically consistent. Passing gates also accepted a trusted `SRC-*` record directly, allowing source material to bypass claim-level relevance entirely. Truth of a claim and relevance to a gate are separate properties; the report boundary had no canonical field with which to enforce the latter.

### Decision

Add an optional, structurally validated `gate_trace` to claim records. When present, the trace is included in the claim content identity, so changing gate scope creates a new immutable `CLM-*` record. Report semantic validation rejects unknown claim gate IDs and requires every claim used by a passing gate to cover that gate; verified or mandatory finding evidence must cover every gate in the finding trace. Passing gates reject direct `SRC-*` evidence, including trusted sources; source records remain lineage for gate-bound claims or typed artifacts. Generic claims remain available for non-gate provenance, but they cannot authorize a passing gate or verified finding without an explicit binding.

### Options Considered

- Infer relevance from source paths or claim wording: rejected because routing by filenames, prose, or model intuition violates canonical gate selection.
- Treat module `gate_trace` as sufficient: rejected because module ownership proves where a result was emitted, not that each referenced claim is relevant to the consuming gate.
- Require every historical claim to gain a gate trace immediately: rejected because generic provenance remains useful outside gate evidence and immutable records cannot be silently rewritten.
- Store gate scope only in the report: rejected because changing evidence scope would not create a new content address and a claim could be detached from its canonical relevance.
- Permit trusted source records directly as gate evidence: rejected because trust/taint state does not prove gate relevance or semantic validation.

### Impact

Schemas changed: `schemas/claim.schema.json`.
Components changed: provenance claim identity/building, report semantic validator, provenance/report regression tests, architecture and lifecycle documentation.
Breaking change: **YES** for passing-gate or verified-finding evidence that omits a relevant claim gate trace.

IMPACT RADIUS: **HIGH**
Cascades: `claim identity → provenance registry → module/report evidence → derived gate result → release evidence`.
Cascade Review: ✅ Done — RED cross-gate reuse, GREEN content-address identity, schema coverage, report-boundary checks, full suite, validator, and package checks cover the changed boundary.

### Consequences

- A claim remains immutable when its gate scope changes; the new scope receives a new ID and journal entry.
- A passing gate can no longer consume a verified claim that is bound only to an unrelated gate or to no gate, nor a trusted source record without typed gate context.
- Verified findings receive the same relevance protection across their full gate trace.
- Generic non-gate claims retain backward-compatible identity when no trace is supplied; external qualification evidence and pilot readiness remain separately blocked by their own prerequisites.
- Consumers constructing gate evidence must now provide gate scope explicitly, adding a small amount of context to claim creation.

### Evidence

- [verified 2026-08-01] RED report regression accepted a claim whose declared gate scope was `HG-B` while `HG-A` passed.
- [verified 2026-08-01] GREEN report validation rejects the mismatch with a typed gate-binding issue, and changing `gate_trace` changes the content-addressed claim ID.
- [verified 2026-08-01] GREEN report validation rejects direct trusted `SRC-*` evidence and requires a typed gate-bound claim/artifact path.
- [verified 2026-08-01] Schema/provenance/report tests pass for valid traces and invalid/unknown trace cases; no production qualification or GA evidence was created.

### Owner

**VHEATM maintainers**

### Known Debts (PATTERN-DEBT)

PATTERN-DEBT entries introduced or affected by this change: none registered. External private/time-sliced qualification, trusted key custody, provider qualification, host namespace capability, vulnerability feed, and successful shadow/canary observation remain open.

### Next Cycle Trigger

Start the next cycle when a new gate taxonomy or multi-gate evidence aggregator is introduced; add explicit coverage tests for shared claims and rerun the cross-gate mutation suite before changing the identity projection.

### Cycle Retrospective

- A claim can be true and verified while still being irrelevant to the gate consuming it.
- Content-addressing protects integrity only for fields included in the identity projection.
- Module ownership traces and claim relevance traces are complementary boundaries, not substitutes.
- Keeping generic claims non-gate-bound preserves provenance reuse without allowing them to mint release gate passes.

## ADR-25 — Qualify RG-09 authorization coverage across all tool classes

**Status:** ✅ ACCEPTED
**Date:** 2026-08-01
**Deciders:** VHEATM maintainers
**Tags:** `qualification` `RG-09` `tool-broker` `fail-closed`
**Change Classification:** `SECURITY HARDENING`
**Review date:** 2026-09-01 — or earlier when runtime tool classes, approval semantics, or host hard-stop instrumentation changes.
**Supersedes:** —
**Superseded by:** —

**DECISION TYPE:** `CONSTRAINT-FORCED`
**CONFIDENCE:** `HIGH` for local broker authorization coverage; `NOT_PRODUCTION_QUALIFIED` for host-level hard-stop timing and private release evidence.
**LAST CONFIRMED:** 2026-08-01 — `IMPLEMENTATION`, `TESTS`, `VALIDATION`
**VOLATILITY:** `WATCHFUL` — tool classes and enforcement points are canonical policy inputs.

### Context

The public seeded RG-09 case submitted an unsupported `admin` class and measured one denial. That did not exercise the five canonical runtime classes (`read`, `write`, `execute`, `network`, `secrets`), nor did it prove that approval-bound requests reached the correct class-specific guard. The release method also declares `hard_stop_p99_seconds`; no trustworthy host-level timing source exists in the public deterministic runner.

### Decision

Replace the single unsupported-class probe with five schema-valid, policy-invalid requests. Read fails its secret-content guard; execute fails sandbox enforcement after a valid single-use approval; write fails workspace scope; network fails destination allowlisting after approval; secrets fails named-secret registration after approval. The case records each decision and control list, emits `unauthorized_block_rate=1.0` over five observations, and remains `public_seeded`/`unverified`. It does not emit `hard_stop_p99_seconds`; host sandbox latency remains unknown until a real deployment-level timing probe can measure the enforcement point.

### Options Considered

- Keep the `admin` request and call it representative: rejected because an unsupported class tests only default-deny routing, not each canonical class guard.
- Add a deterministic constant for `hard_stop_p99_seconds`: rejected because a constant would fabricate a timing observation and could be mistaken for host qualification.
- Time only Python broker calls and label them host hard-stop latency: rejected because broker decision latency is not proof of subprocess/namespace enforcement latency.
- Use an approval token for every request including read: rejected because read is intentionally allowed without approval and the test must preserve the canonical policy semantics.

### Impact

Schemas changed: none.
Components changed: seeded qualification security handler, qualification regression tests, lifecycle/knowledge documentation.
Breaking change: **NO** for runtime behavior; **YES** for the seeded case's sample population and detail shape.

IMPACT RADIUS: **MODERATE**
Cascades: `runtime policy/tool schemas → broker class guards → seeded qualification case → RG-09 candidate measurement`.
Cascade Review: ✅ Done — five-class replay, approval-bound execute/write/network/secrets paths, deterministic repeated-run test, method binding, and public-unverified labeling cover the changed boundary.

### Consequences

- Local seeded evidence now tests every canonical unauthorized tool class at the broker enforcement point.
- A passing matrix means only that these deterministic policy requests were denied; it does not prove private attack-family coverage, host namespace capability, or p99 hard-stop latency.
- Public replay remains deterministic because no wall-clock measurement is inserted into the seeded run identity.
- RG-09 stays incomplete when `hard_stop_p99_seconds` is absent; the evaluator remains fail-closed instead of inferring it from `unauthorized_block_rate`.

### Evidence

- [verified 2026-08-01] The previous single-class case was replaced with five schema/approval-bound requests and all five return `deny` without backend execution.
- [verified 2026-08-01] Seeded replay remains deterministic and emits `unauthorized_block_rate=1.0` with `sample_count=5`, method-bound to the canonical qualification policy.
- [verified 2026-08-01] No `hard_stop_p99_seconds`, private qualification, host namespace, or GA evidence was fabricated.

### Owner

**VHEATM maintainers**

### Known Debts (PATTERN-DEBT)

PATTERN-DEBT entries introduced or affected by this change: none registered. Host-level hard-stop instrumentation, private attack-family trials, trusted external keys, provider qualification, vulnerability feed, and successful shadow/canary observation remain open.

### Next Cycle Trigger

Start the next cycle when a qualified host exposes an enforcement-point timing probe or when a sixth tool class is added; bind the probe's population, clock source, and deployment identity before adding `hard_stop_p99_seconds`.

### Cycle Retrospective

- Default-deny on an unsupported class is not coverage of the canonical class guards.
- Approval-bound negative requests must test the post-approval guard, not only missing-token rejection.
- Determinism and timing are different evidence contracts; keep wall-clock measurements out of replay identities.
- Missing host timing must remain unknown even when every local broker denial succeeds.
