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
