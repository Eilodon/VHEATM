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

- The action reference monitor, real sandbox enforcement, external analyzer providers, private/time-sliced gold corpus, dependency lock, vulnerability evidence, and signing/key service are not implemented.
- The release evaluator can honestly report `unknown`/`fail`, but it does not manufacture qualification metrics.

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

### Owner and Known Debts

**Owner:** VHEATM maintainers

Known pattern debt: none newly opened. Release qualification debt remains: external key custody, vulnerability scanner feed, private time-sliced corpus, allowlisted provider deployment, a host with namespace enforcement, and shadow observations from an actual pilot.

### Next Cycle Trigger

Start the next cycle when any external prerequisite is available. Bind its identity/digest, add crash/isolation/replay evidence, execute RG measurements, and retain `unknown` or `blocked` on any missing observation.
