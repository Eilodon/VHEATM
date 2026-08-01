# CONTEXT.md — Domain Knowledge
<!-- Version: 20 — populate via domain-alignment skill, then keep updated via knowledge-compound -->

## Ubiquitous Language
<!-- Add domain terms where the word means something more specific than common usage -->
- **Candidate overlay:** a schema-valid, content-addressed planning or migration record whose `authority_eligible` value is permanently `false`; it cannot mint a gate, finding, certification, or release claim. <!-- from ADR: ADR.md -->
- **Delta-only assurance:** an assurance mapping that records named SAMM/SSDF/BSIMM improvement deltas without producing a maturity score or certification. <!-- from ADR: ADR.md -->
- **Semantic migration capability:** an executable contract that maps a preserved legacy reference to typed inputs, outputs, failure semantics, and evidence/authority boundaries. <!-- from ADR: ADR.md -->
- **Authorization-to-action binding:** a content-addressed relationship proving that the policy decision and tool receipt authorize the exact action represented by an execution record. <!-- from ADR: ADR-8 -->
- **Reference-monitor receipt:** the schema-valid, content-addressed authorization record emitted at the sandbox boundary before a backend action may claim execution. <!-- from ADR: ADR-8 -->
- **Shared decision contract:** the canonical semantic checks for request version, identity, decision, controls, time, and approval binding applied before any brokered adapter emits an action receipt. <!-- from ADR: ADR-9 -->
- **Typed authorization failure:** a blocked or unknown adapter record representing authorization failure without inventing a deny receipt or claiming transport/execution occurred. <!-- from ADR: ADR-9 -->
- **Non-authoritative migration archive:** preserved legacy implementation material outside the runtime package, retained for comparison and provenance but prohibited from producing policy decisions. <!-- from ADR: ADR-10 -->
- **Evaluator evidence boundary:** the shared schema-and-format validation step that every release-evidence entry point must pass before cryptographic verification can contribute metrics. <!-- from ADR: ADR-11 -->
- **Qualification sample basis:** the canonical population semantics for a measurement, distinguishing private case trials from repeated evaluations and other private observations. <!-- from ADR: ADR-12 -->
- **Blind judge packet:** the content-addressed, randomized evidence envelope that binds independent judge context/provider/configuration to the exact items presented for adjudication. <!-- from ADR: ADR-13 -->
- **Independent judge coverage:** the intersection of packet decision item IDs with verified private receipt case references used to authorize a critical trial count. <!-- from ADR: ADR-13 -->
- **Persisted provider receipt chain:** the redacted network request, broker receipt, and provider response identity retained together so a later pilot boundary can re-verify authorization rather than trust a rehashed run ID. <!-- from ADR: ADR-14 -->
- **Canary evidence revalidation:** the pre-rollout recomputation of the release report from typed evidence, verification keys, bundle root, and evaluator version before tools may be enabled. <!-- from ADR: ADR-15 -->
- **Release-report identity boundary:** the schema, ordered RG-00…RG-15 gate set, derived summary, and evaluation timestamp that must agree before a report can authorize a pilot. <!-- from ADR: ADR-16 -->
- **Canonical semantic profile binding:** the schema-valid semantic policy and manifest-version match required before RPN, FMEA→QBR, QBR, or BRS calculations can return a score. <!-- from ADR: ADR-17 -->
- **Signed independent verdict:** a complete blind-judge verdict carrying a valid signature from a judge key distinct from the qualification evaluator key, required before it contributes release metrics. <!-- from ADR: ADR-18 -->
- **Canonical qualification method:** a manifest-bound measurement definition whose estimator, confidence method, sample basis, and minimum population are hashed into the method digest required by RG evidence. <!-- from ADR: ADR-19 -->
- **Supply-chain freshness boundary:** the manifest-bound maximum age and time-order check required before a signed vulnerability scan can contribute RG-13. <!-- from ADR: ADR-20 -->
- **Immutable pilot transition:** the lifecycle check that recomputes a pilot revision ID before completion or rollback may consume its fields. <!-- from ADR: ADR-21 -->
- **Provider qualification state:** the canonical allowlist state separating a provider that may participate in shadow contract observation from one qualified for canary. <!-- from ADR: ADR-22 -->
- **Verified sandbox backend:** the executable whose bytes match the execute request's digest and whose open file descriptor is reused for reference-monitor preflight and action launch. <!-- from ADR: ADR-23 -->
- **Claim gate binding:** the content-addressed `gate_trace` on a claim that identifies the gate(s) for which verified evidence is valid; report validation rejects cross-gate reuse. <!-- from ADR: ADR-24 -->
- **Unauthorized tool-class matrix:** the deterministic seeded qualification exercise that submits schema-valid, policy-invalid requests for read, write, execute, network, and secrets and records broker denials without invoking an action backend. <!-- from ADR: ADR-25 -->
- **Extracted-corpus re-baseline:** the explicit provenance state used when the original legacy archive is unavailable; the extracted corpus digest is verified, while archive verification remains false. <!-- from ADR: ADR-26 -->
- **Canonical supply-chain binding:** the release-bound verification that recomputes SBOM, dependency, and lock metadata from the current control bundle before signed RG-13 evidence can contribute metrics. <!-- from ADR: ADR-27 -->
- **Host qualification handoff:** a real local sandbox probe emitted as content-addressed `HQR-*` evidence with `evidence_state=unverified`; it is a diagnostic handoff and cannot authorize RG-09 or GA. <!-- from ADR: ADR-28 -->

## Architectural Decisions
<!-- Decisions with applicability beyond a single feature -->
- Migration compatibility is closed only through schema-bound records and deterministic evaluation; prose equivalence or unit-test presence cannot promote a legacy capability to authoritative status. <!-- from ADR: ADR.md -->
- Missing context, ownership, temporal order, AI governance, or standards binding resolves to `unknown`; compatibility output stays tainted until an explicit approved validation boundary clears it. <!-- from ADR: ADR.md -->
- Standards overlays bind to a pinned canonical baseline digest and remain advisory to VHEATM policy. <!-- from ADR: ADR.md -->
- Completed or failed sandbox outcomes require an `allow` decision, a decision digest, and a matching reference-monitor receipt/action digest; malformed authorization fails closed before backend launch. <!-- from ADR: ADR-8 -->
- Schema validity and semantic identity binding are separate controls at an execution boundary; both must hold before an outcome can become evidence. <!-- from ADR: ADR-8 -->
- Every brokered action adapter must use the shared decision contract; completed provider runs require an allowed, content-valid receipt, while pre-authorization failures remain typed blocked/unknown records. <!-- from ADR: ADR-9 -->
- Runtime policy has one authority: compatibility surfaces may re-export the canonical broker or fail explicitly, but may not implement an alternate authorization engine. <!-- from ADR: ADR-10 -->
- A valid evidence signature does not establish schema validity; direct evaluator APIs and CLI ingestion must share the same schema/format boundary before any metric is trusted. <!-- from ADR: ADR-11 -->
- Critical qualification sample counts must be bounded by the verified private receipt population, while determinism may use repeated evaluations; signed counts and threshold predicates do not establish physical metric domains by themselves. <!-- from ADR: ADR-12 -->
- A content-addressed independent verdict is insufficient without its blind packet and exact randomized item coverage; packet identity, verdict binding, and private-case intersection must all hold before critical qualification metrics are derived. <!-- from ADR: ADR-13 -->
- Content-addressing does not prove authorization; persisted provider runs must retain enough redacted network metadata to recompute receipt request/action binding before pilot completion. <!-- from ADR: ADR-14 -->
- A self-consistent all-pass report is not a canary authorization; canary preparation must re-evaluate the underlying evidence and require exact report equality. <!-- from ADR: ADR-15 -->
- A report ID must bind every identity-bearing field, including schema version and evaluation time; generated reports must pass the same schema boundary as caller-supplied reports. <!-- from ADR: ADR-16 -->
- Semantic formulas consume only the schema-valid profile bound to the canonical manifest version; invalid or mismatched profiles fail closed, and unknown BRS inputs remain unknown. <!-- from ADR: ADR-17 -->
- Content-addressed judge identity and packet binding are insufficient for release evidence; persisted verdicts require a distinct judge signature, while unsigned candidates remain non-qualifying. <!-- from ADR: ADR-18 -->
- RG measurements must resolve to the canonical qualification-method policy before signatures or threshold predicates can expose their values; a signed arbitrary method digest remains ineligible. <!-- from ADR: ADR-19 -->
- RG-13 requires a vulnerability scan to be within the canonical evaluation window and supply-chain, vulnerability, and provenance keys to be different key materials; signed stale or self-issued evidence remains blocked. <!-- from ADR: ADR-20 -->
- Pilot status is not pilot integrity; completion and rollback must revalidate the content-addressed pilot ID before consuming mutable fields. <!-- from ADR: ADR-21 -->
- A broker allow receipt authorizes a network action but does not qualify the provider; allowlist membership is required for runs and `qualified` state is required for canary. <!-- from ADR: ADR-22 -->
- Execute authorization must bind the backend executable digest; per-run rehash plus FD-bound launch is required before a sandbox outcome can claim authorized execution. <!-- from ADR: ADR-23 -->
- Verified gate evidence must bind its claim to every consuming gate; a generic verified claim cannot be reused across unrelated gates without a new content address. <!-- from ADR: ADR-24 -->
- Passing gates cannot use `SRC-*` records as direct evidence; a source must remain lineage for a gate-bound claim or typed artifact. <!-- from ADR: ADR-24 -->
- Legacy archive provenance must declare either a verifiable original archive or an unavailable archive with a content-addressed extracted-corpus root; an absent archive cannot retain a verified archive digest. <!-- from ADR: ADR-26 -->
- A signed supply-chain record must bind to the source-derived current bundle inventory, not only to a self-consistent SBOM digest or declared bundle-root string. <!-- from ADR: ADR-27 -->
- Host hard-stop evidence must come from the real digest-bound sandbox kill path; local probes remain unverified until an independent host authority binds deployment identity, capability, and population. <!-- from ADR: ADR-28 -->

## Domain Gotchas
<!-- Format: - [YYYY-MM] What surprised us | Why it matters -->
- [2026-08] Adding a new evaluation family required updating both `eval-corpus.schema.json` and `qualification-run.schema.json` | A corpus can validate while its generated run is rejected if downstream family enums drift. <!-- from ADR: ADR.md -->
- [2026-08] A typed overlay can look complete while losing a required input such as monitoring coverage | Preserve every decision-bearing input in the output schema and bind external standards by digest. <!-- from ADR: ADR.md -->
- [2026-08] A broker callback can be schema-shaped but still be unrelated to the requested action | Validate request identity, controls, timestamp, decision, receipt identity, and action digest at the reference-monitor boundary. <!-- from ADR: ADR-8 -->
- [2026-08] Pre-broker failure has no authorization receipt to preserve | Emit an explicit fail-closed blocked record rather than inventing a receipt or implying execution. <!-- from ADR: ADR-8 -->
- [2026-08] A provider adapter can confuse malformed authorization with provider outage | Reject before transport and use a typed blocked record with a null receipt only when no authorization event existed. <!-- from ADR: ADR-9 -->
- [2026-08] Tightening a receipt schema breaks synthetic pilot fixtures that bypass the real network request | Make fixtures construct the same canonical request, decision, and receipt chain as production. <!-- from ADR: ADR-9 -->
- [2026-08] A deprecated policy module can remain executable even after a newer broker is adopted | Move legacy code to non-runtime migration text and make the compatibility import surface expose only the canonical broker. <!-- from ADR: ADR-10 -->
- [2026-08] A signed release document can still contain undeclared fields or invalid formats | Validate canonical JSON Schema with a format checker at every evaluator entry point, then leave qualification unknown or RG-13 blocked. <!-- from ADR: ADR-11 -->
- [2026-08] A signed sample count can exceed the private corpus or use an impossible rate value | Bind metric-specific sample basis and domains to the verified receipt before deriving release metrics. <!-- from ADR: ADR-12 -->
- [2026-08] A valid judge verdict can be detached from the packet or claim unpresented private cases | Bind the packet sidecar, exact provider/model/config/order fields, and decision IDs before deriving qualification metrics. <!-- from ADR: ADR-13 -->
- [2026-08] A provider run can be rehashed after receipt tampering | Re-verify the persisted network request, broker semantics, receipt identity/digests, response digest, and completed status at every later evidence boundary. <!-- from ADR: ADR-14 -->
- [2026-08] A release report can be rehashed after changing all gates to pass | Re-run the canonical evaluator with the original evidence and bundle/key bindings before enabling tools. <!-- from ADR: ADR-15 -->
- [2026-08] A release report can be schema-invalid or share an ID across evaluation times | Validate the generated and pilot-bound report, derive the summary, and include timestamp/schema fields in the identity projection. <!-- from ADR: ADR-16 -->
- [2026-08] A policy profile can validate while runtime calculators ignore it | Test a non-default profile override across RPN/FMEA/QBR/BRS and bind the profile version to the manifest before accepting a score. <!-- from ADR: ADR-17 -->
- [2026-08] An isolated judge can emit a valid-looking record that is later replaced | Authenticate persisted verdicts with a dedicated judge key and reject reuse of the evaluator key before deriving qualification metrics. <!-- from ADR: ADR-18 -->
- [2026-08] A signed measurement can name an arbitrary method digest | Bind every RG method digest to the schema-valid, manifest-versioned estimator policy before deriving release metrics. <!-- from ADR: ADR-19 -->
- [2026-08] A signed empty vulnerability scan can be historical or self-issued across every supply-chain role | Enforce canonical freshness and compare public-key bytes at the RG-13 boundary. <!-- from ADR: ADR-20 -->
- [2026-08] A `ready` pilot can be caller-mutated between preparation and completion | Recompute its immutable identity at every lifecycle transition, not only at creation. <!-- from ADR: ADR-21 -->
- [2026-08] A valid provider receipt can hide an unallowlisted or unqualified implementation | Bind provider ID/version to canonical policy and reserve `qualified` for external evidence. <!-- from ADR: ADR-22 -->
- [2026-08] A backend can change after executor construction or between hash and launch | Include its digest in the execute request, revalidate every run, and launch the verified FD; host provenance remains external. <!-- from ADR: ADR-23 -->
- [2026-08] A verified claim can be semantically valid yet unrelated to the gate consuming it | Include `gate_trace` in claim identity and require report evidence to cover the consuming gate. <!-- from ADR: ADR-24 -->
- [2026-08] A trusted source can still be raw, gate-irrelevant material | Reject direct source evidence at the passing-gate boundary and require a typed claim/artifact. <!-- from ADR: ADR-24 -->
- [2026-08] Five broker denials do not prove host hard-stop latency | Keep `unauthorized_block_rate` evidence separate from `hard_stop_p99_seconds`, which remains unknown without a real host-level timing probe. <!-- from ADR: ADR-25 -->
- [2026-08] A registry can carry a plausible legacy archive hash even when the archive is absent | Encode `archive_status` and `source_basis`, bind the extracted corpus digest, and reject an unavailable archive marked verified. <!-- from ADR: ADR-26 -->
- [2026-08] A signed attestation can describe the wrong bytes while remaining internally consistent | Rebuild the canonical bundle at the consuming RG-13 boundary and compare every SBOM/dependency-lock field before deriving supply-chain metrics. <!-- from ADR: ADR-27 -->
- [2026-08] A bwrap binary can exist while the host denies the required namespace | Record preflight as `unavailable` with no hard-stop metric; never reinterpret broker denial or preflight timing as RG-09 p99 evidence. <!-- from ADR: ADR-28 -->
