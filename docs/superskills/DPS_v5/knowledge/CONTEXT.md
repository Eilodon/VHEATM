# CONTEXT.md — Domain Knowledge
<!-- Version: 7 — populate via domain-alignment skill, then keep updated via knowledge-compound -->

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
