# CONTEXT.md — Domain Knowledge
<!-- Version: 4 — populate via domain-alignment skill, then keep updated via knowledge-compound -->

## Ubiquitous Language
<!-- Add domain terms where the word means something more specific than common usage -->
- **Candidate overlay:** a schema-valid, content-addressed planning or migration record whose `authority_eligible` value is permanently `false`; it cannot mint a gate, finding, certification, or release claim. <!-- from ADR: ADR.md -->
- **Delta-only assurance:** an assurance mapping that records named SAMM/SSDF/BSIMM improvement deltas without producing a maturity score or certification. <!-- from ADR: ADR.md -->
- **Semantic migration capability:** an executable contract that maps a preserved legacy reference to typed inputs, outputs, failure semantics, and evidence/authority boundaries. <!-- from ADR: ADR.md -->
- **Authorization-to-action binding:** a content-addressed relationship proving that the policy decision and tool receipt authorize the exact action represented by an execution record. <!-- from ADR: ADR-8 -->
- **Reference-monitor receipt:** the schema-valid, content-addressed authorization record emitted at the sandbox boundary before a backend action may claim execution. <!-- from ADR: ADR-8 -->
- **Shared decision contract:** the canonical semantic checks for request version, identity, decision, controls, time, and approval binding applied before any brokered adapter emits an action receipt. <!-- from ADR: ADR-9 -->
- **Typed authorization failure:** a blocked or unknown adapter record representing authorization failure without inventing a deny receipt or claiming transport/execution occurred. <!-- from ADR: ADR-9 -->

## Architectural Decisions
<!-- Decisions with applicability beyond a single feature -->
- Migration compatibility is closed only through schema-bound records and deterministic evaluation; prose equivalence or unit-test presence cannot promote a legacy capability to authoritative status. <!-- from ADR: ADR.md -->
- Missing context, ownership, temporal order, AI governance, or standards binding resolves to `unknown`; compatibility output stays tainted until an explicit approved validation boundary clears it. <!-- from ADR: ADR.md -->
- Standards overlays bind to a pinned canonical baseline digest and remain advisory to VHEATM policy. <!-- from ADR: ADR.md -->
- Completed or failed sandbox outcomes require an `allow` decision, a decision digest, and a matching reference-monitor receipt/action digest; malformed authorization fails closed before backend launch. <!-- from ADR: ADR-8 -->
- Schema validity and semantic identity binding are separate controls at an execution boundary; both must hold before an outcome can become evidence. <!-- from ADR: ADR-8 -->
- Every brokered action adapter must use the shared decision contract; completed provider runs require an allowed, content-valid receipt, while pre-authorization failures remain typed blocked/unknown records. <!-- from ADR: ADR-9 -->

## Domain Gotchas
<!-- Format: - [YYYY-MM] What surprised us | Why it matters -->
- [2026-08] Adding a new evaluation family required updating both `eval-corpus.schema.json` and `qualification-run.schema.json` | A corpus can validate while its generated run is rejected if downstream family enums drift. <!-- from ADR: ADR.md -->
- [2026-08] A typed overlay can look complete while losing a required input such as monitoring coverage | Preserve every decision-bearing input in the output schema and bind external standards by digest. <!-- from ADR: ADR.md -->
- [2026-08] A broker callback can be schema-shaped but still be unrelated to the requested action | Validate request identity, controls, timestamp, decision, receipt identity, and action digest at the reference-monitor boundary. <!-- from ADR: ADR-8 -->
- [2026-08] Pre-broker failure has no authorization receipt to preserve | Emit an explicit fail-closed blocked record rather than inventing a receipt or implying execution. <!-- from ADR: ADR-8 -->
- [2026-08] A provider adapter can confuse malformed authorization with provider outage | Reject before transport and use a typed blocked record with a null receipt only when no authorization event existed. <!-- from ADR: ADR-9 -->
- [2026-08] Tightening a receipt schema breaks synthetic pilot fixtures that bypass the real network request | Make fixtures construct the same canonical request, decision, and receipt chain as production. <!-- from ADR: ADR-9 -->
