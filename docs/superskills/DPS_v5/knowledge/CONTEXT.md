# CONTEXT.md — Domain Knowledge
<!-- Version: 2 — populate via domain-alignment skill, then keep updated via knowledge-compound -->

## Ubiquitous Language
<!-- Add domain terms where the word means something more specific than common usage -->
- **Candidate overlay:** a schema-valid, content-addressed planning or migration record whose `authority_eligible` value is permanently `false`; it cannot mint a gate, finding, certification, or release claim. <!-- from ADR: ADR.md -->
- **Delta-only assurance:** an assurance mapping that records named SAMM/SSDF/BSIMM improvement deltas without producing a maturity score or certification. <!-- from ADR: ADR.md -->
- **Semantic migration capability:** an executable contract that maps a preserved legacy reference to typed inputs, outputs, failure semantics, and evidence/authority boundaries. <!-- from ADR: ADR.md -->

## Architectural Decisions
<!-- Decisions with applicability beyond a single feature -->
- Migration compatibility is closed only through schema-bound records and deterministic evaluation; prose equivalence or unit-test presence cannot promote a legacy capability to authoritative status. <!-- from ADR: ADR.md -->
- Missing context, ownership, temporal order, AI governance, or standards binding resolves to `unknown`; compatibility output stays tainted until an explicit approved validation boundary clears it. <!-- from ADR: ADR.md -->
- Standards overlays bind to a pinned canonical baseline digest and remain advisory to VHEATM policy. <!-- from ADR: ADR.md -->

## Domain Gotchas
<!-- Format: - [YYYY-MM] What surprised us | Why it matters -->
- [2026-08] Adding a new evaluation family required updating both `eval-corpus.schema.json` and `qualification-run.schema.json` | A corpus can validate while its generated run is rejected if downstream family enums drift. <!-- from ADR: ADR.md -->
- [2026-08] A typed overlay can look complete while losing a required input such as monitoring coverage | Preserve every decision-bearing input in the output schema and bind external standards by digest. <!-- from ADR: ADR.md -->
