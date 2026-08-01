# Compound Wiki

Auto-populated by: knowledge-compound skill (run after every adr-commit)

<!-- ENTRIES BELOW — do not delete; each entry is a cycle's extracted learnings -->

---
date: 2026-08-01
sprint: v17-kernel-closure
adr: ADR-7 in docs/superskills/DPS_v5/ADR.md
modules: [MOD-EVIDENCE-ANCHORS, MOD-EXECUTION-FIDELITY, MOD-CONTEXT-CONTRACT, MOD-SYSTEM-MAPS, MOD-ADVERSARIAL-PASS, MOD-CLOSURE-METRICS]
---

## Cycle: semantic-migration-capability-contracts

### New Domain Terms Added to CONTEXT.md
- Candidate overlay: added ✅
- Delta-only assurance: added ✅
- Semantic migration capability: added ✅

### Bug Patterns
- Missing downstream schema consumer for a new eval family: observed and fixed in both corpus and run schemas; no PATTERN-DEBT entry (first occurrence).
- Dropped decision-bearing overlay input: observed and fixed by retaining monitoring coverage and the pinned NIST baseline digest; no PATTERN-DEBT entry (first occurrence).

### Gotchas Captured
- Public or candidate migration output is not release evidence: added to CONTEXT.md Domain Gotchas ✅
- Corpus/run family enums must evolve together: added to CONTEXT.md Domain Gotchas ✅

### Architectural Decisions Promoted
- Candidate overlays stay outside authority and standards bindings are digest-pinned: added to CONTEXT.md Architectural Decisions ✅

---
date: 2026-08-01
sprint: v17-kernel-closure
adr: ADR-8 in docs/superskills/DPS_v5/ADR.md
modules: [MOD-AGENT-SECURITY, MOD-EXECUTION-FIDELITY, MOD-TRANSFORMATION-VERIFICATION, MOD-FIX-VERIFICATION]
---

## Cycle: sandbox-authorization-action-binding

### New Domain Terms Added to CONTEXT.md
- Authorization-to-action binding: added ✅
- Reference-monitor receipt: added ✅

### Bug Patterns
- Sandbox outcome lacked authorization-to-action proof: observed and fixed at the reference-monitor boundary; no PATTERN-DEBT entry (first occurrence).
- Schema-shaped broker decision could be semantically unrelated to the request: observed and fixed with request/decision/receipt/action binding; no PATTERN-DEBT entry (first occurrence).

### Gotchas Captured
- Schema validity is not semantic identity: added to CONTEXT.md Domain Gotchas ✅
- Pre-broker failure must remain blocked without a fabricated receipt: added to CONTEXT.md Domain Gotchas ✅

### Architectural Decisions Promoted
- Completed/failed sandbox outcomes require an allow decision plus content-addressed receipt/action binding: added to CONTEXT.md Architectural Decisions ✅
- Malformed authorization fails closed before backend launch: added to CONTEXT.md Architectural Decisions ✅

---
