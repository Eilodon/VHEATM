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
