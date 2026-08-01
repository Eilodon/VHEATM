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
date: 2026-08-01
sprint: v17-kernel-closure
adr: ADR-9 in docs/superskills/DPS_v5/ADR.md
modules: [MOD-AGENT-SECURITY, MOD-EXECUTION-FIDELITY, MOD-TRANSFORMATION-VERIFICATION, MOD-FIX-VERIFICATION]
---

## Cycle: shared-provider-authorization-receipts

### New Domain Terms Added to CONTEXT.md
- Shared decision contract: added ✅
- Typed authorization failure: added ✅

### Bug Patterns
- Shared receipt builder accepted incomplete broker decisions: observed and fixed with one semantic guard used by sandbox/provider boundaries; no PATTERN-DEBT entry (first occurrence).
- Provider authorization failure could escape as an untyped exception or transport path: observed and fixed with a blocked run and null receipt; no PATTERN-DEBT entry (first occurrence).

### Gotchas Captured
- Null receipt means no authorization event, not deny evidence: added to CONTEXT.md Domain Gotchas ✅
- Synthetic fixtures must preserve the complete request→decision→receipt chain: added to CONTEXT.md Domain Gotchas ✅

### Architectural Decisions Promoted
- All brokered action adapters share semantic decision validation: added to CONTEXT.md Architectural Decisions ✅
- Completed provider outcomes require an allowed content-valid network receipt: added to CONTEXT.md Architectural Decisions ✅

---
date: 2026-08-01
sprint: v17-kernel-closure
adr: ADR-10 in docs/superskills/DPS_v5/ADR.md
modules: [MOD-AGENT-SECURITY, MOD-ARCHITECTURE-DECISIONS, MOD-EXECUTION-FIDELITY, MOD-FIX-VERIFICATION]
---

## Cycle: retire-duplicate-policy-authority

### New Domain Terms Added to CONTEXT.md
- Non-authoritative migration archive: added ✅

### Bug Patterns
- Duplicate executable policy authority remained importable: observed and fixed by canonical broker shim plus non-runtime archive; no PATTERN-DEBT entry (first occurrence).

### Gotchas Captured
- Deprecation comments do not remove an executable bypass: added to CONTEXT.md Domain Gotchas ✅

### Architectural Decisions Promoted
- Compatibility surfaces may not implement a second authorization engine: added to CONTEXT.md Architectural Decisions ✅

---
date: 2026-08-01
sprint: v17-kernel-closure
adr: ADR-11 in docs/superskills/DPS_v5/ADR.md
modules: [MOD-AGENT-SECURITY, MOD-EXECUTION-FIDELITY, MOD-TRANSFORMATION-VERIFICATION, MOD-FIX-VERIFICATION]
---

## Cycle: evaluator-evidence-schema-boundary

### New Domain Terms Added to CONTEXT.md
- Evaluator evidence boundary: added ✅

### Bug Patterns
- Signed-but-schema-invalid release evidence bypassed direct evaluator validation: observed and fixed at the shared boundary; no PATTERN-DEBT entry (first occurrence).

### Gotchas Captured
- A valid signature is not schema validity: added to CONTEXT.md Domain Gotchas ✅
- Direct library APIs can bypass CLI-only validation: added to CONTEXT.md Domain Gotchas ✅

### Architectural Decisions Promoted
- Every evaluator entry point must schema/format validate before cryptographic metric derivation: added to CONTEXT.md Architectural Decisions ✅

---
date: 2026-08-01
sprint: v17-kernel-closure
adr: ADR-12 in docs/superskills/DPS_v5/ADR.md
modules: [MOD-EVIDENCE-ANCHORS, MOD-CLOSURE-METRICS, MOD-EXECUTION-FIDELITY, MOD-FIX-VERIFICATION]
---

## Cycle: qualification-population-and-domain-binding

### New Domain Terms Added to CONTEXT.md
- Qualification sample basis: added ✅

### Bug Patterns
- Signed sample count was not bound to the private corpus population: observed and fixed with receipt case-count enforcement; no PATTERN-DEBT entry (first occurrence).
- Threshold predicates accepted physically impossible bounded metric values: observed and fixed with canonical metric domains; no PATTERN-DEBT entry (first occurrence).

### Gotchas Captured
- A signed count is not population coverage: added to CONTEXT.md Domain Gotchas ✅
- Determinism and critical case trials require different sample bases: added to CONTEXT.md Architectural Decisions ✅

### Architectural Decisions Promoted
- Critical qualification metrics must reference the verified private receipt and remain within its population; domain bounds are enforced before RG derivation: added to CONTEXT.md ✅

---
date: 2026-08-01
sprint: v17-kernel-closure
adr: ADR-16 in docs/superskills/DPS_v5/ADR.md
modules: [MOD-CLOSURE-METRICS, MOD-EXECUTION-FIDELITY, MOD-FIX-VERIFICATION]
---

## Cycle: release-report-identity-boundary

### New Domain Terms Added to CONTEXT.md
- Release-report identity boundary: added ✅

### Bug Patterns
- The evaluator and pilot trusted a report projection that omitted schema/timestamp identity and did not enforce the report schema at every boundary: observed and fixed; no PATTERN-DEBT entry (first occurrence).

### Gotchas Captured
- Generated reports need schema validation just like supplied evidence: added ✅
- Duplicate evidence inputs must not make the output envelope invalid: added ✅

### Architectural Decisions Promoted
- Release reports require canonical schema, ordered gate inventory, derived summary, and identity binding at evaluator and pilot boundaries: added to CONTEXT.md ✅

---
date: 2026-08-01
sprint: v17-kernel-closure
adr: ADR-13 in docs/superskills/DPS_v5/ADR.md
modules: [MOD-EVIDENCE-ANCHORS, MOD-CLOSURE-METRICS, MOD-EXECUTION-FIDELITY, MOD-FIX-VERIFICATION]
---

## Cycle: judge-packet-evidence-binding

### New Domain Terms Added to CONTEXT.md
- Blind judge packet: added ✅
- Independent judge coverage: added ✅

### Bug Patterns
- A signed verdict could be detached from its blind packet or cover unpresented private cases: observed and fixed at the evaluator trust boundary; no PATTERN-DEBT entry (first occurrence).

### Gotchas Captured
- A verdict identity does not prove what context or cases were judged: added to CONTEXT.md Domain Gotchas ✅
- Packet sidecars are part of immutable release provenance: added to CONTEXT.md Architectural Decisions ✅

### Architectural Decisions Promoted
- Qualification metrics require exact packet/verdict binding and private-case intersection coverage: added to CONTEXT.md ✅

---
date: 2026-08-01
sprint: v17-kernel-closure
adr: ADR-14 in docs/superskills/DPS_v5/ADR.md
modules: [MOD-AGENT-SECURITY, MOD-EVIDENCE-ANCHORS, MOD-EXECUTION-FIDELITY, MOD-FIX-VERIFICATION]
---

## Cycle: pilot-receipt-chain-revalidation

### New Domain Terms Added to CONTEXT.md
- Persisted provider receipt chain: added ✅

### Bug Patterns
- Pilot trusted a re-content-addressed provider run without rechecking its embedded receipt authorization: observed and fixed at the pilot boundary; no PATTERN-DEBT entry (first occurrence).

### Gotchas Captured
- Content-addressing does not prove authorization: added to CONTEXT.md Domain Gotchas ✅
- Persisted provider records need redacted request material for later verification: added to CONTEXT.md Architectural Decisions ✅

### Architectural Decisions Promoted
- Pilot completion must re-verify provider request/receipt/response semantics at the persisted evidence boundary: added to CONTEXT.md ✅

---
date: 2026-08-01
sprint: v17-kernel-closure
adr: ADR-15 in docs/superskills/DPS_v5/ADR.md
modules: [MOD-AGENT-SECURITY, MOD-CLOSURE-METRICS, MOD-EXECUTION-FIDELITY, MOD-FIX-VERIFICATION]
---

## Cycle: canary-evidence-revalidation

### New Domain Terms Added to CONTEXT.md
- Canary evidence revalidation: added ✅

### Bug Patterns
- Canary trusted a self-rehashed all-pass report without re-evaluating its underlying evidence: observed and fixed at the canary preparation boundary; no PATTERN-DEBT entry (first occurrence).

### Gotchas Captured
- Report identity is not evidence attestation: added to CONTEXT.md Domain Gotchas ✅
- Tool-enabled rollout requires pre-activation revalidation: added to CONTEXT.md Architectural Decisions ✅

### Architectural Decisions Promoted
- Canary preparation must reuse the canonical evaluator and compare the complete report before enabling tools: added to CONTEXT.md ✅

---
date: 2026-08-01
sprint: v17-kernel-closure
adr: ADR-17 in docs/superskills/DPS_v5/ADR.md
modules: [MOD-ARCHITECTURE-DECISIONS, MOD-TRANSFORMATION-VERIFICATION, MOD-FIX-VERIFICATION]
---

## Cycle: canonical-semantic-profile-binding

### New Domain Terms Added to CONTEXT.md
- Canonical semantic profile binding: added ✅

### Bug Patterns
- Runtime calculators duplicated canonical semantic thresholds and mappings: observed and fixed by loading the schema-valid profile at every calculation boundary; no PATTERN-DEBT entry (first occurrence).

### Gotchas Captured
- A policy YAML can be valid while its consumers silently ignore it: added to CONTEXT.md Domain Gotchas ✅

### Architectural Decisions Promoted
- RPN, FMEA→QBR, QBR, and BRS calculations require a profile/schema/manifest binding and fail closed on invalid or mismatched policy: added to CONTEXT.md Architectural Decisions ✅

---
date: 2026-08-01
sprint: v17-kernel-closure
adr: ADR-18 in docs/superskills/DPS_v5/ADR.md
modules: [MOD-AGENT-SECURITY, MOD-ARCHITECTURE-DECISIONS, MOD-TRANSFORMATION-VERIFICATION, MOD-FIX-VERIFICATION]
---

## Cycle: signed-independent-judge-verdict-boundary

### New Domain Terms Added to CONTEXT.md
- Signed independent verdict: added ✅

### Bug Patterns
- A content-addressed judge verdict could be caller-created and accepted as independent evidence: observed and fixed by a distinct Ed25519 judge signature at the release boundary; no PATTERN-DEBT entry (first occurrence).

### Gotchas Captured
- Process isolation does not authenticate a persisted record after process exit: added to CONTEXT.md Domain Gotchas ✅

### Architectural Decisions Promoted
- Qualification metrics require a signed verdict from a judge key distinct from the evaluator key; unsigned candidates remain non-qualifying: added to CONTEXT.md ✅

---
