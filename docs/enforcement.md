# Enforcement closure

P1.5 closes the gap between declaring controls and enforcing them.

## Audit lifecycle

Audits advance through an explicit append-only state machine:

`created → context_validated → planned → running → blocked | partial | complete → attested`

Blocked and partial audits may return to running. No other transition is valid. Every transition records an actor, reason, timestamp, sequence and evidence references.

## Report integrity

`vheatm-validate-report` validates both JSON Schema and cross-document semantics. A final report must bind to the canonical manifest and runtime policy, contain an exact 22-gate activation plan and result set, use `not_applicable` only for inactive gates, carry a valid provenance registry, and derive its lifecycle status rather than trusting caller-supplied completion claims.

Verified or mandatory evidence must reference content-addressed claims and sources. Passing gates require evidence references. Attestations expire and bind to canonical manifest, runtime policy, and report subject digests.

## Runtime policy decisions

Restricted tool requests are denied before their callback can execute unless all class-specific controls pass. Execute, write, network and secret requests require a signed, scoped, expiring, single-use approval token. Read requests remain limited to workspace-bound access without secret expansion.

The current engine is a decision and guard layer. Platform adapters remain responsible for providing the actual sandbox, filesystem isolation and network transport named by an allowed decision.

## Provenance persistence

The registry recomputes source and claim IDs instead of trusting caller-supplied identifiers. File persistence is atomic and append-only, and updates require the previous root hash to prevent lost updates. Where source bytes are available, their digest and length are verified before use.
