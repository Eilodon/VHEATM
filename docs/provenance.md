# Provenance registry

The provenance layer prevents an agent from presenting unanchored claims as verified evidence or silently changing a claim while preserving its identifier.

## Source records

A source ID is derived from:

- source type;
- stable locator;
- SHA-256 content digest.

Capture time, trust zone, taint state, and metadata do not redefine source identity. Records are immutable once inserted into a registry.

## Claim records

A claim ID is derived from normalized claim text, epistemic status, evidence kind, and sorted source references. Confidence is intentionally excluded from identity, but changing it on an existing claim record is rejected as mutation. A revised assessment should be recorded as a new registry event in a later lifecycle slice.

Rules enforced in code and schema:

- `unknown` claims require `confidence: null`;
- `verified` claims require at least one source reference;
- source references must exist before a claim enters the registry;
- registry insertion is idempotent only when the complete record is identical.

## Finding and report integration

Finding evidence may carry `claim_id` and `source_refs`. Audit reports may embed an activation plan and a provenance registry. These links are optional in P1 for backward compatibility; a later migration slice can make them mandatory by target tier.
