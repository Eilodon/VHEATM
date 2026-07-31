# Compound feature decomposition

Prevent a feature label from hiding missing subcomponents.

1. Classify each material feature as atomic or compound. Treat authentication flows, retries, rate limits, uploads, pagination, write pipelines, and background jobs as compound unless evidence proves otherwise.
2. For every compound feature, enumerate required components before checking implementation. Include configuration, error handling, observability, rollback, and ownership handoffs where applicable.
3. Verify each component from artifacts. Record `present`, `absent`, or `unknown`; do not use “mostly implemented.”
4. Verify interactions between components, especially error propagation, partial success, idempotency, terminal state, and cleanup behavior.
5. Convert every absent or unresolved mandatory component into a traceable hypothesis or finding with an evidence reference.

Pass `HG-CF` only when every in-scope compound feature has a complete component matrix and the critical interactions have been checked. A passing individual component does not prove the compound feature works.
