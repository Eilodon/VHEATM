# System and boundary maps

Establish what exists, what is changing, who owns each boundary, and where evidence is incomplete.

1. Map in-scope components, entry points, stores, queues, external services, and principal data flows. Every material node or edge needs a source reference.
2. Produce a delta map that separates observed current behavior, intended change, unchanged dependencies, and explicitly excluded scope. Do not infer a change from ticket wording alone.
3. Record ownership for components, operational handoffs, and trust boundaries. When ownership is unknown, preserve `unknown` and name the escalation path.
4. Mark stale diagrams or contradictory sources as limitations rather than silently choosing the convenient version.
5. Seed unresolved boundaries as hypotheses for later modules; a map is not evidence that the boundary is safe.

Pass `HG-V` only when the selected scope can be navigated from the maps, material deltas have evidence anchors, and ownership or boundary uncertainty is either resolved or explicitly blocking.
