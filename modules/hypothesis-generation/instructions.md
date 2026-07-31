# Hypothesis generation and bias control

Generate falsifiable candidates; do not convert heuristics directly into findings.

1. Start from the system, delta, ownership, and compound-feature maps. Run a differential premortem: identify how the intended behavior could fail, survive review, or cross a boundary unnoticed.
2. Apply the core generation lenses and only the specialist lenses justified by the canonical context. Record every invoked lens and an explicit skip reason for every expected but inapplicable lens.
3. Create hypotheses that name the suspected mechanism, affected artifact or boundary, consequence, evidence already observed, and a concrete way to disprove the claim.
4. Prioritize using the canonical risk model without fabricating precision. Separate direct observations, hypotheses, claims, and confirmed findings.
5. Run the bias checks for anchoring, confirmation, availability, automation, self-audit, and organizational capture. Add counter-hypotheses where the evidence may support a benign explanation.

Pass `HG-G` only when the output is actionable, traceable to source lenses, includes bias records, and gives high-priority hypotheses a feasible verification path. Volume is not quality; unsupported speculation remains low-confidence or `unknown`.
