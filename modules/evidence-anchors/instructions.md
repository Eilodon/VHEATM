# Evidence anchors and claim disposition

Confidence, repetition, and model agreement are not evidence.

1. Build an evidence matrix for high-priority hypotheses and every mandatory claim. Link direct source or claim identifiers, freshness, the verification method, and the expected falsifying observation.
2. Read the cited artifact rather than relying on a search snippet, summary, generated explanation, or stale report. Preserve taint until an approved validation step clears it.
3. Use static evidence for the mechanism and dynamic evidence where behavior must be demonstrated. When execution is unavailable, record the denied tool or missing environment and downgrade the result to `unknown` or `unavailable`.
4. Re-check claims that originated from automation or pattern matching. A plausible explanation cannot replace a file, test, trace, log, configuration, or authoritative document anchor.
5. Disposition each required claim as confirmed, contradicted, unavailable, or unknown, with the supporting lineage.

Pass `HG-E` only when all required hypotheses and mandatory claims have valid evidence anchors or an explicit blocking disposition. Never convert “likely,” “common pattern,” or “high confidence” into a verified claim.
