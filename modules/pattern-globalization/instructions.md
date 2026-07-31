# Pattern globalization

A confirmed instance creates an obligation to search for the pattern elsewhere.

1. Derive a pattern signature from the confirmed mechanism, not merely the original function name or error text. Include language-idiomatic and divergent-implementation forms when relevant.
2. Define the search scope and exclusions. Scope must cover equivalent entry points, workers, adapters, factories, and ownership boundaries where the same mechanism could recur.
3. Prefer AST, symbol, dependency, or data-flow analysis when structure matters. Use text search only when it can faithfully represent the signature, and record its limitations.
4. Inspect every match before classifying it. A match is a candidate, not a finding. Record true instances, benign variants, unresolved candidates, and zero-result evidence.
5. Create cascade hypotheses or findings for additional instances and update the reusable bug-class record when the pattern is generalizable.

Pass `HG-PG` only when every confirmed finding has a documented search record or an explicit reason globalization is impossible. Fixing one occurrence while leaving equivalent code unsearched is a gate failure.
