# Context contract

Validate scope, mode, target tier, declarations, evidence currency, and ownership before deeper audit work.

Produce a context decision that names missing or ambiguous fields. Security-relevant ambiguity remains `unknown` and blocks progression. Do not infer critical declarations from filenames, repository popularity, or model confidence.

Anchor every accepted declaration to a source or explicit human statement. Record scope exclusions and their owner. Pass `HG-P` only when the context schema is valid and every required unknown has been resolved or explicitly escalated.
