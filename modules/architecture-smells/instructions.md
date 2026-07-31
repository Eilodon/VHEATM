# Architecture smell scan

Inspect system boundaries, dependency direction, state ownership, failure domains, change coupling, and operational bottlenecks. Use structural evidence where available; prose names and comments are only leads.

For each plausible smell, record the concrete anchor, affected boundary, consequence, and a falsifiable follow-up hypothesis. Do not convert a heuristic match directly into a finding. Mark unavailable evidence and preserve uncertainty.

Pass `HG-AS` only when the scan produced evidence-bearing hypotheses or a justified no-signal result for every in-scope architecture surface.
