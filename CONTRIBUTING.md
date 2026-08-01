# Contributing to VHEATM

VHEATM treats prose as non-authoritative. Before contributing, read the
source-of-truth order in [README.md](README.md) and the invariants in
[AGENTS.md](AGENTS.md) — both apply to human and AI contributors equally.

## Setup

```bash
python -m pip install -e '.[dev]'
vheatm-validate --root .
pytest
```

## Before opening a pull request

```bash
vheatm-validate --root .
pytest
```

If your change affects activation or module routing, also run:

```bash
vheatm-evaluate --root . --context examples/context-low-risk.yaml > /tmp/vheatm-plan.json
vheatm-route --root . --plan /tmp/vheatm-plan.json
```

If you changed a module's instruction file or the registry, run
`vheatm-doctor --fix --root .` and commit the corrected digests as part of the
same change — a digest mismatch is a validation failure, not a warning.

## Expectations

- Add tests for every invariant change; never hand-patch a derived count or
  summary.
- Keep pull requests small and reviewable — stacked PRs over one large diff.
- Do not import legacy (pre-V17) prose into the runtime path; migrate it
  through a module contract instead.
- Do not add autonomous write or execution behavior without a policy change,
  tests, rollback behavior, and explicit review.

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md) — do not open a public issue for a security
report.
