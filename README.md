# VHEATM

VHEATM is an AI-executable audit orchestration framework being rebuilt as a **machine-validated, AI-native control plane**.

This repository is the V17 stabilization line derived from the VHEATM v16.1.1 audit. The first milestone moves invariants, gates, schemas, versions, and runtime boundaries out of prose-only instructions and into executable artifacts.

## P0 foundation

The current branch establishes:

- one canonical manifest for phases, gates, version, defaults, and activation rules;
- JSON Schema 2020-12 contracts for the manifest, runtime policy, findings, and audit reports;
- Pydantic models plus cross-file invariant checks;
- fail-safe tri-state declarations (`yes`, `no`, `unknown`) instead of fail-open defaults;
- explicit trust, taint, tool, sandbox, and egress boundaries;
- tests and GitHub Actions CI;
- an `AGENTS.md` contract optimized for coding agents.

## Quick start

```bash
python -m pip install -e '.[dev]'
vheatm-validate --root .
pytest
```

## Source-of-truth order

1. `manifests/vheatm-v17.yaml` — canonical framework inventory and activation semantics.
2. `policies/runtime-boundaries.yaml` — runtime trust and safety policy.
3. `schemas/` — machine contracts.
4. `src/vheatm_control/` — executable validation.
5. `docs/` — human explanation; never overrides executable artifacts.

The v16.1.1 prose corpus is intentionally not treated as authoritative. It will be migrated module-by-module only after its claims pass the V17 manifest, schema, and policy checks.
