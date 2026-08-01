<!-- mcp-name: io.github.vheatm/vheatm-control -->
# VHEATM

VHEATM is an AI-executable audit orchestration framework being rebuilt as a **machine-validated, AI-native control plane**.

The V17 line moves invariants, activation rules, evidence contracts, runtime boundaries, audit completion decisions, and instruction routing out of prose-only instructions and into executable artifacts.

## Implemented slices

### P0 — control-plane foundation

- canonical manifest for 8 phases and 22 hard gates;
- JSON Schema 2020-12 contracts;
- Pydantic and cross-file validation;
- tri-state declarations (`yes`, `no`, `unknown`);
- deny-by-default trust, taint, tool, sandbox, and egress policy;
- coding-agent contract and CI.

### P1 — deterministic planning and provenance

- safe activation DSL parsed without Python `eval` or `exec`;
- strong-Kleene three-valued logic, where unresolved security context remains `unknown`;
- deterministic gate activation plans with machine-readable reasons;
- context-schema reference validation that catches misspelled identifiers in CI;
- content-addressed source and claim IDs;
- provenance registry with cross-reference checks.

### P1.5 — enforcement closure

- replayable, append-only audit lifecycle state machine;
- semantic report validation across manifest, plan, all 22 gate results, findings, provenance, lifecycle, and attestation;
- passing gates require verified evidence references;
- mandatory and verified findings cannot bypass claim/source lineage;
- signed, scoped, expiring, single-use approval tokens for restricted tool classes;
- deny-before-execution policy guard for execute, write, network, and secret requests;
- atomic persistent provenance with ID recomputation, byte-digest verification, append-only updates, and optimistic concurrency protection;
- expiring attestations bound to canonical manifest, runtime policy, and report subject digests.

### P2-A — module contracts and deterministic routing

- compact root `SKILL.md` router capped at 350 lines;
- machine contracts for modules, the module registry, and module-selection output;
- digest chain from registry to module document to instruction file;
- deterministic routing from the complete gate plan, never from keyword matching or agent intuition;
- dependency closure, cycle detection, symmetric conflicts, phase ordering, and hard disclosure budgets;
- unknown gates and unresolved modules remain blocking;
- progressive disclosure keeps instruction bodies out of context until their modules are selected;
- pilot migration for context validation, architecture smells, auditor defense, and execution fidelity.

The evaluator decides only whether a gate is **active**, **inactive**, or **unknown**. The router decides which validated instruction modules are required. Neither component manufactures gate pass/fail results; evidence-bearing results are checked separately by `vheatm-validate-report`.

## Quick start

### From source (contributors)

```bash
python -m pip install -e '.[dev]'
vheatm-validate --root .
vheatm-evaluate --root . --context examples/context-low-risk.yaml > gate-plan.json
vheatm-route --root . --plan gate-plan.json > module-selection.json
vheatm-validate-report --root . --report path/to/report.json
pytest
```

### As a CLI (no clone required)

```bash
uvx vheatm-control vheatm-validate --root .
# or: pip install vheatm-control
```

### As an MCP server (Claude Code, Cursor, Windsurf, Codex, Gemini CLI, ...)

FastMCP 4.0 is currently a pre-release; `--prerelease=allow` is required until
it reaches a stable release. Add to your client's MCP config:

```json
{
  "mcpServers": {
    "vheatm": {
      "command": "uvx",
      "args": ["--prerelease=allow", "--from", "vheatm-control[mcp]", "vheatm-mcp"]
    }
  }
}
```

This exposes `vheatm_validate`, `vheatm_evaluate`, `vheatm_route`, and
`vheatm_validate_report` as MCP tools — the agent calls them directly instead
of shelling out to the CLI.

### As a Claude Code plugin

```
/plugin marketplace add vheatm/VHEATM
/plugin install vheatm@VHEATM
```

### As a container

```bash
docker run --rm -v "$PWD:/workspace:ro" ghcr.io/vheatm/vheatm-control vheatm-validate --root /workspace
```

`vheatm-evaluate` and `vheatm-route` exit codes:

- `0`: the plan or selection is resolved;
- `1`: invalid input, malformed artifact, or runtime error;
- `2`: unknown activation, unresolved module, conflict, or disclosure-budget violation blocks completion.

## Source-of-truth order

1. `manifests/vheatm-v17.yaml` — framework inventory and activation expressions.
2. `policies/runtime-boundaries.yaml` — runtime trust and safety policy.
3. `schemas/` — machine contracts for context, plans, modules, reports, lifecycle, provenance, approvals, tool requests, and policy decisions.
4. `modules/registry.yaml` and `modules/*/module.yaml` — digest-bound runtime-authoritative instruction modules.
5. `SKILL.md` — compact execution router; it cannot override the artifacts above.
6. `src/vheatm_control/` — executable validation, planning, routing, enforcement, lifecycle, and provenance.
7. `tests/` — invariants and regression behavior.
8. `docs/` — explanation; never overrides executable artifacts.

The policy engine is a decision-and-guard layer. Platform adapters must still supply the concrete sandbox, filesystem isolation, and network transport required by an allowed decision.

The module registry currently uses `pilot` coverage. Unmigrated v16.1.1 prose remains non-authoritative until converted into digest-bound modules with declared inputs, outputs, selection, evidence, failure behavior, provenance expectations, runtime needs, and tests.
