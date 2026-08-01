# Conservative Python linkage

`vheatm-link-python` consumes a verified `vheatm-probe-python` bundle and derives an import graph, lexical binding graph, and conservative call candidates. It never imports or executes target modules and never rereads source files.

## Resolution boundary

The linker maps files to modules using explicit, non-overlapping `--source-root` values. It derives structural targets for absolute and relative imports, top-level symbols, nested definitions, and module aliases present in the verified probe.

P3-D adds lexical resolution for:

- module, class, function, async-function, lambda, and comprehension scopes;
- parameters, imports, definitions, assignments, annotations, deletes, and control-dependent binding events;
- Python's function-local rule, including a binding that appears after a call;
- `global` and `nonlocal` declarations;
- direct nested definitions and stable enclosing-scope bindings;
- simple aliases such as `runner = imported_run` and bounded alias chains;
- calls inside functions and methods when the binding evidence is unique.

A `candidate` remains a structural binding claim, not runtime reachability. The linker does not prove that a function was invoked, that a branch executed, or that an object attribute has a particular runtime type.

## Conservative rebinding rules

The current scope is evaluated sequentially: the latest visible unconditional binding may dominate earlier bindings. A parameter or a later function-local assignment shadows outer names according to Python's compile-time local-name rule.

An enclosing function or module binding is elevated only when the relevant name has one stable event. Multiple enclosing events remain `ambiguous` with `enclosing_rebinding_not_proven`, because invocation order and path dominance are outside this slice.

Control-dependent imports, definitions, and assignments remain `ambiguous`. Dynamic right-hand sides, augmented assignments, loop/with/except targets, pattern captures, deletes, annotations without values, and unsupported attribute flows remain `unresolved`. Simple alias chains retain a `binding_chain` so each hop is reviewable and content-addressed.

Representative reasons include:

- `unique_lexical_binding` and `unique_alias_binding`;
- `parameter_binding` and `local_before_binding`;
- `control_dependent_rebinding` and `enclosing_rebinding_not_proven`;
- `dynamic_rebinding`, `deleted_binding`, and `annotation_only_binding`;
- `module_not_callable` and `attribute_target_not_modeled`;
- the existing import, wildcard, collision, external, and dynamic-callee outcomes.

## Evidence records

The linkage bundle now contains normalized `scopes` and resolved `bindings` in addition to modules, import edges, and calls. Every binding records its declaration mode, syntactic value when available, control context, state, reason, candidate targets, and binding chain. Summary counts include candidate, ambiguous, and unresolved bindings plus the number of names rebound within one scope.

## CLI

```bash
vheatm-probe-python --root . --path src --captured-at 2026-08-01T03:00:00Z > probe.json
vheatm-link-python \
  --probe probe.json \
  --source-root src \
  --generated-at 2026-08-01T03:00:00Z > linkage.json
```

Exit code `0` means the graph completed. Exit code `2` means the input probe or module mapping is blocked but partial graph evidence is preserved. Exit code `1` means the request or input bundle is invalid.

The linkage bundle is content-addressed with `LNK-*`, binds the input probe ID and root hash, and can be semantically regenerated from the supplied probe to detect tampering. The identity and root hash include scopes, bindings, import edges, calls, and errors.

## Explicitly deferred

This slice does not model general control-flow graphs, SSA, path dominance, object attributes, descriptors, class MRO, interprocedural execution order, taint propagation, runtime imports, or gate orchestration. Those require separate evidence contracts rather than stronger guesses in this linker.
