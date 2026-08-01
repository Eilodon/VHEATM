# Conservative Python linkage

`vheatm-link-python` consumes a verified `vheatm-probe-python` bundle and derives an import graph plus conservative call candidates. It never imports or executes target modules and never rereads source files.

## Resolution boundary

The linker maps files to modules using explicit, non-overlapping `--source-root` values. It derives structural candidates for:

- absolute and relative imports against modules present in the probe;
- direct `from module import symbol` references when the symbol is a unique top-level class or function;
- module-scope calls to unique local symbols, directly imported symbols, and one-segment symbols reached through imported module aliases. A candidate is not a runtime reachability claim because assignments and rebinding are not yet modeled.

It deliberately leaves calls inside functions and methods unresolved because the structural probe does not yet model assignments, closures, rebinding, or complete lexical shadowing. Dynamic calls, wildcard imports, external dependencies, missing internal symbols, and module collisions remain explicit rather than guessed.

## CLI

```bash
vheatm-probe-python --root . --path src --captured-at 2026-08-01T03:00:00Z > probe.json
vheatm-link-python \
  --probe probe.json \
  --source-root src \
  --generated-at 2026-08-01T03:00:00Z > linkage.json
```

Exit code `0` means the graph completed. Exit code `2` means the input probe or module mapping is blocked but partial graph evidence is preserved. Exit code `1` means the request or input bundle is invalid.

The linkage bundle is content-addressed with `LNK-*`, binds the input probe ID and root hash, and can be semantically regenerated from the supplied probe to detect tampering.
