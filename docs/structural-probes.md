# Read-only structural probes

`vheatm-probe-python` parses workspace Python files with the standard-library AST parser and emits a schema-validated evidence bundle. It never imports target modules or executes target code.

## Evidence boundary

The probe records exact source SHA-256 digests, content-addressed `SRC-*` records, normalized symbol/import/call facts, a lexical scope graph, binding events, and a formatting-insensitive AST digest. Calls are syntactic facts only: dotted names are preserved when statically visible, while computed call targets are marked `dynamic: true` rather than guessed.

Each file now includes:

- `scopes`: module, class, function, async-function, lambda, and comprehension scopes with structural and lookup parents;
- `bindings`: parameters, imports, class/function definitions, assignments, annotations, named expressions, deletes, loop/with/except targets, pattern captures, and comprehension targets;
- `global_names`, `nonlocal_names`, and `local_names` for each scope;
- `control_context` on calls and bindings when syntax is branch-, loop-, try-, match-, comprehension-, or short-circuit-dependent.

Function defaults, decorators, annotations, class bases, and class keywords are visited in their enclosing scope. Function-like scopes defined inside a class skip the class namespace for unqualified lexical lookup, matching Python's scope boundary conservatively. Comprehension targets are isolated in a comprehension scope.

The probe does not assign gate states, severity, exploitability, runtime reachability, or dataflow conclusions. Binding facts do not prove that a statement executed; control-dependent events remain explicitly marked for the linker to handle conservatively.

## Safety and failure behavior

All requested paths must be normalized workspace-relative POSIX paths. Symlinks are rejected, directories use a fixed exclusion list, files are opened without following symlinks when the platform supports it, and file-count, byte-size, and AST-node limits are mandatory.

Missing paths, syntax errors, unreadable files, rejected symlinks, or limit violations produce a `blocked` bundle and exit code `2`. Successfully parsed files remain in the bundle so partial evidence is not discarded, but blocked output cannot be treated as complete coverage.

## Reproducibility

Supply the audit lifecycle timestamp through `--captured-at`. With identical source bytes, requested paths, limits, and timestamp, the complete JSON document is deterministic. The source digest binds exact bytes; `ast_digest` changes only when normalized structural facts change. Scope identifiers use traversal-stable qualified names and counters rather than source offsets, so comments and formatting do not perturb the structural digest.

```bash
vheatm-probe-python \
  --root . \
  --path src \
  --path tests \
  --captured-at 2026-08-01T03:00:00Z
```

The command writes JSON to stdout only. Persisting or registering the bundle remains an explicit write operation outside this read-only probe.
