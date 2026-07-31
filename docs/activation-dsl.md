# Activation DSL

VHEATM activation expressions are deliberately smaller than Python, JavaScript, CEL, or Jinja. The restricted language is easier to audit, deterministic across agents, and cannot execute code.

## Grammar

```text
expression  := or_expression
or_expression := and_expression ("or" and_expression)*
and_expression := primary ("and" primary)*
primary     := "(" expression ")" | boolean_literal | comparison
comparison  := identifier operator value
operator    := "==" | "!=" | ">=" | "<=" | ">" | "<" | "in" | "not in"
value       := number | string | symbol | list
list        := "[" value ("," value)* "]"
```

Supported boolean literals are `always`, `true`, and `false`. Bare symbols such as `standard`, `full`, `enterprise`, `yes`, and `no` are enum values, not identifiers.

## Context resolution

Identifiers first resolve against top-level audit-context fields. If absent, they resolve against `context.declarations`. Missing values, `null`, and the declaration value `unknown` become the unknown sentinel.

The allowed identifier set is derived from `schemas/audit-context.schema.json`. CI rejects expressions that reference any other name.

## Three-valued logic

VHEATM uses strong Kleene semantics:

- `false and unknown` → `false`;
- `true and unknown` → `unknown`;
- `true or unknown` → `true`;
- `false or unknown` → `unknown`;
- comparisons involving an unknown operand → `unknown`.

An unknown activation blocks completion because the framework cannot safely decide whether the gate is required.

## Non-goals

The DSL has no function calls, property traversal, arithmetic, regex, environment access, imports, templates, or tool invocation. Extend the grammar only with a schema change, parser tests, adversarial tests, and explicit review.
