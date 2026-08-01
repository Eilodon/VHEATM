# Security Policy

## Reporting a vulnerability

Please do not open a public GitHub issue for a suspected security
vulnerability. Instead, use GitHub's private vulnerability reporting
("Security" tab → "Report a vulnerability") on this repository, or email the
maintainers listed in [CODEOWNERS](CODEOWNERS).

Include:

- the affected component (schema, evaluator, router, report validator,
  module, MCP server, container image, or CI workflow);
- reproduction steps or a minimal audit context that triggers the issue;
- the impact you believe it has (for example: a gate that should be
  `unknown` resolves to `active`/`inactive`, a digest check that can be
  bypassed, or a policy guard that allows a denied capability).

## Scope

VHEATM is a control plane that gates AI-executed audits. Reports of
particular interest:

- ways to make `unknown` activation resolve to a definite value without an
  explicit declaration;
- ways to make a gate report `pass` without verified evidence;
- ways to bypass digest binding between the module registry, a module
  document, and its instruction file;
- ways to escalate a denied tool/policy decision (execute, write, network,
  secret) into an allowed one;
- supply-chain issues in the release pipeline (PyPI publish, MCP registry
  publish, or the container image).

## Supported versions

VHEATM V17 is `alpha`; only the latest published release receives security
fixes. There is no long-term support branch at this stage.
