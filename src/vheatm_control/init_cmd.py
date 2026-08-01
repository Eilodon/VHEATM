"""Scaffold a starter audit context into a target repository (``vheatm-init``)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

CONTEXT_TEMPLATE = """\
schema_version: "2.0.0"
goal: "Assess this repository against the VHEATM V17 control bundle."
decision_owner: "REPLACE_ME"
stakeholder: "REPLACE_ME"
subject:
  kind: repository
  locator: "REPLACE_ME"
  digest: "0000000000000000000000000000000000000000000000000000000000000000"
  tree_digest: "0000000000000000000000000000000000000000000000000000000000000000"
scope:
  included_paths: ["src"]
  excluded_paths: [".venv", "node_modules"]
audit_stage: code
legacy_state: "unknown"
organization_scope: single-team
execution_profile: standard
audit_intent: assessment-only
pii: "unknown"
compliance: []
multi_tenant: "unknown"
post_incident: "no"
language: "en"
organization_size: "unknown"
test_availability: "unknown"
declarations:
  self_audit: "unknown"
  ai_integrated: "unknown"
  ai_executor: "unknown"
  async_worker: "unknown"
  safety_critical: "unknown"
  financial_path: "unknown"
finding_ledger: []
facts:
  blast_radius: 1
  write_chain_components: 1
amendments: []
"""

QUICKSTART = """\
Created {path}.

VHEATM never treats a missing declaration as "no" — every "unknown" field
above will keep the matching gate unknown until you resolve it. Next steps:

  1. Fill in decision_owner, stakeholder, subject.locator, and the digest
     fields (sha256sum of the repository tree is a reasonable digest source).
  2. Replace "unknown" declarations with "yes"/"no" where you can answer them.
  3. Run: vheatm-evaluate --root . --context {path} > gate-plan.json
  4. Run: vheatm-route --root . --plan gate-plan.json
"""


def scaffold(root: Path, *, force: bool = False) -> Path:
    target = root / "context.yaml"
    if target.exists() and not force:
        raise FileExistsError(f"{target} already exists; pass --force to overwrite")
    target.write_text(CONTEXT_TEMPLATE, encoding="utf-8")
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scaffold a starter VHEATM audit context")
    parser.add_argument("--root", default=".", help="Target repository root")
    parser.add_argument("--force", action="store_true", help="Overwrite an existing context.yaml")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    try:
        path = scaffold(root, force=args.force)
    except FileExistsError as exc:
        print(f"vheatm-init: {exc}", file=sys.stderr)
        return 1

    print(QUICKSTART.format(path=path.relative_to(root) if path.is_relative_to(root) else path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
