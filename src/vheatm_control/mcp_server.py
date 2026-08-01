"""MCP server exposing the VHEATM audit control plane as tools.

Thin wrapper only: every tool below delegates to the existing public
functions in :mod:`vheatm_control.evaluator`, :mod:`vheatm_control.module_router`,
:mod:`vheatm_control.report_validator`, and :mod:`vheatm_control.validator`.
No audit logic lives in this module.
"""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

import yaml
from fastmcp import FastMCP

from . import evaluator, module_router, report_validator, validator
from .bundle import resolve_control_root

mcp = FastMCP("VHEATM Audit Control Plane")


def _resolve(root: str | None) -> Path:
    """Resolve the VHEATM control-plane root, not the audit subject/target.

    Falls through: explicit ``root`` -> current-directory checkout ->
    package data bundled inside the installed wheel. See
    :func:`vheatm_control.bundle.resolve_control_root`.
    """
    return resolve_control_root(Path(root) if root else None)


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _issue_dict(issue: Any) -> dict[str, Any]:
    if is_dataclass(issue):
        return asdict(issue)
    return {"source": getattr(issue, "source", None), "message": getattr(issue, "message", str(issue))}


@mcp.tool
def vheatm_validate(root: str | None = None) -> list[dict[str, Any]]:
    """Validate manifest, schemas, modules, and runtime policy invariants for the VHEATM control plane.

    ``root`` is the control-plane checkout, not the project being audited; omit it to use the
    current directory or the control-plane data bundled with this install.
    """
    issues = validator.validate_repository(_resolve(root))
    return [_issue_dict(issue) for issue in issues]


@mcp.tool
def vheatm_evaluate(context: dict[str, Any], root: str | None = None) -> dict[str, Any]:
    """Produce the 22-gate activation plan (active/inactive/unknown) for a supplied audit context."""
    manifest = _load_yaml(_resolve(root) / "manifests" / "vheatm-v17.yaml")
    return evaluator.evaluate_manifest(manifest, context)


@mcp.tool
def vheatm_route(gate_plan: dict[str, Any], root: str | None = None, include_instructions: bool = False) -> dict[str, Any]:
    """Deterministically select the runtime-authoritative modules required by a fully bound gate plan."""
    return module_router.load_and_route(_resolve(root), gate_plan, include_instructions=include_instructions)


@mcp.tool
def vheatm_validate_report(report: dict[str, Any], root: str | None = None) -> list[dict[str, Any]]:
    """Check the semantic validity of a final audit report before it may be treated as complete."""
    root_path = _resolve(root)
    manifest = _load_yaml(root_path / "manifests" / "vheatm-v17.yaml")
    policy = _load_yaml(root_path / "policies" / "runtime-boundaries.yaml")
    issues = report_validator.validate_report_semantics(manifest=manifest, policy=policy, report=report)
    return [_issue_dict(issue) for issue in issues]


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
