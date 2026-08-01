from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

import yaml
from jsonschema import Draft202012Validator, FormatChecker

from .bundle import resolve_control_root
from .serialization import load_json, load_yaml


class QualificationMethodError(ValueError):
    """Raised when a qualification measurement method is unavailable or unbound."""


_METHOD_FIELDS = ("policy_id", "policy_version", "framework_version", "metric", "sample_basis", "estimator", "confidence_method", "minimum_sample_count")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _load_policy_document(root: Path) -> Mapping[str, Any]:
    policy_path = root / "policies" / "qualification-methods.yaml"
    schema_path = root / "schemas" / "qualification-methods.schema.json"
    manifest_path = root / "manifests" / "vheatm-v17.yaml"
    try:
        policy = load_yaml(policy_path.read_text(encoding="utf-8"))
        schema = load_json(schema_path.read_text(encoding="utf-8"))
        manifest = load_yaml(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise QualificationMethodError(f"qualification method policy is unavailable: {exc}") from exc
    if not isinstance(policy, Mapping) or not isinstance(manifest, Mapping):
        raise QualificationMethodError("qualification method policy and manifest must be objects")
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(policy),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        location = ".".join(str(part) for part in errors[0].absolute_path) or "<root>"
        raise QualificationMethodError(f"qualification method policy is not schema-valid at {location}: {errors[0].message}")
    framework_version = manifest.get("framework", {}).get("version") if isinstance(manifest.get("framework"), Mapping) else None
    if policy.get("framework_version") != framework_version:
        raise QualificationMethodError("qualification method policy framework version does not match the canonical manifest")
    methods = policy.get("methods")
    required = policy.get("required_metrics")
    if not isinstance(methods, list) or not isinstance(required, list):
        raise QualificationMethodError("qualification method policy requires methods and required_metrics arrays")
    by_metric: dict[str, Mapping[str, Any]] = {}
    for method in methods:
        if not isinstance(method, Mapping):
            raise QualificationMethodError("qualification method entries must be objects")
        metric = method.get("metric")
        if not isinstance(metric, str) or not metric:
            raise QualificationMethodError("qualification method entries require a metric")
        if metric in by_metric:
            raise QualificationMethodError(f"qualification method policy contains duplicate metric: {metric}")
        by_metric[metric] = method
    if set(str(metric) for metric in required) != set(by_metric):
        raise QualificationMethodError("qualification method policy required_metrics does not match method entries")
    return policy


def _method_entry(metric: str, *, root: Path | None = None) -> Mapping[str, Any]:
    policy = _load_policy_document(resolve_control_root(root))
    for method in policy["methods"]:
        if method.get("metric") == metric:
            return method
    raise QualificationMethodError(f"no canonical qualification method is declared for metric: {metric}")


def method_definition(metric: str, *, root: Path | None = None) -> dict[str, Any]:
    """Return the schema-validated canonical method definition for a metric."""

    resolved_root = resolve_control_root(root)
    policy = _load_policy_document(resolved_root)
    method = next((item for item in policy["methods"] if item.get("metric") == metric), None)
    if not isinstance(method, Mapping):
        raise QualificationMethodError(f"no canonical qualification method is declared for metric: {metric}")
    return {
        "policy_id": policy["policy_id"],
        "policy_version": policy["policy_version"],
        "framework_version": policy["framework_version"],
        **{key: method[key] for key in _METHOD_FIELDS if key in method},
    }


def expected_method_digest(metric: str, *, root: Path | None = None) -> str:
    """Return the content digest that a measurement must carry for ``metric``."""

    return _digest(method_definition(metric, root=root))


def validate_method_digest(metric: str, digest: str, *, root: Path | None = None) -> None:
    """Reject a measurement whose method digest is not the canonical method digest."""

    if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise QualificationMethodError("qualification method digest must be a lowercase SHA-256 value")
    expected = expected_method_digest(metric, root=root)
    if digest != expected:
        raise QualificationMethodError(f"measurement method digest for {metric} does not match canonical method")


def minimum_sample_count(metric: str, *, root: Path | None = None) -> int:
    """Return the canonical minimum population for a metric."""

    return int(_method_entry(metric, root=root)["minimum_sample_count"])
