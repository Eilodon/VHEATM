from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TextIO

import yaml


class DuplicateKeyError(ValueError):
    """Raised when a machine-readable document repeats an object key."""


class StrictSafeLoader(yaml.SafeLoader):
    """YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(loader: StrictSafeLoader, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            already_present = key in result
        except TypeError as exc:
            raise DuplicateKeyError(f"unhashable YAML mapping key: {key!r}") from exc
        if already_present:
            raise DuplicateKeyError(f"duplicate YAML mapping key: {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


StrictSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _construct_unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_non_finite_json_number(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not permitted: {value}")


def load_yaml(stream: TextIO | str) -> Any:
    return yaml.load(stream, Loader=StrictSafeLoader)


def load_json(stream: TextIO | str) -> Any:
    kwargs = {
        "object_pairs_hook": _construct_unique_json_object,
        "parse_constant": _reject_non_finite_json_number,
    }
    return json.load(stream, **kwargs) if hasattr(stream, "read") else json.loads(stream, **kwargs)


def load_document(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return load_json(handle) if path.suffix.lower() == ".json" else load_yaml(handle)
