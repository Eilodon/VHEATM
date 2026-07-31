from pathlib import Path

import yaml

from vheatm_control.models import Manifest
from vheatm_control.validator import validate_repository

ROOT = Path(__file__).parents[1]


def test_repository_validation_passes() -> None:
    assert validate_repository(ROOT) == []


def test_canonical_counts_are_derived_and_consistent() -> None:
    data = yaml.safe_load((ROOT / "manifests/vheatm-v17.yaml").read_text())
    manifest = Manifest.model_validate(data)
    assert manifest.phases.total == len(manifest.phases.items) == 8
    assert manifest.gates.total == len(manifest.gates.items) == 22
    assert manifest.gates.distribution.model_dump() == {"core": 9, "triggered": 8, "meta": 5}


def test_security_relevant_defaults_are_unknown() -> None:
    data = yaml.safe_load((ROOT / "manifests/vheatm-v17.yaml").read_text())
    defaults = data["defaults"]["declarations"]
    assert defaults
    assert set(defaults.values()) == {"unknown"}
