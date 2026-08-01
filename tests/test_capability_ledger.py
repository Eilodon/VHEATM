from __future__ import annotations

import copy
from pathlib import Path

from vheatm_control.capability_ledger import validate_capability_ledger
from vheatm_control.serialization import load_json, load_yaml


ROOT = Path(__file__).resolve().parents[1]


def test_capability_ledger_covers_all_legacy_files_and_blocks_unowned_stable_claims() -> None:
    ledger = load_yaml((ROOT / "policies" / "capability-ledger.yaml").read_text(encoding="utf-8"))
    schema = load_json((ROOT / "schemas" / "capability-ledger.schema.json").read_text(encoding="utf-8"))
    assert validate_capability_ledger(ROOT, ledger, schema) == []
    assert len(ledger["entries"]) == 33
    assert sum(item["disposition"] == "missing" for item in ledger["entries"]) == 11


def test_capability_ledger_detects_source_mutation() -> None:
    ledger = load_yaml((ROOT / "policies" / "capability-ledger.yaml").read_text(encoding="utf-8"))
    schema = load_json((ROOT / "schemas" / "capability-ledger.schema.json").read_text(encoding="utf-8"))
    mutated = copy.deepcopy(ledger)
    mutated["entries"][0]["source_digest"] = "0" * 64
    assert any("source digest mismatch" in item for item in validate_capability_ledger(ROOT, mutated, schema))
