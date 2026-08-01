from __future__ import annotations

import copy
import hashlib
from pathlib import Path

from vheatm_control.capability_ledger import corpus_digest, expected_ledger_id, validate_capability_ledger
from vheatm_control.serialization import load_json, load_yaml


ROOT = Path(__file__).resolve().parents[1]


def test_capability_ledger_covers_all_legacy_files_and_blocks_unowned_stable_claims() -> None:
    ledger = load_yaml((ROOT / "policies" / "capability-ledger.yaml").read_text(encoding="utf-8"))
    schema = load_json((ROOT / "schemas" / "capability-ledger.schema.json").read_text(encoding="utf-8"))
    assert validate_capability_ledger(ROOT, ledger, schema) == []
    assert len(ledger["entries"]) == 33
    assert sum(item["disposition"] == "missing" for item in ledger["entries"]) == 1
    migrated = {item["capability_id"]: item for item in ledger["entries"]}
    assert all(
        migrated[item]["disposition"] == "corrected"
        for item in ("CAP-LEGACY-06", "CAP-LEGACY-07", "CAP-LEGACY-08", "CAP-LEGACY-12", "CAP-LEGACY-17", "CAP-LEGACY-19", "CAP-LEGACY-22", "CAP-LEGACY-26", "CAP-LEGACY-27", "CAP-LEGACY-28")
    )
    assert migrated["CAP-LEGACY-04"]["disposition"] == "missing"


def test_capability_ledger_detects_source_mutation() -> None:
    ledger = load_yaml((ROOT / "policies" / "capability-ledger.yaml").read_text(encoding="utf-8"))
    schema = load_json((ROOT / "schemas" / "capability-ledger.schema.json").read_text(encoding="utf-8"))
    mutated = copy.deepcopy(ledger)
    mutated["entries"][0]["source_digest"] = "0" * 64
    assert any("source digest mismatch" in item for item in validate_capability_ledger(ROOT, mutated, schema))


def test_capability_ledger_rejects_symlinked_corpus_content(tmp_path: Path) -> None:
    corpus = tmp_path / "legacy"
    corpus.mkdir()
    owned = corpus / "owned.txt"
    owned.write_text("owned", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    try:
        (corpus / "linked.txt").symlink_to(outside)
    except OSError:
        import pytest

        pytest.skip("symlinks unavailable")
    (tmp_path / "modules").mkdir()
    (tmp_path / "modules" / "registry.yaml").write_text("modules: []\n", encoding="utf-8")
    ledger = {
        "schema_version": "1.0.0",
        "ledger_id": "LED-" + "0" * 64,
        "framework_version": "17.0.0-dev.1",
        "legacy_root": "legacy",
        "corpus_digest": corpus_digest(corpus),
        "entries": [
            {
                "capability_id": "CAP-LEGACY-00",
                "source_file": "legacy/owned.txt",
                "source_digest": hashlib.sha256(owned.read_bytes()).hexdigest(),
                "source_sections": ["file"],
                "trigger": "test",
                "typed_inputs": ["input"],
                "algorithm_or_protocol": "test",
                "typed_outputs": ["output"],
                "failure_semantics": "unknown",
                "mode_adaptation": "test",
                "evidence_requirement": "test",
                "disposition": "missing",
                "correction_adr": [],
                "module_owner": [],
                "tests": ["tests/test_capability_ledger.py"],
                "eval_cases": ["EVAL-TEST"],
            }
        ],
    }
    ledger["ledger_id"] = expected_ledger_id(ledger)
    schema = load_json((ROOT / "schemas" / "capability-ledger.schema.json").read_text())
    issues = validate_capability_ledger(tmp_path, ledger, schema)
    assert any("symlink" in issue for issue in issues)
