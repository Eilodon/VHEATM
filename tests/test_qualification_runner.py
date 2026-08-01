from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from vheatm_control.qualification_runner import (
    QualificationRunnerError,
    expected_qualification_run_id,
    run_seeded_corpus,
    validate_qualification_run,
)
from vheatm_control.evaluation import evaluate_release_gates
from vheatm_control.serialization import load_json, load_yaml
from vheatm_control.qualification_methods import expected_method_digest


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = load_json((ROOT / "schemas" / "qualification-run.schema.json").read_text(encoding="utf-8"))


def test_seeded_runner_executes_every_canonical_case_and_is_replayable() -> None:
    first = run_seeded_corpus(ROOT, observed_at="2026-08-01T00:00:00Z")
    second = run_seeded_corpus(ROOT, observed_at="2026-08-01T00:00:00Z")

    assert first == second
    assert first["status"] == "complete"
    assert first["visibility"] == "public_seeded"
    assert first["evidence_state"] == "unverified"
    corpus = load_yaml((ROOT / "evals" / "cases.yaml").read_text(encoding="utf-8"))
    assert [item["case_id"] for item in first["case_results"]] == [item["case_id"] for item in corpus["cases"]]
    assert all(item["outcome"] == "pass" for item in first["case_results"])
    assert any(item["metric"] == "determinism_runs" and item["sample_count"] == 1000 for item in first["measurements"])
    assert all(item["method_digest"] == expected_method_digest(item["metric"], root=ROOT) for item in first["measurements"])
    assert validate_qualification_run(first, SCHEMA) == []


def test_security_case_covers_every_unauthorized_tool_class() -> None:
    run = run_seeded_corpus(ROOT, observed_at="2026-08-01T00:00:00Z")
    security_case = next(item for item in run["case_results"] if item["case_id"] == "EVC-SECURITY-001")
    security_metric = next(item for item in run["measurements"] if item["metric"] == "unauthorized_block_rate")

    assert security_case["outcome"] == "pass"
    assert security_metric["value"] == 1
    assert security_metric["sample_count"] == 5
    assert security_case["details"]["unauthorized_classes"] == ["execute", "network", "read", "secrets", "write"]
    assert security_case["details"]["blocked_classes"] == security_case["details"]["unauthorized_classes"]


def test_seeded_runner_rejects_content_tampering() -> None:
    run = run_seeded_corpus(ROOT, observed_at="2026-08-01T00:00:00Z")
    tampered = copy.deepcopy(run)
    tampered["case_results"][0]["outcome"] = "fail"
    assert validate_qualification_run(tampered, SCHEMA) == ["run_id does not match canonical run content"]
    assert expected_qualification_run_id(run) == run["run_id"]


def test_seeded_runner_rejects_unknown_measurement_method() -> None:
    run = run_seeded_corpus(ROOT, observed_at="2026-08-01T00:00:00Z")
    tampered = copy.deepcopy(run)
    tampered["measurements"][0]["method_digest"] = "c" * 64
    tampered["run_id"] = expected_qualification_run_id(tampered)
    assert any("does not match canonical method" in issue for issue in validate_qualification_run(tampered, SCHEMA, root=ROOT))


def test_seeded_runner_rejects_non_finite_measurement() -> None:
    run = run_seeded_corpus(ROOT, observed_at="2026-08-01T00:00:00Z")
    tampered = copy.deepcopy(run)
    tampered["measurements"][0]["value"] = float("nan")
    tampered["run_id"] = expected_qualification_run_id(tampered)

    assert any("finite" in issue for issue in validate_qualification_run(tampered, SCHEMA, root=ROOT))


def test_seeded_runner_rejects_invalid_corpus_before_dispatch(tmp_path: Path) -> None:
    root = tmp_path / "fixture"
    root.mkdir()
    for relative in ("manifests/vheatm-v17.yaml", "schemas/eval-corpus.schema.json", "evals/cases.yaml"):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((ROOT / relative).read_text(encoding="utf-8"), encoding="utf-8")
    corpus = load_yaml((root / "evals/cases.yaml").read_text(encoding="utf-8"))
    corpus["cases"][0]["expected"] = "pass"
    (root / "evals/cases.yaml").write_text(json.dumps(corpus), encoding="utf-8")
    with pytest.raises(QualificationRunnerError, match="seeded evaluation corpus is invalid"):
        run_seeded_corpus(root, observed_at="2026-08-01T00:00:00Z")


def test_seeded_measurements_cannot_mint_release_gate_status() -> None:
    run = run_seeded_corpus(ROOT, observed_at="2026-08-01T00:00:00Z")
    raw_metrics = {item["metric"]: item["value"] for item in run["measurements"]}
    report = evaluate_release_gates("17.0.0-dev.1", {"metrics": raw_metrics}, evaluated_at="2026-08-01T00:00:00Z")
    assert report["summary"]["ga_eligible"] is False
    assert all(gate["status"] == "unknown" for gate in report["gates"])
