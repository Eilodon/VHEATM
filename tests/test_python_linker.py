from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from vheatm_control.python_linker import LinkerError, link_probe_bundle, main, verify_linkage_bundle
from vheatm_control.structural_probe import probe_workspace

CAPTURED_AT = "2026-08-01T03:00:00Z"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _probe(tmp_path: Path, paths: list[str] | None = None) -> dict:
    return probe_workspace(tmp_path, paths or ["src"], captured_at=CAPTURED_AT)


def test_builds_modules_import_edges_and_module_scope_call_resolutions(tmp_path: Path) -> None:
    _write(tmp_path / "src" / "pkg" / "__init__.py", "")
    _write(tmp_path / "src" / "pkg" / "service.py", "def run():\n    return 1\n")
    _write(
        tmp_path / "src" / "app.py",
        """import pkg.service as service
from pkg.service import run as execute
service.run()
execute()
def wrapper():
    service.run()
""",
    )
    linkage = link_probe_bundle(_probe(tmp_path), ["src"], generated_at=CAPTURED_AT)
    assert linkage["status"] == "complete"
    assert [item["module"] for item in linkage["modules"]] == ["app", "pkg", "pkg.service"]
    assert [item["state"] for item in linkage["imports"]] == ["internal_module", "internal_symbol"]
    calls = {((item["callee"] or ""), item["caller"]): item for item in linkage["calls"]}
    assert calls[("service.run", "<module>")]["state"] == "candidate"
    assert calls[("service.run", "<module>")]["targets"][0]["qualified_name"] == "pkg.service.run"
    assert calls[("execute", "<module>")]["state"] == "candidate"
    assert calls[("service.run", "wrapper")]["reason"] == "lexical_shadowing_not_modeled"


def test_resolves_relative_imports(tmp_path: Path) -> None:
    _write(tmp_path / "src" / "pkg" / "__init__.py", "")
    _write(tmp_path / "src" / "pkg" / "service.py", "def run():\n    pass\n")
    _write(tmp_path / "src" / "pkg" / "consumer.py", "from .service import run\nrun()\n")
    linkage = link_probe_bundle(_probe(tmp_path), ["src"], generated_at=CAPTURED_AT)
    edge = next(item for item in linkage["imports"] if item["source_module"] == "pkg.consumer")
    assert edge["state"] == "internal_symbol"
    call = next(item for item in linkage["calls"] if item["source_module"] == "pkg.consumer")
    assert call["state"] == "candidate"
    assert call["targets"][0]["qualified_name"] == "pkg.service.run"


def test_external_and_dynamic_calls_remain_unresolved(tmp_path: Path) -> None:
    _write(tmp_path / "src" / "app.py", "import requests\nrequests.get('x')\nfactory()()\n")
    linkage = link_probe_bundle(_probe(tmp_path), ["src"], generated_at=CAPTURED_AT)
    assert linkage["imports"][0]["state"] == "external"
    by_reason = {item["reason"] for item in linkage["calls"]}
    assert "external_target" in by_reason
    assert "dynamic_callee" in by_reason


def test_from_import_symbol_submodule_collision_is_ambiguous(tmp_path: Path) -> None:
    _write(tmp_path / "src" / "pkg" / "__init__.py", "def service():\n    return 1\n")
    _write(tmp_path / "src" / "pkg" / "service.py", "def run():\n    pass\n")
    _write(tmp_path / "src" / "app.py", "from pkg import service\nservice()\n")
    linkage = link_probe_bundle(_probe(tmp_path), ["src"], generated_at=CAPTURED_AT)
    edge = linkage["imports"][0]
    assert edge["state"] == "ambiguous"
    assert {item["kind"] for item in edge["targets"]} == {"module", "symbol"}
    call = linkage["calls"][0]
    assert call["state"] == "ambiguous"
    assert call["reason"] == "multiple_internal_targets"


def test_module_collisions_are_explicit_not_blocking(tmp_path: Path) -> None:
    _write(tmp_path / "src_a" / "pkg" / "mod.py", "def run():\n    pass\n")
    _write(tmp_path / "src_b" / "pkg" / "mod.py", "def run():\n    pass\n")
    _write(tmp_path / "src_a" / "app.py", "import pkg.mod as mod\nmod.run()\n")
    probe = _probe(tmp_path, ["src_a", "src_b"])
    linkage = link_probe_bundle(probe, ["src_a", "src_b"], generated_at=CAPTURED_AT)
    assert linkage["status"] == "complete"
    assert linkage["module_collisions"] == [{"module": "pkg.mod", "paths": ["src_a/pkg/mod.py", "src_b/pkg/mod.py"]}]
    edge = next(item for item in linkage["imports"] if item["source_module"] == "app")
    assert edge["state"] == "ambiguous"
    call = linkage["calls"][0]
    assert call["state"] == "ambiguous"
    assert len(call["targets"]) == 2


def test_unmapped_and_unimportable_files_block_with_partial_graph(tmp_path: Path) -> None:
    _write(tmp_path / "src" / "valid.py", "value = 1\n")
    _write(tmp_path / "other" / "outside.py", "value = 2\n")
    _write(tmp_path / "src" / "bad-name.py", "value = 3\n")
    probe = _probe(tmp_path, ["src", "other"])
    linkage = link_probe_bundle(probe, ["src"], generated_at=CAPTURED_AT)
    assert linkage["status"] == "blocked"
    assert [item["module"] for item in linkage["modules"]] == ["valid"]
    assert {item["code"] for item in linkage["errors"]} == {"unmapped_file", "unimportable_module"}


def test_blocked_probe_preserves_partial_graph_but_blocks_linkage(tmp_path: Path) -> None:
    _write(tmp_path / "src" / "good.py", "def run():\n    pass\nrun()\n")
    _write(tmp_path / "src" / "bad.py", "def broken(:\n")
    probe = _probe(tmp_path)
    assert probe["status"] == "blocked"
    linkage = link_probe_bundle(probe, ["src"], generated_at=CAPTURED_AT)
    assert linkage["status"] == "blocked"
    assert linkage["modules"][0]["module"] == "good"
    assert linkage["errors"][0]["code"] == "input_probe_blocked"


@pytest.mark.parametrize("roots", [["src", "src/pkg"], ["." , "src"], ["../src"], ["src/"]])
def test_rejects_invalid_or_overlapping_source_roots(tmp_path: Path, roots: list[str]) -> None:
    _write(tmp_path / "src" / "app.py", "value = 1\n")
    with pytest.raises(LinkerError):
        link_probe_bundle(_probe(tmp_path), roots, generated_at=CAPTURED_AT)


def test_workspace_root_source_root_maps_top_level_modules(tmp_path: Path) -> None:
    _write(tmp_path / "app.py", "def run():\n    pass\nrun()\n")
    probe = _probe(tmp_path, ["app.py"])
    linkage = link_probe_bundle(probe, ["."], generated_at=CAPTURED_AT)
    assert linkage["modules"][0]["module"] == "app"
    assert linkage["calls"][0]["state"] == "candidate"


def test_output_validates_against_schema(tmp_path: Path) -> None:
    _write(tmp_path / "src" / "app.py", "def run():\n    pass\nrun()\n")
    linkage = link_probe_bundle(_probe(tmp_path), ["src"], generated_at=CAPTURED_AT)
    schema = json.loads((Path(__file__).parents[1] / "schemas" / "python-linkage.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(linkage)


def test_semantic_verifier_rejects_tampering_against_probe(tmp_path: Path) -> None:
    _write(tmp_path / "src" / "app.py", "def run():\n    pass\nrun()\n")
    probe = _probe(tmp_path)
    linkage = link_probe_bundle(probe, ["src"], generated_at=CAPTURED_AT)
    verify_linkage_bundle(linkage, probe)
    linkage["calls"][0]["callee"] = "stop"
    with pytest.raises(LinkerError):
        verify_linkage_bundle(linkage, probe)


def test_cli_returns_two_for_blocked_linkage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _write(tmp_path / "src" / "bad.py", "def broken(:\n")
    probe_path = tmp_path / "probe.json"
    probe_path.write_text(json.dumps(_probe(tmp_path)), encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv",
        [
            "vheatm-link-python",
            "--probe",
            str(probe_path),
            "--source-root",
            "src",
            "--generated-at",
            CAPTURED_AT,
            "--compact",
        ],
    )
    assert main() == 2
    document = json.loads(capsys.readouterr().out)
    assert document["status"] == "blocked"


def test_canonical_validator_requires_probe_contracts() -> None:
    validator = pytest.importorskip("vheatm_control.validator")
    assert {
        "structural-probe.schema.json",
        "python-linkage.schema.json",
    } <= validator.REQUIRED_SCHEMA_FILES
