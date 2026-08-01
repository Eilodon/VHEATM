from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from vheatm_control.structural_probe import ProbeError, ProbeLimits, main, probe_workspace, verify_probe_bundle

CAPTURED_AT = "2026-08-01T03:00:00Z"


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_collects_normalized_symbols_imports_and_calls(tmp_path: Path) -> None:
    _write(
        tmp_path / "src" / "sample.py",
        """import os as operating\nfrom .helpers import run as execute\n\n@decorator()\nclass Service(Base):\n    async def handle(self, value: int = 1, *, flag=False) -> str:\n        os.path.join('a', 'b')\n        factory()(value, **options)\n        return str(value)\n""",
    )
    bundle = probe_workspace(tmp_path, ["src"], captured_at=CAPTURED_AT)
    assert bundle["status"] == "complete"
    assert bundle["summary"] == {"discovered_files": 1, "parsed_files": 1, "symbols": 2, "imports": 2, "calls": 5, "errors": 0}
    file_record = bundle["files"][0]
    assert [item["qualified_name"] for item in file_record["symbols"]] == ["Service", "Service.handle"]
    assert file_record["symbols"][1]["kind"] == "async_method"
    assert file_record["imports"][1]["level"] == 1
    assert any(item["callee"] == "os.path.join" for item in file_record["calls"])
    assert any(item["dynamic"] is True and item["callee"] is None for item in file_record["calls"])
    assert file_record["source"]["locator"] == "workspace:src/sample.py"
    assert file_record["source"]["taint_state"] == "validated"


def test_probe_id_and_root_hash_are_deterministic_with_fixed_timestamp(tmp_path: Path) -> None:
    _write(tmp_path / "a.py", "def value():\n    return 1\n")
    first = probe_workspace(tmp_path, ["a.py"], captured_at=CAPTURED_AT)
    second = probe_workspace(tmp_path, ["a.py"], captured_at=CAPTURED_AT)
    assert first == second


def test_ast_digest_ignores_comments_and_formatting_but_source_digest_changes(tmp_path: Path) -> None:
    target = tmp_path / "a.py"
    _write(target, "def value(x):\n    return x + 1\n")
    first = probe_workspace(tmp_path, ["a.py"], captured_at=CAPTURED_AT)["files"][0]
    _write(target, "# comment\ndef value( x ):\n\n    return x+1\n")
    second = probe_workspace(tmp_path, ["a.py"], captured_at=CAPTURED_AT)["files"][0]
    assert first["source"]["digest"] != second["source"]["digest"]
    assert first["ast_digest"] == second["ast_digest"]


def test_syntax_error_blocks_without_dropping_other_evidence(tmp_path: Path) -> None:
    _write(tmp_path / "good.py", "value = call()\n")
    _write(tmp_path / "bad.py", "def broken(:\n")
    bundle = probe_workspace(tmp_path, ["good.py", "bad.py"], captured_at=CAPTURED_AT)
    assert bundle["status"] == "blocked"
    assert [item["path"] for item in bundle["files"]] == ["good.py"]
    assert bundle["errors"][0]["code"] == "syntax_error"
    assert bundle["summary"]["errors"] == 1


@pytest.mark.parametrize("value", ["../secret.py", "/tmp/a.py", "./a.py", "a//b.py", "a\\b.py", "."])
def test_rejects_non_normalized_or_escaping_paths(tmp_path: Path, value: str) -> None:
    with pytest.raises(ProbeError):
        probe_workspace(tmp_path, [value], captured_at=CAPTURED_AT)


def test_rejects_symlink_file(tmp_path: Path) -> None:
    if not hasattr(os, "symlink"):
        pytest.skip("symlinks unavailable")
    _write(tmp_path / "real.py", "value = 1\n")
    try:
        os.symlink(tmp_path / "real.py", tmp_path / "link.py")
    except OSError:
        pytest.skip("symlink creation not permitted")
    bundle = probe_workspace(tmp_path, ["link.py"], captured_at=CAPTURED_AT)
    assert bundle["status"] == "blocked"
    assert bundle["errors"][0]["code"] == "symlink_rejected"
    assert bundle["files"] == []


def test_enforces_file_size_and_ast_node_limits(tmp_path: Path) -> None:
    _write(tmp_path / "large.py", "value = 1\n" * 20)
    size_blocked = probe_workspace(tmp_path, ["large.py"], captured_at=CAPTURED_AT, limits=ProbeLimits(max_bytes_per_file=10))
    assert size_blocked["status"] == "blocked"
    assert "max_bytes_per_file" in size_blocked["errors"][0]["message"]
    node_blocked = probe_workspace(tmp_path, ["large.py"], captured_at=CAPTURED_AT, limits=ProbeLimits(max_ast_nodes=5))
    assert node_blocked["status"] == "blocked"
    assert "max_ast_nodes" in node_blocked["errors"][0]["message"]


def test_file_limit_blocks_entire_request(tmp_path: Path) -> None:
    _write(tmp_path / "a.py", "a = 1\n")
    _write(tmp_path / "b.py", "b = 2\n")
    bundle = probe_workspace(tmp_path, [".".replace(".", "src")], captured_at=CAPTURED_AT, limits=ProbeLimits(max_files=1))
    assert bundle["status"] == "blocked"
    assert bundle["errors"][0]["code"] == "not_found"
    _write(tmp_path / "src" / "a.py", "a = 1\n")
    _write(tmp_path / "src" / "b.py", "b = 2\n")
    bundle = probe_workspace(tmp_path, ["src"], captured_at=CAPTURED_AT, limits=ProbeLimits(max_files=1))
    assert bundle["status"] == "blocked"
    assert bundle["errors"][0]["code"] == "limit_exceeded"
    assert bundle["files"] == []


def test_output_validates_against_probe_schema(tmp_path: Path) -> None:
    _write(tmp_path / "sample.py", "import json\njson.dumps({})\n")
    bundle = probe_workspace(tmp_path, ["sample.py"], captured_at=CAPTURED_AT)
    schema_root = Path(__file__).parents[1] / "schemas"
    probe_schema = json.loads((schema_root / "structural-probe.schema.json").read_text(encoding="utf-8"))
    provenance_schema = json.loads((schema_root / "provenance-record.schema.json").read_text(encoding="utf-8"))
    registry = Registry().with_resource(provenance_schema["$id"], Resource.from_contents(provenance_schema))
    Draft202012Validator(probe_schema, registry=registry).validate(bundle)


def test_cli_returns_two_for_blocked_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _write(tmp_path / "bad.py", "def broken(:\n")
    monkeypatch.setattr("sys.argv", ["vheatm-probe-python", "--root", str(tmp_path), "--path", "bad.py", "--captured-at", CAPTURED_AT, "--compact"])
    assert main() == 2
    document = json.loads(capsys.readouterr().out)
    assert document["status"] == "blocked"


def test_empty_directory_blocks(tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()
    bundle = probe_workspace(tmp_path, ["empty"], captured_at=CAPTURED_AT)
    assert bundle["status"] == "blocked"
    assert bundle["errors"][0]["code"] == "no_python_files"


def test_semantic_verifier_accepts_generated_bundle_and_rejects_tampering(tmp_path: Path) -> None:
    _write(tmp_path / "sample.py", "service.run()\n")
    bundle = probe_workspace(tmp_path, ["sample.py"], captured_at=CAPTURED_AT)
    verify_probe_bundle(bundle)
    bundle["files"][0]["calls"][0]["callee"] = "service.stop"
    with pytest.raises(ProbeError, match="AST digest mismatch"):
        verify_probe_bundle(bundle)
