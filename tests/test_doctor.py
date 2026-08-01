import hashlib
from pathlib import Path

from vheatm_control.doctor import check_repository, main


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _build_fixture(root: Path, *, module_digest: str, instruction_digest: str) -> None:
    module_dir = root / "modules" / "demo"
    module_dir.mkdir(parents=True)

    instructions_text = "# demo instructions\nStep one.\n"
    (module_dir / "instructions.md").write_text(instructions_text, encoding="utf-8")

    module_yaml = f"""\
schema_version: 1.0.0
id: MOD-DEMO
contract:
  disclosure:
    instruction_path: instructions.md
    instruction_sha256: "{instruction_digest}"
"""
    (module_dir / "module.yaml").write_text(module_yaml, encoding="utf-8")

    registry_yaml = f"""\
schema_version: 1.0.0
modules:
- id: MOD-DEMO
  path: modules/demo/module.yaml
  sha256: "{module_digest}"
"""
    (root / "modules" / "registry.yaml").write_text(registry_yaml, encoding="utf-8")


def test_check_repository_reports_no_issues_when_digests_match(tmp_path: Path) -> None:
    module_dir = tmp_path / "modules" / "demo"
    module_dir.mkdir(parents=True)
    instructions_text = "# demo instructions\nStep one.\n"
    (module_dir / "instructions.md").write_text(instructions_text, encoding="utf-8")
    instruction_digest = _sha256(instructions_text.encode("utf-8"))

    module_yaml = f"""\
schema_version: 1.0.0
id: MOD-DEMO
contract:
  disclosure:
    instruction_path: instructions.md
    instruction_sha256: "{instruction_digest}"
"""
    (module_dir / "module.yaml").write_text(module_yaml, encoding="utf-8")
    module_digest = _sha256(module_yaml.encode("utf-8"))

    registry_yaml = f"""\
schema_version: 1.0.0
modules:
- id: MOD-DEMO
  path: modules/demo/module.yaml
  sha256: "{module_digest}"
"""
    (tmp_path / "modules" / "registry.yaml").write_text(registry_yaml, encoding="utf-8")

    assert check_repository(tmp_path) == []


def test_check_repository_reports_mismatch(tmp_path: Path) -> None:
    _build_fixture(tmp_path, module_digest="0" * 64, instruction_digest="1" * 64)
    issues = check_repository(tmp_path)
    fields = {issue.field for issue in issues}
    assert "sha256" in fields
    assert "instruction_sha256" in fields


def test_fix_rewrites_only_the_digest_value(tmp_path: Path) -> None:
    _build_fixture(tmp_path, module_digest="0" * 64, instruction_digest="1" * 64)

    issues = check_repository(tmp_path, fix=True)
    assert len(issues) == 2

    assert check_repository(tmp_path) == []

    registry_text = (tmp_path / "modules" / "registry.yaml").read_text(encoding="utf-8")
    assert "id: MOD-DEMO" in registry_text
    assert "path: modules/demo/module.yaml" in registry_text

    module_text = (tmp_path / "modules" / "demo" / "module.yaml").read_text(encoding="utf-8")
    assert "instruction_path: instructions.md" in module_text


def test_main_exit_codes(tmp_path: Path) -> None:
    _build_fixture(tmp_path, module_digest="0" * 64, instruction_digest="1" * 64)
    assert main(["--root", str(tmp_path)]) == 1
    assert main(["--root", str(tmp_path), "--fix"]) == 0
    assert main(["--root", str(tmp_path)]) == 0
