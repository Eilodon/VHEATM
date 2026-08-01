from pathlib import Path

import pytest

from vheatm_control.init_cmd import main, scaffold


def test_scaffold_writes_context_template(tmp_path: Path) -> None:
    path = scaffold(tmp_path)
    assert path == tmp_path / "context.yaml"
    text = path.read_text(encoding="utf-8")
    assert 'schema_version: "2.0.0"' in text
    assert "declarations:" in text


def test_scaffold_refuses_overwrite_without_force(tmp_path: Path) -> None:
    scaffold(tmp_path)
    with pytest.raises(FileExistsError):
        scaffold(tmp_path)


def test_scaffold_force_overwrites(tmp_path: Path) -> None:
    scaffold(tmp_path)
    path = scaffold(tmp_path, force=True)
    assert path.exists()


def test_main_returns_zero_on_success(tmp_path: Path) -> None:
    assert main(["--root", str(tmp_path)]) == 0
    assert (tmp_path / "context.yaml").exists()


def test_main_returns_one_when_exists_without_force(tmp_path: Path) -> None:
    assert main(["--root", str(tmp_path)]) == 0
    assert main(["--root", str(tmp_path)]) == 1
