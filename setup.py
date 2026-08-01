from __future__ import annotations

import shutil
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py
from setuptools.command.sdist import sdist as _sdist


CANONICAL_EXACT = (
    "SKILL.md",
    "Makefile",
    "pyproject.toml",
    "setup.py",
    "MANIFEST.in",
    "manifests/vheatm-v17.yaml",
    "policies/runtime-boundaries.yaml",
    "policies/capability-ledger.yaml",
    "policies/standards-baseline.yaml",
    "uv.lock",
    "modules/registry.yaml",
)
CANONICAL_GLOBS = (
    "modules/*/module.yaml",
    "modules/*/instructions.md",
    "schemas/*.schema.json",
    "src/vheatm_control/*.py",
    "docs/VHEATM-bản gốc tham khảo/vheatm-ultimate/**/*",
    "evals/*.yaml",
)


def canonical_files(root: Path) -> list[Path]:
    paths = {root / relative for relative in CANONICAL_EXACT}
    for pattern in CANONICAL_GLOBS:
        paths.update(root.glob(pattern))
    return sorted((path for path in paths if path.is_file()), key=lambda path: path.relative_to(root).as_posix())


def copy_assets(source_root: Path, target_root: Path) -> list[Path]:
    outputs: list[Path] = []
    for source in canonical_files(source_root):
        relative = source.relative_to(source_root)
        target = target_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        outputs.append(target)
    return outputs


class build_py(_build_py):
    def run(self):
        super().run()
        source_root = Path(__file__).resolve().parent
        target_root = Path(self.build_lib) / "vheatm_control" / "assets"
        self._bundle_outputs = [str(path) for path in copy_assets(source_root, target_root)]

    def get_outputs(self):
        return super().get_outputs() + list(getattr(self, "_bundle_outputs", []))


class sdist(_sdist):
    def make_release_tree(self, base_dir, files):
        super().make_release_tree(base_dir, files)
        source_root = Path(base_dir)
        copy_assets(source_root, source_root / "src" / "vheatm_control" / "assets")


setup(cmdclass={"build_py": build_py, "sdist": sdist})
