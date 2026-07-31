"""Executable validation, planning, enforcement, and provenance for VHEATM."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("vheatm-control")
except PackageNotFoundError:  # pragma: no cover - source tree without installation
    __version__ = "0+unknown"
