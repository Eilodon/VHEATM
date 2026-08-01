import asyncio
from pathlib import Path

import pytest

pytest.importorskip("fastmcp", reason="fastmcp is an optional extra ([mcp])")

from vheatm_control import mcp_server  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def test_tools_are_registered() -> None:
    tools = asyncio.run(mcp_server.mcp.list_tools())
    names = {tool.name for tool in tools}
    assert {"vheatm_validate", "vheatm_evaluate", "vheatm_route", "vheatm_validate_report"} <= names


def test_vheatm_validate_wraps_validator() -> None:
    issues = mcp_server.vheatm_validate(str(ROOT))
    assert isinstance(issues, list)
    for issue in issues:
        assert set(issue) == {"source", "message"}
