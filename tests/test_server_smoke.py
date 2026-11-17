"""In-process and stdio smoke tests for the MCP server."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from aws_network_mcp.server import (
    describe_path_tool,
    explain_connectivity_tool,
    list_demo_scenarios_tool,
    load_demo_scenario_tool,
    reset_runtime,
)


def test_server_tools_in_process() -> None:
    """Tool functions work against the landing-zone fixture without stdio."""
    reset_runtime(demo_mode=True)
    listed = list_demo_scenarios_tool()
    names = {item["name"] for item in listed["scenarios"]}
    assert "prod_nonprod_blocked" in names
    assert "spoke_onprem_via_inspection" in names

    loaded = load_demo_scenario_tool("missing_tgw_propagation")
    assert loaded["loaded"] == "missing_tgw_propagation"
    assert loaded["test_case"]["source_ip"] == "10.10.0.10"

    explained = explain_connectivity_tool(
        source_ip="10.10.0.10",
        dest_ip="10.200.1.50",
        port=443,
        protocol="tcp",
    )
    assert explained["verdict"] == "DENY"
    assert "None-None" not in explained["explanation"]

    path = describe_path_tool(source_ip="10.10.0.10", dest_ip="10.20.0.10", port=443)
    assert path["overall_verdict"] == "BLACKHOLE"
    assert path["additional_findings"]


@pytest.mark.asyncio
async def test_stdio_list_tools_and_call_tool() -> None:
    """Launch the server over stdio and exercise list_tools plus call_tool."""
    env = os.environ.copy()
    env["AWS_NETWORK_MCP_DEMO"] = "true"
    env["PYTHONUNBUFFERED"] = "1"
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "aws_network_mcp.server"],
        env=env,
        cwd=str(Path(__file__).resolve().parents[1]),
    )
    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        tools = await session.list_tools()
        names = {tool.name for tool in tools.tools}
        assert "describe_path" in names
        assert "explain_connectivity" in names
        assert "list_demo_scenarios" in names
        assert "load_demo_scenario" in names

        listed = await session.call_tool("list_demo_scenarios", {})
        assert listed.is_error is False
        listed_text = _tool_text(listed)
        assert "prod_nonprod_blocked" in listed_text

        result = await session.call_tool(
            "explain_connectivity",
            {
                "source_ip": "10.10.0.10",
                "dest_ip": "10.20.0.10",
                "port": 443,
                "protocol": "tcp",
            },
        )
        assert result.is_error is False
        text = _tool_text(result)
        assert "BLACKHOLE" in text
        assert "None-None" not in text


def _tool_text(result: object) -> str:
    content = getattr(result, "content", [])
    parts: list[str] = []
    for block in content:
        text = getattr(block, "text", None)
        if text:
            parts.append(text)
    structured = getattr(result, "structured_content", None)
    if structured:
        parts.append(json.dumps(structured))
    return "\n".join(parts)
