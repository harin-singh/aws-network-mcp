"""MCP Server for AWS Network Troubleshooting.

Provides AI assistants with tools to diagnose AWS and hybrid
network connectivity issues through Transit Gateway, VPN,
Direct Connect, security groups, NACLs, and Route 53 Resolver.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from aws_network_mcp.analysis.path_analyzer import NetworkTopology
from aws_network_mcp.aws_client.ec2_client import EC2Client
from aws_network_mcp.aws_client.logs_client import CloudWatchLogsClient
from aws_network_mcp.aws_client.route53_client import Route53ResolverClient
from aws_network_mcp.fixtures.scenarios import DEMO_SCENARIOS, get_scenario
from aws_network_mcp.fixtures.topology import load_demo_topology
from aws_network_mcp.tools.connectivity import (
    describe_path,
    explain_connectivity,
    run_reachability_analysis,
)
from aws_network_mcp.tools.dns import check_dns_resolution
from aws_network_mcp.tools.flow_logs import query_flow_logs
from aws_network_mcp.tools.tgw import (
    inspect_vpn_bgp,
    list_tgw_attachments,
    tgw_route_lookup,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AWSNetworkMCPServer:
    """MCP Server for AWS network troubleshooting."""

    def __init__(self, demo_mode: bool = False):
        self.server = Server("aws-network-mcp")
        self.demo_mode = demo_mode or os.environ.get("AWS_NETWORK_MCP_DEMO", "").lower() == "true"

        self._ec2_client: EC2Client | None = None
        self._route53_client: Route53ResolverClient | None = None
        self._logs_client: CloudWatchLogsClient | None = None
        self._topology: NetworkTopology | None = None
        self._current_scenario: str | None = None

        if self.demo_mode:
            self._topology = load_demo_topology()
            logger.info("Running in demo mode with fixture topology")
        else:
            try:
                self._ec2_client = EC2Client()
                self._route53_client = Route53ResolverClient()
                self._logs_client = CloudWatchLogsClient()
                logger.info("Connected to AWS APIs")
            except Exception as e:
                logger.warning(f"Could not connect to AWS: {e}. Falling back to demo mode.")
                self.demo_mode = True
                self._topology = load_demo_topology()

        self._register_handlers()

    def _register_handlers(self) -> None:
        """Register MCP tool handlers."""

        @self.server.list_tools()  # type: ignore[attr-defined, untyped-decorator]
        async def list_tools() -> list[Tool]:
            return [
                Tool(
                    name="describe_path",
                    description=(
                        "Analyze network path from source to destination through AWS infrastructure. "
                        "Walks through security groups, NACLs, route tables, and Transit Gateway, "
                        "returning a hop-by-hop verdict with the exact blocking rule if any."
                    ),
                    input_schema={
                        "type": "object",
                        "properties": {
                            "source_instance_id": {
                                "type": "string",
                                "description": "EC2 instance ID of source",
                            },
                            "source_eni_id": {
                                "type": "string",
                                "description": "ENI ID of source",
                            },
                            "source_ip": {
                                "type": "string",
                                "description": "IP address of source",
                            },
                            "dest_instance_id": {
                                "type": "string",
                                "description": "EC2 instance ID of destination",
                            },
                            "dest_eni_id": {
                                "type": "string",
                                "description": "ENI ID of destination",
                            },
                            "dest_ip": {
                                "type": "string",
                                "description": "IP address of destination",
                            },
                            "port": {
                                "type": "integer",
                                "description": "Destination port (default: 443)",
                                "default": 443,
                            },
                            "protocol": {
                                "type": "string",
                                "enum": ["tcp", "udp", "icmp"],
                                "description": "Protocol (default: tcp)",
                                "default": "tcp",
                            },
                        },
                    },
                ),
                Tool(
                    name="explain_connectivity",
                    description=(
                        "Explain why source can or cannot reach destination. "
                        "Simplified interface using IP addresses that returns a human-readable explanation."
                    ),
                    input_schema={
                        "type": "object",
                        "properties": {
                            "source_ip": {
                                "type": "string",
                                "description": "Source IP address",
                            },
                            "dest_ip": {
                                "type": "string",
                                "description": "Destination IP address",
                            },
                            "port": {
                                "type": "integer",
                                "description": "Destination port",
                                "default": 443,
                            },
                            "protocol": {
                                "type": "string",
                                "enum": ["tcp", "udp", "icmp"],
                                "default": "tcp",
                            },
                        },
                        "required": ["source_ip", "dest_ip"],
                    },
                ),
                Tool(
                    name="run_reachability_analysis",
                    description=(
                        "Run VPC Reachability Analyzer to test connectivity. "
                        "NOTE: This incurs a ~$0.10 charge per path analyzed. "
                        "Use describe_path for free offline analysis first."
                    ),
                    input_schema={
                        "type": "object",
                        "properties": {
                            "source": {
                                "type": "string",
                                "description": "Source resource (instance ID, ENI ID)",
                            },
                            "destination": {
                                "type": "string",
                                "description": "Destination resource",
                            },
                            "destination_port": {
                                "type": "integer",
                                "description": "Destination port",
                            },
                            "protocol": {
                                "type": "string",
                                "enum": ["tcp", "udp"],
                                "default": "tcp",
                            },
                        },
                        "required": ["source", "destination"],
                    },
                ),
                Tool(
                    name="tgw_route_lookup",
                    description=(
                        "Perform longest-prefix match lookup in a Transit Gateway route table. "
                        "Shows which attachment traffic would be routed to for a given destination."
                    ),
                    input_schema={
                        "type": "object",
                        "properties": {
                            "tgw_route_table_id": {
                                "type": "string",
                                "description": "TGW route table ID",
                            },
                            "destination_cidr": {
                                "type": "string",
                                "description": "CIDR or IP address to look up",
                            },
                        },
                        "required": ["tgw_route_table_id", "destination_cidr"],
                    },
                ),
                Tool(
                    name="list_tgw_attachments",
                    description="List Transit Gateway attachments with their state and associated resources.",
                    input_schema={
                        "type": "object",
                        "properties": {
                            "tgw_id": {
                                "type": "string",
                                "description": "Optional TGW ID to filter by",
                            },
                        },
                    },
                ),
                Tool(
                    name="inspect_vpn_bgp",
                    description=(
                        "Inspect Site-to-Site VPN tunnel status and BGP state. "
                        "Also shows Direct Connect virtual interface status if available."
                    ),
                    input_schema={
                        "type": "object",
                        "properties": {
                            "vpn_id": {
                                "type": "string",
                                "description": "Optional VPN connection ID",
                            },
                        },
                    },
                ),
                Tool(
                    name="check_dns_resolution",
                    description=(
                        "Check how DNS for a domain would be resolved from a VPC. "
                        "Shows Route 53 Resolver forwarding rules and whether queries "
                        "go to on-premises DNS or Route 53."
                    ),
                    input_schema={
                        "type": "object",
                        "properties": {
                            "domain": {
                                "type": "string",
                                "description": "Domain name to check",
                            },
                            "vpc_id": {
                                "type": "string",
                                "description": "VPC ID to check resolution from",
                            },
                        },
                        "required": ["domain", "vpc_id"],
                    },
                ),
                Tool(
                    name="query_flow_logs",
                    description=(
                        "Query VPC Flow Logs for traffic matching a 5-tuple filter. "
                        "Useful for finding ACCEPT/REJECT records for specific connections."
                    ),
                    input_schema={
                        "type": "object",
                        "properties": {
                            "log_group": {
                                "type": "string",
                                "description": "CloudWatch Logs group containing flow logs",
                            },
                            "src_addr": {
                                "type": "string",
                                "description": "Source IP filter",
                            },
                            "dst_addr": {
                                "type": "string",
                                "description": "Destination IP filter",
                            },
                            "dst_port": {
                                "type": "integer",
                                "description": "Destination port filter",
                            },
                            "action": {
                                "type": "string",
                                "enum": ["ACCEPT", "REJECT"],
                                "description": "Action filter",
                            },
                        },
                        "required": ["log_group"],
                    },
                ),
                Tool(
                    name="load_demo_scenario",
                    description=(
                        "Load a demo scenario with a specific network misconfiguration. "
                        "Available scenarios: missing_tgw_propagation, blackhole_route, "
                        "sg_missing_return_rule, sg_wrong_port, nacl_blocking_ephemeral, "
                        "asymmetric_routing"
                    ),
                    input_schema={
                        "type": "object",
                        "properties": {
                            "scenario_name": {
                                "type": "string",
                                "description": "Name of the scenario to load",
                                "enum": list(DEMO_SCENARIOS.keys()),
                            },
                        },
                        "required": ["scenario_name"],
                    },
                ),
                Tool(
                    name="list_demo_scenarios",
                    description="List available demo scenarios for troubleshooting practice.",
                    input_schema={"type": "object", "properties": {}},
                ),
            ]

        @self.server.call_tool()  # type: ignore[attr-defined, untyped-decorator]
        async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
            result = await self._handle_tool_call(name, arguments)
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

    async def _handle_tool_call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Handle a tool call and return the result."""
        try:
            if name == "describe_path":
                return describe_path(
                    source_instance_id=arguments.get("source_instance_id"),
                    source_eni_id=arguments.get("source_eni_id"),
                    source_ip=arguments.get("source_ip"),
                    dest_instance_id=arguments.get("dest_instance_id"),
                    dest_eni_id=arguments.get("dest_eni_id"),
                    dest_ip=arguments.get("dest_ip"),
                    port=arguments.get("port", 443),
                    protocol=arguments.get("protocol", "tcp"),
                    ec2_client=self._ec2_client,
                    topology=self._topology,
                )

            elif name == "explain_connectivity":
                return explain_connectivity(
                    source_ip=arguments["source_ip"],
                    dest_ip=arguments["dest_ip"],
                    port=arguments.get("port", 443),
                    protocol=arguments.get("protocol", "tcp"),
                    ec2_client=self._ec2_client,
                    topology=self._topology,
                )

            elif name == "run_reachability_analysis":
                return run_reachability_analysis(
                    source=arguments["source"],
                    destination=arguments["destination"],
                    destination_port=arguments.get("destination_port"),
                    protocol=arguments.get("protocol", "tcp"),
                    ec2_client=self._ec2_client,
                )

            elif name == "tgw_route_lookup":
                return tgw_route_lookup(
                    tgw_route_table_id=arguments["tgw_route_table_id"],
                    destination_cidr=arguments["destination_cidr"],
                    ec2_client=self._ec2_client,
                    topology=self._topology,
                )

            elif name == "list_tgw_attachments":
                return list_tgw_attachments(
                    tgw_id=arguments.get("tgw_id"),
                    ec2_client=self._ec2_client,
                    topology=self._topology,
                )

            elif name == "inspect_vpn_bgp":
                return inspect_vpn_bgp(
                    vpn_id=arguments.get("vpn_id"),
                    ec2_client=self._ec2_client,
                    topology=self._topology,
                )

            elif name == "check_dns_resolution":
                return check_dns_resolution(
                    domain=arguments["domain"],
                    vpc_id=arguments["vpc_id"],
                    route53_client=self._route53_client,
                )

            elif name == "query_flow_logs":
                return query_flow_logs(
                    log_group=arguments["log_group"],
                    src_addr=arguments.get("src_addr"),
                    dst_addr=arguments.get("dst_addr"),
                    dst_port=arguments.get("dst_port"),
                    action=arguments.get("action"),
                    logs_client=self._logs_client,
                )

            elif name == "load_demo_scenario":
                scenario_name = arguments["scenario_name"]
                result = get_scenario(scenario_name)
                if result is None:
                    return {
                        "error": f"Unknown scenario: {scenario_name}",
                        "available": list(DEMO_SCENARIOS.keys()),
                    }
                scenario, topology = result
                self._topology = topology
                self._current_scenario = scenario_name
                return {
                    "loaded": scenario_name,
                    "description": scenario.description,
                    "test_case": {
                        "source_ip": scenario.source.ip,
                        "source_eni": scenario.source.eni_id,
                        "destination_ip": scenario.destination.ip,
                        "port": scenario.port,
                        "protocol": scenario.protocol.value,
                    },
                    "hint": "Use explain_connectivity or describe_path to diagnose this scenario",
                }

            elif name == "list_demo_scenarios":
                return {
                    "scenarios": [
                        {
                            "name": name,
                            "description": scenario.description,
                        }
                        for name, (scenario, _) in DEMO_SCENARIOS.items()
                    ],
                    "current_scenario": self._current_scenario,
                }

            else:
                return {"error": f"Unknown tool: {name}"}

        except Exception as e:
            logger.exception(f"Error handling tool {name}")
            return {"error": str(e)}

    async def run(self) -> None:
        """Run the MCP server."""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options(),
            )


def main() -> None:
    """Entry point for the MCP server."""
    import asyncio

    demo_mode = os.environ.get("AWS_NETWORK_MCP_DEMO", "").lower() == "true"
    server = AWSNetworkMCPServer(demo_mode=demo_mode)
    asyncio.run(server.run())


if __name__ == "__main__":
    main()
