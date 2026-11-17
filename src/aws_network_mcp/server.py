"""MCP server for hybrid AWS path analysis.

Uses the high-level ``MCPServer`` API from the pinned MCP Python SDK (2.x).
"""

from __future__ import annotations

import logging
import os
from typing import Any

from mcp.server import MCPServer

from aws_network_mcp.analysis.path_analyzer import NetworkTopology
from aws_network_mcp.aws_client.ec2_client import EC2Client
from aws_network_mcp.aws_client.logs_client import CloudWatchLogsClient
from aws_network_mcp.aws_client.nfw_client import NetworkFirewallClient
from aws_network_mcp.aws_client.route53_client import Route53ResolverClient
from aws_network_mcp.aws_client.topology_loader import LiveTopologyLoader
from aws_network_mcp.fixtures.scenarios import DEMO_SCENARIOS, get_scenario
from aws_network_mcp.fixtures.topology import load_demo_topology
from aws_network_mcp.tools.connectivity import (
    describe_path,
    explain_connectivity,
    run_reachability_analysis,
)
from aws_network_mcp.tools.dns import check_dns_resolution
from aws_network_mcp.tools.flow_logs import query_flow_logs
from aws_network_mcp.tools.tgw import inspect_vpn_bgp, list_tgw_attachments, tgw_route_lookup

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

mcp = MCPServer(
    "aws-network-mcp",
    instructions=(
        "Hybrid path analysis for AWS Transit Gateway, inspection VPC / Network Firewall, "
        "security groups, NACLs, and on-prem routes learned over VPN or Direct Connect BGP. "
        "Use explain_connectivity or describe_path to answer why traffic between two "
        "endpoints is allowed or dropped."
    ),
)


class ServerRuntime:
    """Process-wide clients and the currently loaded topology."""

    def __init__(self, demo_mode: bool | None = None) -> None:
        env_demo = os.environ.get("AWS_NETWORK_MCP_DEMO", "").lower() == "true"
        self.demo_mode = env_demo if demo_mode is None else demo_mode
        self.ec2_client: EC2Client | None = None
        self.nfw_client: NetworkFirewallClient | None = None
        self.route53_client: Route53ResolverClient | None = None
        self.logs_client: CloudWatchLogsClient | None = None
        self.topology: NetworkTopology | None = None
        self.current_scenario: str | None = None

        if self.demo_mode:
            self.topology = load_demo_topology()
            logger.info("Running in demo mode with landing-zone fixture topology")
            return

        try:
            self.ec2_client = EC2Client()
            self.nfw_client = NetworkFirewallClient()
            self.route53_client = Route53ResolverClient()
            self.logs_client = CloudWatchLogsClient()
            self.topology = LiveTopologyLoader(self.ec2_client, self.nfw_client).load()
            logger.info("Connected to AWS APIs and loaded live topology")
        except Exception as exc:
            logger.warning("Could not connect to AWS: %s. Falling back to demo mode.", exc)
            self.demo_mode = True
            self.topology = load_demo_topology()


_runtime: ServerRuntime | None = None


def get_runtime() -> ServerRuntime:
    """Return the process-wide runtime, creating it on first use."""
    global _runtime
    if _runtime is None:
        _runtime = ServerRuntime()
    return _runtime


def reset_runtime(demo_mode: bool = True) -> ServerRuntime:
    """Replace the process-wide runtime. Used by tests."""
    global _runtime
    _runtime = ServerRuntime(demo_mode=demo_mode)
    return _runtime


@mcp.tool(name="describe_path")
def describe_path_tool(
    source_instance_id: str | None = None,
    source_eni_id: str | None = None,
    source_ip: str | None = None,
    dest_instance_id: str | None = None,
    dest_eni_id: str | None = None,
    dest_ip: str | None = None,
    port: int = 443,
    protocol: str = "tcp",
) -> dict[str, Any]:
    """Analyze the hop-by-hop path between two endpoints.

    Walks security groups, NACLs, VPC route tables, Transit Gateway route tables
    (static, propagated, blackhole), inspection VPC / Network Firewall, and
    on-prem VPN/DX routes. Returns the exact rule or route that allowed or dropped
    the flow at each hop.
    """
    runtime = get_runtime()
    return describe_path(
        source_instance_id=source_instance_id,
        source_eni_id=source_eni_id,
        source_ip=source_ip,
        dest_instance_id=dest_instance_id,
        dest_eni_id=dest_eni_id,
        dest_ip=dest_ip,
        port=port,
        protocol=protocol,
        ec2_client=runtime.ec2_client,
        topology=runtime.topology,
    )


@mcp.tool(name="explain_connectivity")
def explain_connectivity_tool(
    source_ip: str,
    dest_ip: str,
    port: int = 443,
    protocol: str = "tcp",
) -> dict[str, Any]:
    """Explain why source_ip can or cannot reach dest_ip.

    Simplified IP-based interface that returns a human-readable hop list.
    """
    runtime = get_runtime()
    return explain_connectivity(
        source_ip=source_ip,
        dest_ip=dest_ip,
        port=port,
        protocol=protocol,
        ec2_client=runtime.ec2_client,
        topology=runtime.topology,
    )


@mcp.tool(name="run_reachability_analysis")
def run_reachability_analysis_tool(
    source: str,
    destination: str,
    destination_port: int | None = None,
    protocol: str = "tcp",
) -> dict[str, Any]:
    """Run VPC Reachability Analyzer. Charges apply (~$0.10 per path)."""
    runtime = get_runtime()
    return run_reachability_analysis(
        source=source,
        destination=destination,
        destination_port=destination_port,
        protocol=protocol,
        ec2_client=runtime.ec2_client,
    )


@mcp.tool(name="tgw_route_lookup")
def tgw_route_lookup_tool(tgw_route_table_id: str, destination_cidr: str) -> dict[str, Any]:
    """Longest-prefix match in a Transit Gateway route table."""
    runtime = get_runtime()
    return tgw_route_lookup(
        tgw_route_table_id=tgw_route_table_id,
        destination_cidr=destination_cidr,
        ec2_client=runtime.ec2_client,
        topology=runtime.topology,
    )


@mcp.tool(name="list_tgw_attachments")
def list_tgw_attachments_tool(tgw_id: str | None = None) -> dict[str, Any]:
    """List Transit Gateway attachments and their associated route tables."""
    runtime = get_runtime()
    return list_tgw_attachments(
        tgw_id=tgw_id,
        ec2_client=runtime.ec2_client,
        topology=runtime.topology,
    )


@mcp.tool(name="inspect_vpn_bgp")
def inspect_vpn_bgp_tool(vpn_id: str | None = None) -> dict[str, Any]:
    """Inspect Site-to-Site VPN tunnel / BGP state and Direct Connect VIFs."""
    runtime = get_runtime()
    return inspect_vpn_bgp(
        vpn_id=vpn_id,
        ec2_client=runtime.ec2_client,
        topology=runtime.topology,
    )


@mcp.tool(name="check_dns_resolution")
def check_dns_resolution_tool(domain: str, vpc_id: str) -> dict[str, Any]:
    """Check Route 53 Resolver forwarding for a domain from a VPC."""
    runtime = get_runtime()
    return check_dns_resolution(
        domain=domain,
        vpc_id=vpc_id,
        route53_client=runtime.route53_client,
    )


@mcp.tool(name="query_flow_logs")
def query_flow_logs_tool(
    log_group: str,
    src_addr: str | None = None,
    dst_addr: str | None = None,
    dst_port: int | None = None,
    action: str | None = None,
) -> dict[str, Any]:
    """Query VPC Flow Logs for a 5-tuple filter."""
    runtime = get_runtime()
    return query_flow_logs(
        log_group=log_group,
        src_addr=src_addr,
        dst_addr=dst_addr,
        dst_port=dst_port,
        action=action,
        logs_client=runtime.logs_client,
    )


@mcp.tool(name="load_demo_scenario")
def load_demo_scenario_tool(scenario_name: str) -> dict[str, Any]:
    """Load a fixture topology with a known misconfiguration or allowed path."""
    runtime = get_runtime()
    loaded = get_scenario(scenario_name)
    if loaded is None:
        return {
            "error": f"Unknown scenario: {scenario_name}",
            "available": list(DEMO_SCENARIOS.keys()),
        }
    scenario, topology = loaded
    runtime.topology = topology
    runtime.current_scenario = scenario_name
    return {
        "loaded": scenario_name,
        "description": scenario.description,
        "expected_verdict": scenario.expected_verdict.value,
        "test_case": {
            "source_ip": scenario.source.ip,
            "source_eni": scenario.source.eni_id,
            "destination_ip": scenario.destination.ip,
            "port": scenario.port,
            "protocol": scenario.protocol.value,
        },
        "hint": "Use explain_connectivity or describe_path to diagnose this scenario",
    }


@mcp.tool(name="list_demo_scenarios")
def list_demo_scenarios_tool() -> dict[str, Any]:
    """List offline demo scenarios (landing-zone segmentation and classic misconfigs)."""
    runtime = get_runtime()
    return {
        "scenarios": [
            {
                "name": name,
                "description": scenario.description,
                "expected_verdict": scenario.expected_verdict.value,
            }
            for name, (scenario, _) in DEMO_SCENARIOS.items()
        ],
        "current_scenario": runtime.current_scenario,
    }


def main() -> None:
    """Entry point for the MCP server (stdio)."""
    get_runtime()
    mcp.run()


if __name__ == "__main__":
    main()
