"""Pytest configuration and shared fixtures."""

from __future__ import annotations

import pytest

from aws_network_mcp.analysis.path_analyzer import NetworkTopology
from aws_network_mcp.fixtures.topology import load_demo_topology
from aws_network_mcp.models import (
    NaclInfo,
    NaclRule,
    NetworkEndpoint,
    RouteEntry,
    RouteTableInfo,
    SecurityGroupInfo,
    SecurityGroupRule,
    TgwRouteEntry,
    TgwRouteTableInfo,
)


@pytest.fixture
def demo_topology() -> NetworkTopology:
    """Load the standard demo topology."""
    return load_demo_topology()


@pytest.fixture
def simple_topology() -> NetworkTopology:
    """Create a simple topology for focused testing."""
    return NetworkTopology(
        route_tables={
            "rtb-001": RouteTableInfo(
                route_table_id="rtb-001",
                vpc_id="vpc-001",
                name="test-rt",
                routes=(
                    RouteEntry("10.0.0.0/16", "local", "local", "active"),
                    RouteEntry("10.1.0.0/16", "transit-gateway", "tgw-001", "active"),
                    RouteEntry("0.0.0.0/0", "nat-gateway", "nat-001", "active"),
                ),
                subnet_associations=("subnet-001",),
            ),
            "rtb-002": RouteTableInfo(
                route_table_id="rtb-002",
                vpc_id="vpc-002",
                name="dest-rt",
                routes=(
                    RouteEntry("10.1.0.0/16", "local", "local", "active"),
                    RouteEntry("10.0.0.0/16", "transit-gateway", "tgw-001", "active"),
                ),
                subnet_associations=("subnet-002",),
            ),
        },
        security_groups={
            "sg-001": SecurityGroupInfo(
                sg_id="sg-001",
                name="allow-all",
                vpc_id="vpc-001",
                rules=(
                    SecurityGroupRule("ingress", "-1", None, None, "0.0.0.0/0"),
                    SecurityGroupRule("egress", "-1", None, None, "0.0.0.0/0"),
                ),
            ),
            "sg-002": SecurityGroupInfo(
                sg_id="sg-002",
                name="allow-443-only",
                vpc_id="vpc-002",
                rules=(
                    SecurityGroupRule("ingress", "6", 443, 443, "10.0.0.0/8"),
                    SecurityGroupRule("egress", "-1", None, None, "0.0.0.0/0"),
                ),
            ),
        },
        nacls={
            "acl-001": NaclInfo(
                nacl_id="acl-001",
                vpc_id="vpc-001",
                name="allow-all-nacl",
                rules=(
                    NaclRule(100, "ingress", "-1", None, None, "0.0.0.0/0", "allow"),
                    NaclRule(100, "egress", "-1", None, None, "0.0.0.0/0", "allow"),
                ),
                subnet_associations=("subnet-001",),
            ),
            "acl-002": NaclInfo(
                nacl_id="acl-002",
                vpc_id="vpc-002",
                name="allow-all-nacl",
                rules=(
                    NaclRule(100, "ingress", "-1", None, None, "0.0.0.0/0", "allow"),
                    NaclRule(100, "egress", "-1", None, None, "0.0.0.0/0", "allow"),
                ),
                subnet_associations=("subnet-002",),
            ),
        },
        tgw_route_tables={
            "tgw-rtb-001": TgwRouteTableInfo(
                tgw_rt_id="tgw-rtb-001",
                tgw_id="tgw-001",
                name="main-tgw-rt",
                routes=(
                    TgwRouteEntry(
                        "10.0.0.0/16", "tgw-att-001", "vpc", "vpc-001", "active", "propagated"
                    ),
                    TgwRouteEntry(
                        "10.1.0.0/16", "tgw-att-002", "vpc", "vpc-002", "active", "propagated"
                    ),
                ),
                associations=("tgw-att-001", "tgw-att-002"),
                propagations=("tgw-att-001", "tgw-att-002"),
            ),
        },
        subnet_to_route_table={
            "subnet-001": "rtb-001",
            "subnet-002": "rtb-002",
        },
        subnet_to_nacl={
            "subnet-001": "acl-001",
            "subnet-002": "acl-002",
        },
        eni_to_security_groups={
            "eni-001": ["sg-001"],
            "eni-002": ["sg-002"],
        },
        subnet_to_vpc={
            "subnet-001": "vpc-001",
            "subnet-002": "vpc-002",
        },
        tgw_attachment_to_route_table={
            "tgw-att-001": "tgw-rtb-001",
            "tgw-att-002": "tgw-rtb-001",
        },
        vpc_to_tgw_attachment={
            "vpc-001": "tgw-att-001",
            "vpc-002": "tgw-att-002",
        },
        prefix_list_cidrs={},
    )


@pytest.fixture
def source_endpoint() -> NetworkEndpoint:
    """Standard source endpoint for tests."""
    return NetworkEndpoint(
        ip="10.0.0.100",
        vpc_id="vpc-001",
        subnet_id="subnet-001",
        eni_id="eni-001",
    )


@pytest.fixture
def dest_endpoint() -> NetworkEndpoint:
    """Standard destination endpoint for tests."""
    return NetworkEndpoint(
        ip="10.1.0.100",
        vpc_id="vpc-002",
        subnet_id="subnet-002",
        eni_id="eni-002",
    )
