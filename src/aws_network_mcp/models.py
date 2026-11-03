"""Data models for AWS network analysis.

These models are pure Python/Pydantic with no AWS SDK dependencies,
enabling clean separation between analysis logic and API calls.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal


class Verdict(StrEnum):
    """Analysis verdict for a network path or rule evaluation."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    UNKNOWN = "UNKNOWN"
    BLACKHOLE = "BLACKHOLE"


class Protocol(StrEnum):
    """Network protocol for connectivity analysis."""

    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ALL = "all"


@dataclass(frozen=True)
class NetworkEndpoint:
    """Represents a source or destination in connectivity analysis."""

    ip: str
    vpc_id: str | None = None
    subnet_id: str | None = None
    instance_id: str | None = None
    eni_id: str | None = None
    is_on_prem: bool = False


@dataclass(frozen=True)
class ConnectivityRequest:
    """Input for connectivity analysis."""

    source: NetworkEndpoint
    destination: NetworkEndpoint
    port: int
    protocol: Protocol = Protocol.TCP


@dataclass(frozen=True)
class RouteEntry:
    """A single route table entry."""

    destination_cidr: str
    target_type: str
    target_id: str
    state: Literal["active", "blackhole"]
    propagated: bool = False
    prefix_list_id: str | None = None


@dataclass(frozen=True)
class RouteTableInfo:
    """Route table with its routes."""

    route_table_id: str
    vpc_id: str
    name: str | None
    routes: tuple[RouteEntry, ...]
    subnet_associations: tuple[str, ...]


@dataclass(frozen=True)
class SecurityGroupRule:
    """A single security group rule."""

    direction: Literal["ingress", "egress"]
    protocol: str
    from_port: int | None
    to_port: int | None
    cidr: str | None = None
    source_sg_id: str | None = None
    prefix_list_id: str | None = None
    description: str | None = None


@dataclass(frozen=True)
class SecurityGroupInfo:
    """Security group with its rules."""

    sg_id: str
    name: str
    vpc_id: str
    rules: tuple[SecurityGroupRule, ...]


@dataclass(frozen=True)
class NaclRule:
    """A single NACL rule."""

    rule_number: int
    direction: Literal["ingress", "egress"]
    protocol: str
    from_port: int | None
    to_port: int | None
    cidr: str
    action: Literal["allow", "deny"]


@dataclass(frozen=True)
class NaclInfo:
    """Network ACL with its rules."""

    nacl_id: str
    vpc_id: str
    name: str | None
    rules: tuple[NaclRule, ...]
    subnet_associations: tuple[str, ...]


@dataclass(frozen=True)
class TgwAttachment:
    """Transit Gateway attachment."""

    attachment_id: str
    tgw_id: str
    attachment_type: Literal["vpc", "vpn", "direct-connect-gateway", "peering", "connect"]
    state: str
    resource_id: str
    resource_owner_id: str
    name: str | None = None


@dataclass(frozen=True)
class TgwRouteEntry:
    """Transit Gateway route table entry."""

    destination_cidr: str
    attachment_id: str | None
    resource_type: str | None
    resource_id: str | None
    state: Literal["active", "blackhole"]
    route_type: Literal["static", "propagated"]
    prefix_list_id: str | None = None


@dataclass(frozen=True)
class TgwRouteTableInfo:
    """Transit Gateway route table."""

    tgw_rt_id: str
    tgw_id: str
    name: str | None
    routes: tuple[TgwRouteEntry, ...]
    associations: tuple[str, ...]
    propagations: tuple[str, ...]


@dataclass(frozen=True)
class VpnTunnelInfo:
    """VPN tunnel status information."""

    tunnel_id: str
    outside_ip: str
    status: Literal["UP", "DOWN"]
    status_message: str | None
    bgp_status: Literal["UP", "DOWN"] | None = None
    routes_received: int | None = None


@dataclass(frozen=True)
class VpnConnectionInfo:
    """Site-to-Site VPN connection."""

    vpn_id: str
    state: str
    tgw_id: str | None
    customer_gateway_ip: str
    tunnels: tuple[VpnTunnelInfo, ...]
    name: str | None = None


@dataclass(frozen=True)
class DxVifInfo:
    """Direct Connect virtual interface."""

    vif_id: str
    vif_type: Literal["private", "public", "transit"]
    state: str
    bgp_status: str
    vlan: int
    amazon_address: str | None
    customer_address: str | None
    bgp_asn: int | None


@dataclass(frozen=True)
class DnsForwardingRule:
    """Route 53 Resolver forwarding rule."""

    rule_id: str
    domain_name: str
    rule_type: Literal["FORWARD", "SYSTEM", "RECURSIVE"]
    target_ips: tuple[str, ...]
    vpc_associations: tuple[str, ...]
    name: str | None = None


@dataclass(frozen=True)
class ResolverEndpoint:
    """Route 53 Resolver endpoint."""

    endpoint_id: str
    direction: Literal["INBOUND", "OUTBOUND"]
    vpc_id: str
    ip_addresses: tuple[str, ...]
    status: str
    name: str | None = None


@dataclass
class HopAnalysis:
    """Analysis result for a single hop in the path."""

    hop_type: str
    resource_id: str
    resource_name: str | None
    verdict: Verdict
    details: str
    blocking_rule: str | None = None
    matched_route: str | None = None


@dataclass
class PathAnalysisResult:
    """Complete path analysis result."""

    source: NetworkEndpoint
    destination: NetworkEndpoint
    port: int
    protocol: Protocol
    overall_verdict: Verdict
    hops: list[HopAnalysis] = field(default_factory=list)
    summary: str = ""
    blocking_hop: HopAnalysis | None = None


@dataclass(frozen=True)
class FlowLogEntry:
    """A single VPC Flow Log entry."""

    timestamp: str
    src_addr: str
    dst_addr: str
    src_port: int
    dst_port: int
    protocol: int
    action: Literal["ACCEPT", "REJECT"]
    log_status: str
    interface_id: str | None = None


@dataclass
class ReachabilityAnalysisResult:
    """VPC Reachability Analyzer result."""

    analysis_id: str
    path_id: str
    status: str
    reachable: bool | None
    explanations: list[str] = field(default_factory=list)
    forward_path: list[str] = field(default_factory=list)
    return_path: list[str] = field(default_factory=list)
    cost_note: str = (
        "This analysis incurs a ~$0.10 charge per path analyzed. See AWS pricing for current rates."
    )
