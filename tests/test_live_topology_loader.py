"""Live topology loader tests using moto and botocore Stubber."""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from typing import Any

import boto3
from moto import mock_aws

from aws_network_mcp.analysis.path_analyzer import PathAnalyzer
from aws_network_mcp.analysis.suricata_parser import parse_suricata_rules
from aws_network_mcp.aws_client.ec2_client import EC2Client
from aws_network_mcp.aws_client.nfw_client import NetworkFirewallClient
from aws_network_mcp.aws_client.topology_loader import LiveTopologyLoader
from aws_network_mcp.models import FirewallPolicy, NetworkEndpoint, Protocol, Verdict

LANDING_ZONE_RULES = """
drop ip 10.10.0.0/24 any -> 10.20.0.0/24 any (msg:"Deny prod to nonprod"; sid:1000001; rev:1;)
drop ip 10.20.0.0/24 any -> 10.10.0.0/24 any (msg:"Deny nonprod to prod"; sid:1000002; rev:1;)
drop ip 10.20.0.0/24 any -> 10.200.0.0/16 any (msg:"Deny nonprod to onprem"; sid:1000003; rev:1;)
pass ip 10.10.0.0/24 any -> 10.1.0.0/24 any (msg:"Allow prod to shared"; sid:2000001; rev:1;)
pass ip 10.10.0.0/24 any -> 10.200.0.0/16 any (msg:"Allow prod to onprem"; sid:2000005; rev:1;)
pass ip 10.20.0.0/24 any -> 10.1.0.0/24 any (msg:"Allow nonprod to shared"; sid:2000003; rev:1;)
"""


@dataclass
class MotoHub:
    """IDs created in moto for a landing-zone-shaped hub."""

    vpcs: dict[str, str]
    subnets: dict[str, str]
    attachments: dict[str, str]
    tgw_rts: dict[str, str]
    ips: dict[str, str]
    tgw_id: str


class _NfwFromString(NetworkFirewallClient):
    """NFW client that returns a parsed Suricata policy for a known inspection VPC."""

    def __init__(self, inspection_vpc_id: str, rules: str) -> None:
        self._inspection_vpc_id = inspection_vpc_id
        self._rules = rules

    def load_policies(self) -> tuple[dict[str, FirewallPolicy], frozenset[str], tuple[str, ...]]:
        parsed = parse_suricata_rules(self._rules, source_name="hybrid-stateful")
        policy = FirewallPolicy(
            policy_id="nfw-policy-inspection-001",
            name="hybrid-network-inspection-policy",
            rule_order="STRICT_ORDER",
            default_action="aws:drop_established",
            rules=tuple(parsed.rules),
        )
        return (
            {policy.policy_id: policy},
            frozenset({self._inspection_vpc_id}),
            tuple(parsed.unsupported),
        )


class _EC2WithTgwRoutes(EC2Client):
    """moto EC2 client with AWS-shaped TGW search results (attachment IDs present)."""

    def __init__(self, route_override: dict[str, list[dict[str, Any]]], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._route_override = route_override

    def search_tgw_routes(self, tgw_rt_id: str) -> list[dict[str, Any]]:
        if tgw_rt_id in self._route_override:
            return self._route_override[tgw_rt_id]
        return super().search_tgw_routes(tgw_rt_id)


def _create_spoke(ec2: Any, cidr: str, name: str, ip: str) -> tuple[str, str, str, str]:
    vpc = ec2.create_vpc(CidrBlock=cidr)["Vpc"]
    ec2.create_tags(
        Resources=[vpc["VpcId"]],
        Tags=[{"Key": "Name", "Value": name}, {"Key": "Role", "Value": name}],
    )
    subnet = ec2.create_subnet(VpcId=vpc["VpcId"], CidrBlock=cidr)["Subnet"]
    sg = ec2.create_security_group(
        GroupName=f"{name}-app", Description=f"{name} app", VpcId=vpc["VpcId"]
    )
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "10.0.0.0/8", "Description": "RFC1918"}],
            }
        ],
    )
    eni = ec2.create_network_interface(
        SubnetId=subnet["SubnetId"],
        PrivateIpAddress=ip,
        Groups=[sg["GroupId"]],
        Description=f"{name}-app",
    )["NetworkInterface"]
    return vpc["VpcId"], subnet["SubnetId"], sg["GroupId"], eni["NetworkInterfaceId"]


def _associate(ec2: Any, tgw_rt: str, attachment: str) -> None:
    with contextlib.suppress(Exception):
        ec2.associate_transit_gateway_route_table(
            TransitGatewayRouteTableId=tgw_rt, TransitGatewayAttachmentId=attachment
        )


def build_moto_landing_zone(ec2: Any) -> MotoHub:
    """Create VPCs, TGW attachments, a VPN, and custom TGW RTs in moto."""
    prod_vpc, prod_subnet, _, _ = _create_spoke(ec2, "10.10.0.0/24", "prod", "10.10.0.10")
    nonprod_vpc, nonprod_subnet, _, _ = _create_spoke(ec2, "10.20.0.0/24", "nonprod", "10.20.0.10")
    shared_vpc, shared_subnet, _, _ = _create_spoke(ec2, "10.1.0.0/24", "shared", "10.1.0.10")
    insp_vpc, insp_subnet, _, _ = _create_spoke(ec2, "10.0.0.0/24", "inspection", "10.0.0.10")

    tgw = ec2.create_transit_gateway()["TransitGateway"]
    tgw_id = tgw["TransitGatewayId"]

    def attach(vpc_id: str, subnet_id: str, name: str) -> str:
        att = ec2.create_transit_gateway_vpc_attachment(
            TransitGatewayId=tgw_id,
            VpcId=vpc_id,
            SubnetIds=[subnet_id],
            TagSpecifications=[
                {
                    "ResourceType": "transit-gateway-attachment",
                    "Tags": [{"Key": "Name", "Value": name}],
                }
            ],
        )["TransitGatewayVpcAttachment"]
        return str(att["TransitGatewayAttachmentId"])

    attachments = {
        "prod": attach(prod_vpc, prod_subnet, "prod"),
        "nonprod": attach(nonprod_vpc, nonprod_subnet, "nonprod"),
        "shared": attach(shared_vpc, shared_subnet, "shared"),
        "inspection": attach(insp_vpc, insp_subnet, "inspection"),
    }

    cgw = ec2.create_customer_gateway(Type="ipsec.1", PublicIp="203.0.113.1", BgpAsn=65000)
    ec2.create_vpn_connection(
        Type="ipsec.1",
        CustomerGatewayId=cgw["CustomerGateway"]["CustomerGatewayId"],
        TransitGatewayId=tgw_id,
        TagSpecifications=[
            {"ResourceType": "vpn-connection", "Tags": [{"Key": "Name", "Value": "onprem"}]}
        ],
    )
    vpn_att = next(
        att["TransitGatewayAttachmentId"]
        for att in ec2.describe_transit_gateway_attachments()["TransitGatewayAttachments"]
        if att.get("ResourceType") == "vpn"
    )
    attachments["vpn"] = str(vpn_att)

    def make_rt(name: str) -> str:
        table = ec2.create_transit_gateway_route_table(
            TransitGatewayId=tgw_id,
            TagSpecifications=[
                {
                    "ResourceType": "transit-gateway-route-table",
                    "Tags": [{"Key": "Name", "Value": name}],
                }
            ],
        )["TransitGatewayRouteTable"]
        return str(table["TransitGatewayRouteTableId"])

    tgw_rts = {
        "prod": make_rt("prod"),
        "nonprod": make_rt("nonprod"),
        "shared": make_rt("shared"),
        "inspection": make_rt("inspection"),
        "onprem": make_rt("onprem"),
    }
    _associate(ec2, tgw_rts["prod"], attachments["prod"])
    _associate(ec2, tgw_rts["nonprod"], attachments["nonprod"])
    _associate(ec2, tgw_rts["shared"], attachments["shared"])
    _associate(ec2, tgw_rts["inspection"], attachments["inspection"])
    _associate(ec2, tgw_rts["onprem"], attachments["vpn"])

    for vpc_id in (prod_vpc, nonprod_vpc, shared_vpc, insp_vpc):
        tables = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])[
            "RouteTables"
        ]
        main = next(rt for rt in tables if any(assoc.get("Main") for assoc in rt["Associations"]))
        ec2.create_route(
            RouteTableId=main["RouteTableId"],
            DestinationCidrBlock="0.0.0.0/0",
            TransitGatewayId=tgw_id,
        )

    return MotoHub(
        vpcs={
            "prod": prod_vpc,
            "nonprod": nonprod_vpc,
            "shared": shared_vpc,
            "inspection": insp_vpc,
        },
        subnets={
            "prod": prod_subnet,
            "nonprod": nonprod_subnet,
            "shared": shared_subnet,
            "inspection": insp_subnet,
        },
        attachments=attachments,
        tgw_rts=tgw_rts,
        ips={"prod": "10.10.0.10", "nonprod": "10.20.0.10", "shared": "10.1.0.10"},
        tgw_id=tgw_id,
    )


def _landing_zone_routes(hub: MotoHub) -> dict[str, list[dict[str, Any]]]:
    att = hub.attachments

    def static(cidr: str, attachment: str | None, blackhole: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "DestinationCidrBlock": cidr,
            "State": "blackhole" if blackhole else "active",
            "Type": "static",
        }
        if attachment and not blackhole:
            payload["TransitGatewayAttachments"] = [
                {"TransitGatewayAttachmentId": attachment, "ResourceType": "vpc"}
            ]
        return payload

    def propagated(cidr: str, attachment: str, resource_type: str) -> dict[str, Any]:
        return {
            "DestinationCidrBlock": cidr,
            "State": "active",
            "Type": "propagated",
            "TransitGatewayAttachments": [
                {
                    "TransitGatewayAttachmentId": attachment,
                    "ResourceType": resource_type,
                }
            ],
        }

    return {
        hub.tgw_rts["prod"]: [
            static("10.20.0.0/24", None, blackhole=True),
            static("10.1.0.0/24", att["inspection"]),
            static("10.200.0.0/16", att["inspection"]),
            static("10.0.0.0/24", att["inspection"]),
        ],
        hub.tgw_rts["nonprod"]: [
            static("10.10.0.0/24", None, blackhole=True),
            static("10.200.0.0/16", None, blackhole=True),
            static("10.1.0.0/24", att["inspection"]),
            static("10.0.0.0/24", att["inspection"]),
        ],
        hub.tgw_rts["shared"]: [
            static("10.10.0.0/24", att["inspection"]),
            static("10.20.0.0/24", att["inspection"]),
            static("10.200.0.0/16", att["inspection"]),
        ],
        hub.tgw_rts["inspection"]: [
            static("10.10.0.0/24", att["prod"]),
            static("10.20.0.0/24", att["nonprod"]),
            static("10.1.0.0/24", att["shared"]),
            propagated("10.200.0.0/16", att["vpn"], "vpn"),
        ],
        hub.tgw_rts["onprem"]: [
            static("10.10.0.0/24", att["inspection"]),
            static("10.1.0.0/24", att["inspection"]),
            static("10.20.0.0/24", None, blackhole=True),
        ],
    }


@mock_aws
def test_live_loader_reads_vpc_inventory_from_moto() -> None:
    region = "us-east-1"
    raw = boto3.client("ec2", region_name=region)
    hub = build_moto_landing_zone(raw)
    client = EC2Client(region=region)
    topology = LiveTopologyLoader(client, nfw_client=None).load()

    assert hub.vpcs["prod"] in topology.vpc_to_tgw_attachment
    assert hub.ips["prod"] in topology.known_endpoints
    assert topology.known_endpoints[hub.ips["prod"]].subnet_id == hub.subnets["prod"]
    assert topology.vpc_cidrs[hub.vpcs["prod"]]
    assert hub.attachments["vpn"] in topology.attachments
    assert topology.attachments[hub.attachments["vpn"]].attachment_type == "vpn"
    assert topology.inspection_vpc_id == hub.vpcs["inspection"]
    assert hub.attachments["inspection"] in topology.inspection_attachment_ids


@mock_aws
def test_live_loader_landing_zone_path_analysis() -> None:
    region = "us-east-1"
    session = boto3.Session(region_name=region)
    raw = session.client("ec2")
    hub = build_moto_landing_zone(raw)
    ec2 = _EC2WithTgwRoutes(_landing_zone_routes(hub), region=region, session=session, client=raw)
    nfw = _NfwFromString(hub.vpcs["inspection"], LANDING_ZONE_RULES)
    topology = LiveTopologyLoader(ec2, nfw).load()

    assert topology.inspection_vpc_id == hub.vpcs["inspection"]
    assert topology.vpn_attachment_id == hub.attachments["vpn"]
    assert "10.200.0.0/16" in topology.on_prem_cidrs
    assert topology.firewall_policies
    policy = next(iter(topology.firewall_policies.values()))
    assert policy.rule_order == "STRICT_ORDER"
    assert any(rule.sid == "1000001" for rule in policy.rules)

    analyzer = PathAnalyzer(topology)
    prod = topology.known_endpoints["10.10.0.10"]
    nonprod = topology.known_endpoints["10.20.0.10"]
    shared = topology.known_endpoints["10.1.0.10"]
    onprem = NetworkEndpoint(ip="10.200.1.50", is_on_prem=True)

    blocked = analyzer.analyze_path(prod, nonprod, 443, Protocol.TCP)
    assert blocked.overall_verdict == Verdict.BLACKHOLE
    assert blocked.blocking_hop is not None
    assert blocked.blocking_hop.hop_type == "transit_gateway"
    assert any("1000001" in finding for finding in blocked.additional_findings)

    allowed = analyzer.analyze_path(prod, shared, 443, Protocol.TCP)
    assert allowed.overall_verdict == Verdict.ALLOW
    hop_types = [hop.hop_type for hop in allowed.hops]
    assert "network_firewall" in hop_types
    fw = next(hop for hop in allowed.hops if hop.hop_type == "network_firewall")
    assert "sid:2000001" in fw.details

    hybrid = analyzer.analyze_path(prod, onprem, 443, Protocol.TCP)
    assert hybrid.overall_verdict == Verdict.ALLOW
    assert any(hop.hop_type == "on_prem" for hop in hybrid.hops)
    fw = next(hop for hop in hybrid.hops if hop.hop_type == "network_firewall")
    assert "sid:2000005" in fw.details
    inspection_rt = next(
        hop
        for hop in hybrid.hops
        if hop.hop_type == "transit_gateway" and hop.resource_id == hub.tgw_rts["inspection"]
    )
    assert inspection_rt.matched_route is not None
    assert "10.200.0.0/16" in inspection_rt.matched_route
    assert "propagated" in inspection_rt.matched_route

    denied_hybrid = analyzer.analyze_path(nonprod, onprem, 443, Protocol.TCP)
    assert denied_hybrid.overall_verdict == Verdict.BLACKHOLE
    assert any("1000003" in finding for finding in denied_hybrid.additional_findings)
