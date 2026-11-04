"""Demo topology matching aws-hybrid-network-landing-zone.

CIDRs and TGW segmentation follow examples/complete in
https://github.com/harin-singh/aws-hybrid-network-landing-zone

- Inspection VPC 10.0.0.0/24
- Shared Services 10.1.0.0/24
- Prod 10.10.0.0/24
- Nonprod 10.20.0.0/24
- On-prem advertised via BGP 10.200.0.0/16
- Simulated on-prem VPC 192.168.100.0/24
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aws_network_mcp.analysis.path_analyzer import NetworkTopology
from aws_network_mcp.models import (
    FirewallPolicy,
    FirewallRule,
    NaclInfo,
    NaclRule,
    NetworkEndpoint,
    RouteEntry,
    RouteTableInfo,
    SecurityGroupInfo,
    SecurityGroupRule,
    TgwAttachment,
    TgwRouteEntry,
    TgwRouteTableInfo,
)


class DemoTopology:
    """Landing-zone topology builder for offline testing."""

    VPC_INSPECTION = "vpc-inspection-001"
    VPC_SHARED = "vpc-shared-001"
    VPC_PROD = "vpc-prod-001"
    VPC_NONPROD = "vpc-nonprod-001"

    CIDR_INSPECTION = "10.0.0.0/24"
    CIDR_SHARED = "10.1.0.0/24"
    CIDR_PROD = "10.10.0.0/24"
    CIDR_NONPROD = "10.20.0.0/24"
    CIDR_ONPREM = "10.200.0.0/16"
    CIDR_ONPREM_VPC = "192.168.100.0/24"

    SUBNET_PROD_APP = "subnet-prod-app-001"
    SUBNET_PROD_DB = "subnet-prod-db-002"
    SUBNET_NONPROD_APP = "subnet-nonprod-app-001"
    SUBNET_SHARED_DNS = "subnet-shared-dns-001"
    SUBNET_INSPECTION = "subnet-inspection-001"

    TGW_ID = "tgw-demo-001"
    TGW_ATT_PROD = "tgw-attach-prod-001"
    TGW_ATT_NONPROD = "tgw-attach-nonprod-002"
    TGW_ATT_SHARED = "tgw-attach-shared-003"
    TGW_ATT_INSPECTION = "tgw-attach-inspection-004"
    TGW_ATT_VPN = "tgw-attach-vpn-005"

    TGW_RT_PROD = "tgw-rtb-prod-001"
    TGW_RT_NONPROD = "tgw-rtb-nonprod-002"
    TGW_RT_SHARED = "tgw-rtb-shared-003"
    TGW_RT_INSPECTION = "tgw-rtb-inspection-004"
    TGW_RT_ONPREM = "tgw-rtb-onprem-005"

    ENI_PROD_APP = "eni-prod-app-001"
    ENI_PROD_DB = "eni-prod-db-002"
    ENI_NONPROD_APP = "eni-nonprod-app-001"
    ENI_SHARED_DNS = "eni-shared-dns-001"

    IP_PROD_APP = "10.10.0.10"
    IP_PROD_DB = "10.10.0.20"
    IP_NONPROD_APP = "10.20.0.10"
    IP_SHARED_DNS = "10.1.0.10"
    IP_ONPREM = "10.200.1.50"

    SG_PROD_APP = "sg-prod-app-001"
    SG_PROD_DB = "sg-prod-db-002"
    SG_NONPROD_APP = "sg-nonprod-app-001"
    SG_SHARED_DNS = "sg-shared-dns-001"

    NACL_PROD = "acl-prod-001"
    NACL_NONPROD = "acl-nonprod-001"
    NACL_SHARED = "acl-shared-001"

    FW_POLICY_ID = "nfw-policy-inspection-001"

    @classmethod
    def build_healthy_topology(cls) -> NetworkTopology:
        """Build the landing-zone topology with segmentation intact."""
        known = {
            cls.IP_PROD_APP: NetworkEndpoint(
                ip=cls.IP_PROD_APP,
                vpc_id=cls.VPC_PROD,
                subnet_id=cls.SUBNET_PROD_APP,
                eni_id=cls.ENI_PROD_APP,
            ),
            cls.IP_PROD_DB: NetworkEndpoint(
                ip=cls.IP_PROD_DB,
                vpc_id=cls.VPC_PROD,
                subnet_id=cls.SUBNET_PROD_DB,
                eni_id=cls.ENI_PROD_DB,
            ),
            cls.IP_NONPROD_APP: NetworkEndpoint(
                ip=cls.IP_NONPROD_APP,
                vpc_id=cls.VPC_NONPROD,
                subnet_id=cls.SUBNET_NONPROD_APP,
                eni_id=cls.ENI_NONPROD_APP,
            ),
            cls.IP_SHARED_DNS: NetworkEndpoint(
                ip=cls.IP_SHARED_DNS,
                vpc_id=cls.VPC_SHARED,
                subnet_id=cls.SUBNET_SHARED_DNS,
                eni_id=cls.ENI_SHARED_DNS,
            ),
            cls.IP_ONPREM: NetworkEndpoint(ip=cls.IP_ONPREM, is_on_prem=True),
        }
        return NetworkTopology(
            route_tables=cls._build_route_tables(),
            security_groups=cls._build_security_groups(),
            nacls=cls._build_nacls(),
            tgw_route_tables=cls._build_tgw_route_tables(),
            subnet_to_route_table=cls._build_subnet_rt_mapping(),
            subnet_to_nacl=cls._build_subnet_nacl_mapping(),
            eni_to_security_groups=cls._build_eni_sg_mapping(),
            subnet_to_vpc=cls._build_subnet_vpc_mapping(),
            tgw_attachment_to_route_table=cls._build_tgw_attachment_rt_mapping(),
            vpc_to_tgw_attachment=cls._build_vpc_tgw_attachment_mapping(),
            prefix_list_cidrs={},
            attachments=cls._build_attachments(),
            inspection_attachment_ids=frozenset({cls.TGW_ATT_INSPECTION}),
            firewall_policies={cls.FW_POLICY_ID: cls._build_firewall_policy()},
            inspection_vpc_id=cls.VPC_INSPECTION,
            vpn_attachment_id=cls.TGW_ATT_VPN,
            known_endpoints=known,
            on_prem_cidrs=(cls.CIDR_ONPREM, cls.CIDR_ONPREM_VPC),
        )

    @classmethod
    def _build_attachments(cls) -> dict[str, TgwAttachment]:
        return {
            cls.TGW_ATT_PROD: TgwAttachment(
                cls.TGW_ATT_PROD,
                cls.TGW_ID,
                "vpc",
                "available",
                cls.VPC_PROD,
                "111111111111",
                "prod",
            ),
            cls.TGW_ATT_NONPROD: TgwAttachment(
                cls.TGW_ATT_NONPROD,
                cls.TGW_ID,
                "vpc",
                "available",
                cls.VPC_NONPROD,
                "111111111111",
                "nonprod",
            ),
            cls.TGW_ATT_SHARED: TgwAttachment(
                cls.TGW_ATT_SHARED,
                cls.TGW_ID,
                "vpc",
                "available",
                cls.VPC_SHARED,
                "111111111111",
                "shared",
            ),
            cls.TGW_ATT_INSPECTION: TgwAttachment(
                cls.TGW_ATT_INSPECTION,
                cls.TGW_ID,
                "vpc",
                "available",
                cls.VPC_INSPECTION,
                "111111111111",
                "inspection",
            ),
            cls.TGW_ATT_VPN: TgwAttachment(
                cls.TGW_ATT_VPN,
                cls.TGW_ID,
                "vpn",
                "available",
                "vpn-demo-001",
                "111111111111",
                "onprem-vpn",
            ),
        }

    @classmethod
    def _build_firewall_policy(cls) -> FirewallPolicy:
        home_net = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        return FirewallPolicy(
            policy_id=cls.FW_POLICY_ID,
            name="hybrid-network-inspection-policy",
            rule_order="STRICT_ORDER",
            default_action="aws:drop_established",
            rules=(
                FirewallRule(
                    "1000001",
                    "drop",
                    "ip",
                    (cls.CIDR_PROD,),
                    (cls.CIDR_NONPROD,),
                    message="Deny prod to nonprod",
                ),
                FirewallRule(
                    "1000002",
                    "drop",
                    "ip",
                    (cls.CIDR_NONPROD,),
                    (cls.CIDR_PROD,),
                    message="Deny nonprod to prod",
                ),
                FirewallRule(
                    "1000003",
                    "drop",
                    "ip",
                    (cls.CIDR_NONPROD,),
                    (cls.CIDR_ONPREM, cls.CIDR_ONPREM_VPC),
                    message="Deny nonprod to onprem",
                ),
                FirewallRule(
                    "1000004",
                    "drop",
                    "ip",
                    (cls.CIDR_ONPREM, cls.CIDR_ONPREM_VPC),
                    (cls.CIDR_NONPROD,),
                    message="Deny onprem to nonprod",
                ),
                FirewallRule(
                    "2000001",
                    "pass",
                    "ip",
                    (cls.CIDR_PROD,),
                    (cls.CIDR_SHARED,),
                    message="Allow prod to shared",
                ),
                FirewallRule(
                    "2000002",
                    "pass",
                    "ip",
                    (cls.CIDR_SHARED,),
                    (cls.CIDR_PROD,),
                    message="Allow shared to prod",
                ),
                FirewallRule(
                    "2000003",
                    "pass",
                    "ip",
                    (cls.CIDR_NONPROD,),
                    (cls.CIDR_SHARED,),
                    message="Allow nonprod to shared",
                ),
                FirewallRule(
                    "2000004",
                    "pass",
                    "ip",
                    (cls.CIDR_SHARED,),
                    (cls.CIDR_NONPROD,),
                    message="Allow shared to nonprod",
                ),
                FirewallRule(
                    "2000005",
                    "pass",
                    "ip",
                    (cls.CIDR_PROD,),
                    (cls.CIDR_ONPREM, cls.CIDR_ONPREM_VPC),
                    message="Allow prod to onprem",
                ),
                FirewallRule(
                    "2000006",
                    "pass",
                    "ip",
                    (cls.CIDR_ONPREM, cls.CIDR_ONPREM_VPC),
                    (cls.CIDR_PROD,),
                    message="Allow onprem to prod",
                ),
                FirewallRule(
                    "2000007",
                    "pass",
                    "ip",
                    (cls.CIDR_SHARED,),
                    (cls.CIDR_ONPREM, cls.CIDR_ONPREM_VPC),
                    message="Allow shared to onprem",
                ),
                FirewallRule(
                    "2000008",
                    "pass",
                    "ip",
                    (cls.CIDR_ONPREM, cls.CIDR_ONPREM_VPC),
                    (cls.CIDR_SHARED,),
                    message="Allow onprem to shared",
                ),
                FirewallRule(
                    "3000001",
                    "pass",
                    "ip",
                    home_net,
                    home_net,
                    dest_negate=True,
                    message="Allow inspected egress to internet",
                ),
            ),
        )

    @classmethod
    def _build_route_tables(cls) -> dict[str, RouteTableInfo]:
        return {
            "rtb-prod-001": RouteTableInfo(
                route_table_id="rtb-prod-001",
                vpc_id=cls.VPC_PROD,
                name="prod-private-rt",
                routes=(
                    RouteEntry(cls.CIDR_PROD, "local", "local", "active"),
                    RouteEntry("0.0.0.0/0", "transit-gateway", cls.TGW_ID, "active"),
                ),
                subnet_associations=(cls.SUBNET_PROD_APP, cls.SUBNET_PROD_DB),
            ),
            "rtb-nonprod-001": RouteTableInfo(
                route_table_id="rtb-nonprod-001",
                vpc_id=cls.VPC_NONPROD,
                name="nonprod-private-rt",
                routes=(
                    RouteEntry(cls.CIDR_NONPROD, "local", "local", "active"),
                    RouteEntry("0.0.0.0/0", "transit-gateway", cls.TGW_ID, "active"),
                ),
                subnet_associations=(cls.SUBNET_NONPROD_APP,),
            ),
            "rtb-shared-001": RouteTableInfo(
                route_table_id="rtb-shared-001",
                vpc_id=cls.VPC_SHARED,
                name="shared-private-rt",
                routes=(
                    RouteEntry(cls.CIDR_SHARED, "local", "local", "active"),
                    RouteEntry("0.0.0.0/0", "transit-gateway", cls.TGW_ID, "active"),
                ),
                subnet_associations=(cls.SUBNET_SHARED_DNS,),
            ),
            "rtb-inspection-001": RouteTableInfo(
                route_table_id="rtb-inspection-001",
                vpc_id=cls.VPC_INSPECTION,
                name="inspection-rt",
                routes=(
                    RouteEntry(cls.CIDR_INSPECTION, "local", "local", "active"),
                    RouteEntry("10.0.0.0/8", "transit-gateway", cls.TGW_ID, "active"),
                    RouteEntry("172.16.0.0/12", "transit-gateway", cls.TGW_ID, "active"),
                    RouteEntry("192.168.0.0/16", "transit-gateway", cls.TGW_ID, "active"),
                ),
                subnet_associations=(cls.SUBNET_INSPECTION,),
            ),
        }

    @classmethod
    def _allow_all_egress(cls) -> SecurityGroupRule:
        return SecurityGroupRule(
            "egress", "-1", None, None, "0.0.0.0/0", description="Allow all outbound"
        )

    @classmethod
    def _build_security_groups(cls) -> dict[str, SecurityGroupInfo]:
        rfc1918_ingress = (
            SecurityGroupRule(
                "ingress", "1", -1, -1, "10.0.0.0/8", description="ICMP from RFC1918"
            ),
            SecurityGroupRule(
                "ingress", "1", -1, -1, "172.16.0.0/12", description="ICMP from RFC1918"
            ),
            SecurityGroupRule(
                "ingress", "1", -1, -1, "192.168.0.0/16", description="ICMP from RFC1918"
            ),
            SecurityGroupRule(
                "ingress", "6", 443, 443, "10.0.0.0/8", description="HTTPS from RFC1918"
            ),
            SecurityGroupRule(
                "ingress", "6", 443, 443, "172.16.0.0/12", description="HTTPS from RFC1918"
            ),
            SecurityGroupRule(
                "ingress", "6", 443, 443, "192.168.0.0/16", description="HTTPS from RFC1918"
            ),
        )
        return {
            cls.SG_PROD_APP: SecurityGroupInfo(
                sg_id=cls.SG_PROD_APP,
                name="prod-app-sg",
                vpc_id=cls.VPC_PROD,
                rules=(*rfc1918_ingress, cls._allow_all_egress()),
            ),
            cls.SG_PROD_DB: SecurityGroupInfo(
                sg_id=cls.SG_PROD_DB,
                name="prod-db-sg",
                vpc_id=cls.VPC_PROD,
                rules=(
                    SecurityGroupRule(
                        "ingress",
                        "6",
                        5432,
                        5432,
                        source_sg_id=cls.SG_PROD_APP,
                        description="PostgreSQL from app",
                    ),
                    cls._allow_all_egress(),
                ),
            ),
            cls.SG_NONPROD_APP: SecurityGroupInfo(
                sg_id=cls.SG_NONPROD_APP,
                name="nonprod-app-sg",
                vpc_id=cls.VPC_NONPROD,
                rules=(*rfc1918_ingress, cls._allow_all_egress()),
            ),
            cls.SG_SHARED_DNS: SecurityGroupInfo(
                sg_id=cls.SG_SHARED_DNS,
                name="shared-dns-sg",
                vpc_id=cls.VPC_SHARED,
                rules=(
                    SecurityGroupRule("ingress", "17", 53, 53, "10.0.0.0/8", description="DNS UDP"),
                    SecurityGroupRule("ingress", "6", 53, 53, "10.0.0.0/8", description="DNS TCP"),
                    SecurityGroupRule("ingress", "6", 443, 443, "10.0.0.0/8", description="HTTPS"),
                    cls._allow_all_egress(),
                ),
            ),
        }

    @classmethod
    def _permissive_nacl(
        cls, nacl_id: str, vpc_id: str, name: str, subnets: tuple[str, ...]
    ) -> NaclInfo:
        return NaclInfo(
            nacl_id=nacl_id,
            vpc_id=vpc_id,
            name=name,
            rules=(
                NaclRule(100, "ingress", "-1", None, None, "10.0.0.0/8", "allow"),
                NaclRule(110, "ingress", "-1", None, None, "172.16.0.0/12", "allow"),
                NaclRule(120, "ingress", "-1", None, None, "192.168.0.0/16", "allow"),
                NaclRule(200, "ingress", "6", 1024, 65535, "0.0.0.0/0", "allow"),
                NaclRule(32767, "ingress", "-1", None, None, "0.0.0.0/0", "deny"),
                NaclRule(100, "egress", "-1", None, None, "0.0.0.0/0", "allow"),
                NaclRule(32767, "egress", "-1", None, None, "0.0.0.0/0", "deny"),
            ),
            subnet_associations=subnets,
        )

    @classmethod
    def _build_nacls(cls) -> dict[str, NaclInfo]:
        return {
            cls.NACL_PROD: cls._permissive_nacl(
                cls.NACL_PROD, cls.VPC_PROD, "prod-nacl", (cls.SUBNET_PROD_APP, cls.SUBNET_PROD_DB)
            ),
            cls.NACL_NONPROD: cls._permissive_nacl(
                cls.NACL_NONPROD, cls.VPC_NONPROD, "nonprod-nacl", (cls.SUBNET_NONPROD_APP,)
            ),
            cls.NACL_SHARED: cls._permissive_nacl(
                cls.NACL_SHARED, cls.VPC_SHARED, "shared-nacl", (cls.SUBNET_SHARED_DNS,)
            ),
        }

    @classmethod
    def _build_tgw_route_tables(cls) -> dict[str, TgwRouteTableInfo]:
        insp = cls.TGW_ATT_INSPECTION
        return {
            cls.TGW_RT_PROD: TgwRouteTableInfo(
                tgw_rt_id=cls.TGW_RT_PROD,
                tgw_id=cls.TGW_ID,
                name="prod-tgw-rt",
                routes=(
                    TgwRouteEntry(cls.CIDR_NONPROD, None, None, None, "blackhole", "static"),
                    TgwRouteEntry(
                        cls.CIDR_SHARED, insp, "vpc", cls.VPC_INSPECTION, "active", "static"
                    ),
                    TgwRouteEntry(
                        cls.CIDR_ONPREM, insp, "vpc", cls.VPC_INSPECTION, "active", "static"
                    ),
                    TgwRouteEntry(
                        cls.CIDR_ONPREM_VPC, insp, "vpc", cls.VPC_INSPECTION, "active", "static"
                    ),
                    TgwRouteEntry("0.0.0.0/0", insp, "vpc", cls.VPC_INSPECTION, "active", "static"),
                ),
                associations=(cls.TGW_ATT_PROD,),
                propagations=(),
            ),
            cls.TGW_RT_NONPROD: TgwRouteTableInfo(
                tgw_rt_id=cls.TGW_RT_NONPROD,
                tgw_id=cls.TGW_ID,
                name="nonprod-tgw-rt",
                routes=(
                    TgwRouteEntry(cls.CIDR_PROD, None, None, None, "blackhole", "static"),
                    TgwRouteEntry(cls.CIDR_ONPREM, None, None, None, "blackhole", "static"),
                    TgwRouteEntry(cls.CIDR_ONPREM_VPC, None, None, None, "blackhole", "static"),
                    TgwRouteEntry(
                        cls.CIDR_SHARED, insp, "vpc", cls.VPC_INSPECTION, "active", "static"
                    ),
                    TgwRouteEntry("0.0.0.0/0", insp, "vpc", cls.VPC_INSPECTION, "active", "static"),
                ),
                associations=(cls.TGW_ATT_NONPROD,),
                propagations=(),
            ),
            cls.TGW_RT_SHARED: TgwRouteTableInfo(
                tgw_rt_id=cls.TGW_RT_SHARED,
                tgw_id=cls.TGW_ID,
                name="shared-tgw-rt",
                routes=(
                    TgwRouteEntry(
                        cls.CIDR_ONPREM, insp, "vpc", cls.VPC_INSPECTION, "active", "static"
                    ),
                    TgwRouteEntry(
                        cls.CIDR_ONPREM_VPC, insp, "vpc", cls.VPC_INSPECTION, "active", "static"
                    ),
                    TgwRouteEntry("0.0.0.0/0", insp, "vpc", cls.VPC_INSPECTION, "active", "static"),
                ),
                associations=(cls.TGW_ATT_SHARED,),
                propagations=(),
            ),
            cls.TGW_RT_INSPECTION: TgwRouteTableInfo(
                tgw_rt_id=cls.TGW_RT_INSPECTION,
                tgw_id=cls.TGW_ID,
                name="inspection-tgw-rt",
                routes=(
                    TgwRouteEntry(
                        cls.CIDR_PROD, cls.TGW_ATT_PROD, "vpc", cls.VPC_PROD, "active", "static"
                    ),
                    TgwRouteEntry(
                        cls.CIDR_NONPROD,
                        cls.TGW_ATT_NONPROD,
                        "vpc",
                        cls.VPC_NONPROD,
                        "active",
                        "static",
                    ),
                    TgwRouteEntry(
                        cls.CIDR_SHARED,
                        cls.TGW_ATT_SHARED,
                        "vpc",
                        cls.VPC_SHARED,
                        "active",
                        "static",
                    ),
                    TgwRouteEntry(
                        cls.CIDR_ONPREM,
                        cls.TGW_ATT_VPN,
                        "vpn",
                        "vpn-demo-001",
                        "active",
                        "propagated",
                    ),
                    TgwRouteEntry(
                        cls.CIDR_ONPREM_VPC,
                        cls.TGW_ATT_VPN,
                        "vpn",
                        "vpn-demo-001",
                        "active",
                        "static",
                    ),
                ),
                associations=(cls.TGW_ATT_INSPECTION,),
                propagations=(
                    cls.TGW_ATT_PROD,
                    cls.TGW_ATT_NONPROD,
                    cls.TGW_ATT_SHARED,
                    cls.TGW_ATT_VPN,
                ),
            ),
            cls.TGW_RT_ONPREM: TgwRouteTableInfo(
                tgw_rt_id=cls.TGW_RT_ONPREM,
                tgw_id=cls.TGW_ID,
                name="onprem-tgw-rt",
                routes=(
                    TgwRouteEntry(cls.CIDR_NONPROD, None, None, None, "blackhole", "static"),
                    TgwRouteEntry("0.0.0.0/0", insp, "vpc", cls.VPC_INSPECTION, "active", "static"),
                ),
                associations=(cls.TGW_ATT_VPN,),
                propagations=(),
            ),
        }

    @classmethod
    def _build_subnet_rt_mapping(cls) -> dict[str, str]:
        return {
            cls.SUBNET_PROD_APP: "rtb-prod-001",
            cls.SUBNET_PROD_DB: "rtb-prod-001",
            cls.SUBNET_NONPROD_APP: "rtb-nonprod-001",
            cls.SUBNET_SHARED_DNS: "rtb-shared-001",
            cls.SUBNET_INSPECTION: "rtb-inspection-001",
        }

    @classmethod
    def _build_subnet_nacl_mapping(cls) -> dict[str, str]:
        return {
            cls.SUBNET_PROD_APP: cls.NACL_PROD,
            cls.SUBNET_PROD_DB: cls.NACL_PROD,
            cls.SUBNET_NONPROD_APP: cls.NACL_NONPROD,
            cls.SUBNET_SHARED_DNS: cls.NACL_SHARED,
        }

    @classmethod
    def _build_eni_sg_mapping(cls) -> dict[str, list[str]]:
        return {
            cls.ENI_PROD_APP: [cls.SG_PROD_APP],
            cls.ENI_PROD_DB: [cls.SG_PROD_DB],
            cls.ENI_NONPROD_APP: [cls.SG_NONPROD_APP],
            cls.ENI_SHARED_DNS: [cls.SG_SHARED_DNS],
        }

    @classmethod
    def _build_subnet_vpc_mapping(cls) -> dict[str, str]:
        return {
            cls.SUBNET_PROD_APP: cls.VPC_PROD,
            cls.SUBNET_PROD_DB: cls.VPC_PROD,
            cls.SUBNET_NONPROD_APP: cls.VPC_NONPROD,
            cls.SUBNET_SHARED_DNS: cls.VPC_SHARED,
            cls.SUBNET_INSPECTION: cls.VPC_INSPECTION,
        }

    @classmethod
    def _build_tgw_attachment_rt_mapping(cls) -> dict[str, str]:
        return {
            cls.TGW_ATT_PROD: cls.TGW_RT_PROD,
            cls.TGW_ATT_NONPROD: cls.TGW_RT_NONPROD,
            cls.TGW_ATT_SHARED: cls.TGW_RT_SHARED,
            cls.TGW_ATT_INSPECTION: cls.TGW_RT_INSPECTION,
            cls.TGW_ATT_VPN: cls.TGW_RT_ONPREM,
        }

    @classmethod
    def _build_vpc_tgw_attachment_mapping(cls) -> dict[str, str]:
        return {
            cls.VPC_PROD: cls.TGW_ATT_PROD,
            cls.VPC_NONPROD: cls.TGW_ATT_NONPROD,
            cls.VPC_SHARED: cls.TGW_ATT_SHARED,
            cls.VPC_INSPECTION: cls.TGW_ATT_INSPECTION,
        }


def load_demo_topology() -> NetworkTopology:
    """Load the default landing-zone demo topology."""
    return DemoTopology.build_healthy_topology()


def topology_to_json(topology: NetworkTopology) -> dict[str, Any]:
    """Convert topology to a JSON-serializable dict."""

    def _route_to_dict(r: RouteEntry) -> dict[str, Any]:
        return {
            "destination_cidr": r.destination_cidr,
            "target_type": r.target_type,
            "target_id": r.target_id,
            "state": r.state,
            "propagated": r.propagated,
        }

    def _tgw_route_to_dict(r: TgwRouteEntry) -> dict[str, Any]:
        return {
            "destination_cidr": r.destination_cidr,
            "attachment_id": r.attachment_id,
            "resource_type": r.resource_type,
            "resource_id": r.resource_id,
            "state": r.state,
            "route_type": r.route_type,
        }

    def _sg_rule_to_dict(r: SecurityGroupRule) -> dict[str, Any]:
        return {
            "direction": r.direction,
            "protocol": r.protocol,
            "from_port": r.from_port,
            "to_port": r.to_port,
            "cidr": r.cidr,
            "source_sg_id": r.source_sg_id,
            "description": r.description,
        }

    def _nacl_rule_to_dict(r: NaclRule) -> dict[str, Any]:
        return {
            "rule_number": r.rule_number,
            "direction": r.direction,
            "protocol": r.protocol,
            "from_port": r.from_port,
            "to_port": r.to_port,
            "cidr": r.cidr,
            "action": r.action,
        }

    return {
        "route_tables": {
            rt_id: {
                "route_table_id": rt.route_table_id,
                "vpc_id": rt.vpc_id,
                "name": rt.name,
                "routes": [_route_to_dict(r) for r in rt.routes],
                "subnet_associations": list(rt.subnet_associations),
            }
            for rt_id, rt in topology.route_tables.items()
        },
        "security_groups": {
            sg_id: {
                "sg_id": sg.sg_id,
                "name": sg.name,
                "vpc_id": sg.vpc_id,
                "rules": [_sg_rule_to_dict(r) for r in sg.rules],
            }
            for sg_id, sg in topology.security_groups.items()
        },
        "nacls": {
            nacl_id: {
                "nacl_id": nacl.nacl_id,
                "vpc_id": nacl.vpc_id,
                "name": nacl.name,
                "rules": [_nacl_rule_to_dict(r) for r in nacl.rules],
                "subnet_associations": list(nacl.subnet_associations),
            }
            for nacl_id, nacl in topology.nacls.items()
        },
        "tgw_route_tables": {
            tgw_rt_id: {
                "tgw_rt_id": tgw_rt.tgw_rt_id,
                "tgw_id": tgw_rt.tgw_id,
                "name": tgw_rt.name,
                "routes": [_tgw_route_to_dict(r) for r in tgw_rt.routes],
                "associations": list(tgw_rt.associations),
                "propagations": list(tgw_rt.propagations),
            }
            for tgw_rt_id, tgw_rt in topology.tgw_route_tables.items()
        },
        "subnet_to_route_table": topology.subnet_to_route_table,
        "subnet_to_nacl": topology.subnet_to_nacl,
        "eni_to_security_groups": topology.eni_to_security_groups,
        "subnet_to_vpc": topology.subnet_to_vpc,
        "tgw_attachment_to_route_table": topology.tgw_attachment_to_route_table,
        "vpc_to_tgw_attachment": topology.vpc_to_tgw_attachment,
    }


def save_topology_to_file(topology: NetworkTopology, path: Path) -> None:
    """Save topology to a JSON file."""
    path.write_text(json.dumps(topology_to_json(topology), indent=2))
