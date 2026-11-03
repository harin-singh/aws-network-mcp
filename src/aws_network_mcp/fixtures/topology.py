"""Demo topology fixtures for offline mode.

Represents a realistic hub-and-spoke architecture:
- 3 spoke VPCs (prod, dev, shared-services)
- 1 inspection VPC with Network Firewall
- Transit Gateway with segmented route tables
- Site-to-Site VPN to simulated on-prem (10.200.0.0/16)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aws_network_mcp.analysis.path_analyzer import NetworkTopology
from aws_network_mcp.models import (
    NaclInfo,
    NaclRule,
    RouteEntry,
    RouteTableInfo,
    SecurityGroupInfo,
    SecurityGroupRule,
    TgwRouteEntry,
    TgwRouteTableInfo,
)


class DemoTopology:
    """Demo topology builder for offline testing."""

    VPC_PROD = "vpc-prod-001"
    VPC_DEV = "vpc-dev-002"
    VPC_SHARED = "vpc-shared-003"
    VPC_INSPECTION = "vpc-inspection-004"
    ON_PREM_CIDR = "10.200.0.0/16"

    SUBNET_PROD_APP = "subnet-prod-app-001"
    SUBNET_PROD_DB = "subnet-prod-db-002"
    SUBNET_DEV_APP = "subnet-dev-app-003"
    SUBNET_SHARED_DNS = "subnet-shared-dns-004"
    SUBNET_INSPECTION = "subnet-inspection-005"

    TGW_ID = "tgw-demo-001"
    TGW_ATT_PROD = "tgw-attach-prod-001"
    TGW_ATT_DEV = "tgw-attach-dev-002"
    TGW_ATT_SHARED = "tgw-attach-shared-003"
    TGW_ATT_INSPECTION = "tgw-attach-inspection-004"
    TGW_ATT_VPN = "tgw-attach-vpn-005"

    TGW_RT_PROD = "tgw-rtb-prod-001"
    TGW_RT_DEV = "tgw-rtb-dev-002"
    TGW_RT_SHARED = "tgw-rtb-shared-003"
    TGW_RT_INSPECTION = "tgw-rtb-inspection-004"

    ENI_PROD_APP = "eni-prod-app-001"
    ENI_PROD_DB = "eni-prod-db-002"
    ENI_DEV_APP = "eni-dev-app-003"
    ENI_SHARED_DNS = "eni-shared-dns-004"

    SG_PROD_APP = "sg-prod-app-001"
    SG_PROD_DB = "sg-prod-db-002"
    SG_DEV_APP = "sg-dev-app-001"
    SG_SHARED_DNS = "sg-shared-dns-001"

    NACL_PROD = "acl-prod-001"
    NACL_DEV = "acl-dev-001"
    NACL_SHARED = "acl-shared-001"

    @classmethod
    def build_healthy_topology(cls) -> NetworkTopology:
        """Build a fully healthy topology with no connectivity issues."""
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
        )

    @classmethod
    def _build_route_tables(cls) -> dict[str, RouteTableInfo]:
        return {
            "rtb-prod-001": RouteTableInfo(
                route_table_id="rtb-prod-001",
                vpc_id=cls.VPC_PROD,
                name="prod-private-rt",
                routes=(
                    RouteEntry("10.1.0.0/16", "local", "local", "active"),
                    RouteEntry("10.0.0.0/8", "transit-gateway", cls.TGW_ID, "active"),
                    RouteEntry("0.0.0.0/0", "transit-gateway", cls.TGW_ID, "active"),
                ),
                subnet_associations=(cls.SUBNET_PROD_APP, cls.SUBNET_PROD_DB),
            ),
            "rtb-dev-001": RouteTableInfo(
                route_table_id="rtb-dev-001",
                vpc_id=cls.VPC_DEV,
                name="dev-private-rt",
                routes=(
                    RouteEntry("10.2.0.0/16", "local", "local", "active"),
                    RouteEntry("10.0.0.0/8", "transit-gateway", cls.TGW_ID, "active"),
                    RouteEntry("0.0.0.0/0", "transit-gateway", cls.TGW_ID, "active"),
                ),
                subnet_associations=(cls.SUBNET_DEV_APP,),
            ),
            "rtb-shared-001": RouteTableInfo(
                route_table_id="rtb-shared-001",
                vpc_id=cls.VPC_SHARED,
                name="shared-private-rt",
                routes=(
                    RouteEntry("10.3.0.0/16", "local", "local", "active"),
                    RouteEntry("10.0.0.0/8", "transit-gateway", cls.TGW_ID, "active"),
                ),
                subnet_associations=(cls.SUBNET_SHARED_DNS,),
            ),
            "rtb-inspection-001": RouteTableInfo(
                route_table_id="rtb-inspection-001",
                vpc_id=cls.VPC_INSPECTION,
                name="inspection-rt",
                routes=(
                    RouteEntry("10.4.0.0/16", "local", "local", "active"),
                    RouteEntry("10.0.0.0/8", "transit-gateway", cls.TGW_ID, "active"),
                ),
                subnet_associations=(cls.SUBNET_INSPECTION,),
            ),
        }

    @classmethod
    def _build_security_groups(cls) -> dict[str, SecurityGroupInfo]:
        return {
            cls.SG_PROD_APP: SecurityGroupInfo(
                sg_id=cls.SG_PROD_APP,
                name="prod-app-sg",
                vpc_id=cls.VPC_PROD,
                rules=(
                    SecurityGroupRule(
                        "ingress", "6", 443, 443, "10.0.0.0/8", description="HTTPS from internal"
                    ),
                    SecurityGroupRule(
                        "ingress",
                        "6",
                        22,
                        22,
                        "10.3.0.0/16",
                        description="SSH from shared-services",
                    ),
                    SecurityGroupRule(
                        "egress", "-1", None, None, "0.0.0.0/0", description="Allow all outbound"
                    ),
                ),
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
                    SecurityGroupRule(
                        "egress", "-1", None, None, "0.0.0.0/0", description="Allow all outbound"
                    ),
                ),
            ),
            cls.SG_DEV_APP: SecurityGroupInfo(
                sg_id=cls.SG_DEV_APP,
                name="dev-app-sg",
                vpc_id=cls.VPC_DEV,
                rules=(
                    SecurityGroupRule(
                        "ingress", "6", 443, 443, "10.0.0.0/8", description="HTTPS from internal"
                    ),
                    SecurityGroupRule(
                        "ingress", "6", 22, 22, "10.0.0.0/8", description="SSH from internal"
                    ),
                    SecurityGroupRule(
                        "egress", "-1", None, None, "0.0.0.0/0", description="Allow all outbound"
                    ),
                ),
            ),
            cls.SG_SHARED_DNS: SecurityGroupInfo(
                sg_id=cls.SG_SHARED_DNS,
                name="shared-dns-sg",
                vpc_id=cls.VPC_SHARED,
                rules=(
                    SecurityGroupRule(
                        "ingress", "17", 53, 53, "10.0.0.0/8", description="DNS UDP from internal"
                    ),
                    SecurityGroupRule(
                        "ingress", "6", 53, 53, "10.0.0.0/8", description="DNS TCP from internal"
                    ),
                    SecurityGroupRule(
                        "egress", "-1", None, None, "0.0.0.0/0", description="Allow all outbound"
                    ),
                ),
            ),
        }

    @classmethod
    def _build_nacls(cls) -> dict[str, NaclInfo]:
        return {
            cls.NACL_PROD: NaclInfo(
                nacl_id=cls.NACL_PROD,
                vpc_id=cls.VPC_PROD,
                name="prod-nacl",
                rules=(
                    NaclRule(100, "ingress", "-1", None, None, "10.0.0.0/8", "allow"),
                    NaclRule(200, "ingress", "6", 1024, 65535, "0.0.0.0/0", "allow"),
                    NaclRule(32767, "ingress", "-1", None, None, "0.0.0.0/0", "deny"),
                    NaclRule(100, "egress", "-1", None, None, "0.0.0.0/0", "allow"),
                    NaclRule(32767, "egress", "-1", None, None, "0.0.0.0/0", "deny"),
                ),
                subnet_associations=(cls.SUBNET_PROD_APP, cls.SUBNET_PROD_DB),
            ),
            cls.NACL_DEV: NaclInfo(
                nacl_id=cls.NACL_DEV,
                vpc_id=cls.VPC_DEV,
                name="dev-nacl",
                rules=(
                    NaclRule(100, "ingress", "-1", None, None, "0.0.0.0/0", "allow"),
                    NaclRule(32767, "ingress", "-1", None, None, "0.0.0.0/0", "deny"),
                    NaclRule(100, "egress", "-1", None, None, "0.0.0.0/0", "allow"),
                    NaclRule(32767, "egress", "-1", None, None, "0.0.0.0/0", "deny"),
                ),
                subnet_associations=(cls.SUBNET_DEV_APP,),
            ),
            cls.NACL_SHARED: NaclInfo(
                nacl_id=cls.NACL_SHARED,
                vpc_id=cls.VPC_SHARED,
                name="shared-nacl",
                rules=(
                    NaclRule(100, "ingress", "-1", None, None, "10.0.0.0/8", "allow"),
                    NaclRule(200, "ingress", "6", 1024, 65535, "0.0.0.0/0", "allow"),
                    NaclRule(32767, "ingress", "-1", None, None, "0.0.0.0/0", "deny"),
                    NaclRule(100, "egress", "-1", None, None, "0.0.0.0/0", "allow"),
                    NaclRule(32767, "egress", "-1", None, None, "0.0.0.0/0", "deny"),
                ),
                subnet_associations=(cls.SUBNET_SHARED_DNS,),
            ),
        }

    @classmethod
    def _build_tgw_route_tables(cls) -> dict[str, TgwRouteTableInfo]:
        return {
            cls.TGW_RT_PROD: TgwRouteTableInfo(
                tgw_rt_id=cls.TGW_RT_PROD,
                tgw_id=cls.TGW_ID,
                name="prod-tgw-rt",
                routes=(
                    TgwRouteEntry(
                        "10.1.0.0/16", cls.TGW_ATT_PROD, "vpc", cls.VPC_PROD, "active", "propagated"
                    ),
                    TgwRouteEntry(
                        "10.3.0.0/16",
                        cls.TGW_ATT_SHARED,
                        "vpc",
                        cls.VPC_SHARED,
                        "active",
                        "propagated",
                    ),
                    TgwRouteEntry(
                        "10.200.0.0/16",
                        cls.TGW_ATT_VPN,
                        "vpn",
                        "vpn-demo-001",
                        "active",
                        "propagated",
                    ),
                    TgwRouteEntry(
                        "0.0.0.0/0",
                        cls.TGW_ATT_INSPECTION,
                        "vpc",
                        cls.VPC_INSPECTION,
                        "active",
                        "static",
                    ),
                ),
                associations=(cls.TGW_ATT_PROD,),
                propagations=(cls.TGW_ATT_PROD, cls.TGW_ATT_SHARED, cls.TGW_ATT_VPN),
            ),
            cls.TGW_RT_DEV: TgwRouteTableInfo(
                tgw_rt_id=cls.TGW_RT_DEV,
                tgw_id=cls.TGW_ID,
                name="dev-tgw-rt",
                routes=(
                    TgwRouteEntry(
                        "10.2.0.0/16", cls.TGW_ATT_DEV, "vpc", cls.VPC_DEV, "active", "propagated"
                    ),
                    TgwRouteEntry(
                        "10.3.0.0/16",
                        cls.TGW_ATT_SHARED,
                        "vpc",
                        cls.VPC_SHARED,
                        "active",
                        "propagated",
                    ),
                    TgwRouteEntry(
                        "10.200.0.0/16",
                        cls.TGW_ATT_VPN,
                        "vpn",
                        "vpn-demo-001",
                        "active",
                        "propagated",
                    ),
                    TgwRouteEntry(
                        "0.0.0.0/0",
                        cls.TGW_ATT_INSPECTION,
                        "vpc",
                        cls.VPC_INSPECTION,
                        "active",
                        "static",
                    ),
                ),
                associations=(cls.TGW_ATT_DEV,),
                propagations=(cls.TGW_ATT_DEV, cls.TGW_ATT_SHARED, cls.TGW_ATT_VPN),
            ),
            cls.TGW_RT_SHARED: TgwRouteTableInfo(
                tgw_rt_id=cls.TGW_RT_SHARED,
                tgw_id=cls.TGW_ID,
                name="shared-tgw-rt",
                routes=(
                    TgwRouteEntry(
                        "10.1.0.0/16", cls.TGW_ATT_PROD, "vpc", cls.VPC_PROD, "active", "propagated"
                    ),
                    TgwRouteEntry(
                        "10.2.0.0/16", cls.TGW_ATT_DEV, "vpc", cls.VPC_DEV, "active", "propagated"
                    ),
                    TgwRouteEntry(
                        "10.3.0.0/16",
                        cls.TGW_ATT_SHARED,
                        "vpc",
                        cls.VPC_SHARED,
                        "active",
                        "propagated",
                    ),
                    TgwRouteEntry(
                        "10.200.0.0/16",
                        cls.TGW_ATT_VPN,
                        "vpn",
                        "vpn-demo-001",
                        "active",
                        "propagated",
                    ),
                ),
                associations=(cls.TGW_ATT_SHARED,),
                propagations=(
                    cls.TGW_ATT_PROD,
                    cls.TGW_ATT_DEV,
                    cls.TGW_ATT_SHARED,
                    cls.TGW_ATT_VPN,
                ),
            ),
            cls.TGW_RT_INSPECTION: TgwRouteTableInfo(
                tgw_rt_id=cls.TGW_RT_INSPECTION,
                tgw_id=cls.TGW_ID,
                name="inspection-tgw-rt",
                routes=(
                    TgwRouteEntry(
                        "10.1.0.0/16", cls.TGW_ATT_PROD, "vpc", cls.VPC_PROD, "active", "static"
                    ),
                    TgwRouteEntry(
                        "10.2.0.0/16", cls.TGW_ATT_DEV, "vpc", cls.VPC_DEV, "active", "static"
                    ),
                    TgwRouteEntry(
                        "10.3.0.0/16", cls.TGW_ATT_SHARED, "vpc", cls.VPC_SHARED, "active", "static"
                    ),
                    TgwRouteEntry(
                        "10.200.0.0/16", cls.TGW_ATT_VPN, "vpn", "vpn-demo-001", "active", "static"
                    ),
                ),
                associations=(cls.TGW_ATT_INSPECTION,),
                propagations=(),
            ),
        }

    @classmethod
    def _build_subnet_rt_mapping(cls) -> dict[str, str]:
        return {
            cls.SUBNET_PROD_APP: "rtb-prod-001",
            cls.SUBNET_PROD_DB: "rtb-prod-001",
            cls.SUBNET_DEV_APP: "rtb-dev-001",
            cls.SUBNET_SHARED_DNS: "rtb-shared-001",
            cls.SUBNET_INSPECTION: "rtb-inspection-001",
        }

    @classmethod
    def _build_subnet_nacl_mapping(cls) -> dict[str, str]:
        return {
            cls.SUBNET_PROD_APP: cls.NACL_PROD,
            cls.SUBNET_PROD_DB: cls.NACL_PROD,
            cls.SUBNET_DEV_APP: cls.NACL_DEV,
            cls.SUBNET_SHARED_DNS: cls.NACL_SHARED,
        }

    @classmethod
    def _build_eni_sg_mapping(cls) -> dict[str, list[str]]:
        return {
            cls.ENI_PROD_APP: [cls.SG_PROD_APP],
            cls.ENI_PROD_DB: [cls.SG_PROD_DB],
            cls.ENI_DEV_APP: [cls.SG_DEV_APP],
            cls.ENI_SHARED_DNS: [cls.SG_SHARED_DNS],
        }

    @classmethod
    def _build_subnet_vpc_mapping(cls) -> dict[str, str]:
        return {
            cls.SUBNET_PROD_APP: cls.VPC_PROD,
            cls.SUBNET_PROD_DB: cls.VPC_PROD,
            cls.SUBNET_DEV_APP: cls.VPC_DEV,
            cls.SUBNET_SHARED_DNS: cls.VPC_SHARED,
            cls.SUBNET_INSPECTION: cls.VPC_INSPECTION,
        }

    @classmethod
    def _build_tgw_attachment_rt_mapping(cls) -> dict[str, str]:
        return {
            cls.TGW_ATT_PROD: cls.TGW_RT_PROD,
            cls.TGW_ATT_DEV: cls.TGW_RT_DEV,
            cls.TGW_ATT_SHARED: cls.TGW_RT_SHARED,
            cls.TGW_ATT_INSPECTION: cls.TGW_RT_INSPECTION,
        }

    @classmethod
    def _build_vpc_tgw_attachment_mapping(cls) -> dict[str, str]:
        return {
            cls.VPC_PROD: cls.TGW_ATT_PROD,
            cls.VPC_DEV: cls.TGW_ATT_DEV,
            cls.VPC_SHARED: cls.TGW_ATT_SHARED,
            cls.VPC_INSPECTION: cls.TGW_ATT_INSPECTION,
        }


def load_demo_topology() -> NetworkTopology:
    """Load the default demo topology."""
    return DemoTopology.build_healthy_topology()


def topology_to_json(topology: NetworkTopology) -> dict[str, Any]:
    """Convert topology to JSON-serializable dict."""

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
    data = topology_to_json(topology)
    path.write_text(json.dumps(data, indent=2))
