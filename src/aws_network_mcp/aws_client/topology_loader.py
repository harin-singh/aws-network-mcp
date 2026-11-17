"""Build NetworkTopology from live read-only AWS describe APIs."""

from __future__ import annotations

import contextlib
import logging
from typing import Any, Protocol

from aws_network_mcp.analysis.path_analyzer import NetworkTopology
from aws_network_mcp.aws_client.ec2_client import EC2Client
from aws_network_mcp.models import (
    FirewallPolicy,
    NetworkEndpoint,
    TgwRouteTableInfo,
)

logger = logging.getLogger(__name__)


class FirewallPolicyImporter(Protocol):
    """Minimal interface used by the live loader."""

    def load_policies(self) -> tuple[dict[str, FirewallPolicy], frozenset[str], tuple[str, ...]]:
        """Return policies, inspection VPC IDs, and import warnings."""
        ...


class LiveTopologyLoader:
    """Assemble hop-by-hop analysis input from EC2 + Network Firewall."""

    def __init__(
        self,
        ec2_client: EC2Client,
        nfw_client: FirewallPolicyImporter | None = None,
    ) -> None:
        self.ec2 = ec2_client
        self.nfw = nfw_client

    def load(self) -> NetworkTopology:
        """Describe regional network state and return a NetworkTopology."""
        warnings: list[str] = []

        vpcs = self.ec2.list_vpcs()
        subnets = self.ec2.list_subnets()
        route_tables = {rt.route_table_id: rt for rt in self.ec2.list_route_tables()}
        security_groups = {sg.sg_id: sg for sg in self.ec2.list_security_groups()}
        nacls = {nacl.nacl_id: nacl for nacl in self.ec2.list_nacls()}
        enis = self.ec2.list_network_interfaces()
        attachments = {att.attachment_id: att for att in self.ec2.list_tgw_attachments()}
        prefix_list_cidrs = self.ec2.list_prefix_list_cidrs()

        subnet_to_vpc = {
            str(subnet.get("SubnetId")): str(subnet.get("VpcId"))
            for subnet in subnets
            if subnet.get("SubnetId") and subnet.get("VpcId")
        }
        vpc_cidrs = {
            str(vpc.get("VpcId")): tuple(
                str(assoc.get("CidrBlock"))
                for assoc in vpc.get("CidrBlockAssociationSet", [])
                if assoc.get("CidrBlock")
                and assoc.get("CidrBlockState", {}).get("State") != "disassociated"
            )
            or ((str(vpc.get("CidrBlock")),) if vpc.get("CidrBlock") else ())
            for vpc in vpcs
            if vpc.get("VpcId")
        }

        subnet_to_route_table: dict[str, str] = {}
        for rt in route_tables.values():
            for subnet_id in rt.subnet_associations:
                subnet_to_route_table[subnet_id] = rt.route_table_id
        _apply_main_route_tables(route_tables, subnets, subnet_to_route_table)

        subnet_to_nacl: dict[str, str] = {}
        for nacl in nacls.values():
            for subnet_id in nacl.subnet_associations:
                subnet_to_nacl[subnet_id] = nacl.nacl_id

        eni_to_security_groups: dict[str, list[str]] = {}
        known_endpoints: dict[str, NetworkEndpoint] = {}
        for eni in enis:
            eni_id = str(eni.get("NetworkInterfaceId") or "")
            ip = eni.get("PrivateIpAddress")
            if eni_id:
                eni_to_security_groups[eni_id] = [
                    str(group.get("GroupId"))
                    for group in eni.get("Groups", [])
                    if group.get("GroupId")
                ]
            if ip:
                known_endpoints[str(ip)] = NetworkEndpoint(
                    ip=str(ip),
                    vpc_id=eni.get("VpcId"),
                    subnet_id=eni.get("SubnetId"),
                    eni_id=eni_id or None,
                    instance_id=eni.get("Attachment", {}).get("InstanceId"),
                )

        tgw_route_tables, attachment_to_rt, extra_warnings = self._load_tgw_route_tables(
            attachments
        )
        warnings.extend(extra_warnings)

        vpc_to_tgw_attachment = {
            att.resource_id: att.attachment_id
            for att in attachments.values()
            if att.attachment_type == "vpc" and att.resource_id
        }
        vpn_attachment_id = next(
            (
                att.attachment_id
                for att in attachments.values()
                if att.attachment_type in {"vpn", "direct-connect-gateway"}
            ),
            None,
        )

        firewall_policies: dict[str, Any] = {}
        inspection_vpcs: frozenset[str] = frozenset()
        if self.nfw is not None:
            try:
                firewall_policies, inspection_vpcs, nfw_warnings = self.nfw.load_policies()
                warnings.extend(nfw_warnings)
            except Exception as exc:
                warnings.append(f"Network Firewall import failed: {exc}")

        tagged_inspection = _inspection_vpcs_from_tags(vpcs, attachments)
        inspection_vpcs = frozenset(set(inspection_vpcs) | tagged_inspection)
        inspection_attachment_ids = frozenset(
            att.attachment_id
            for att in attachments.values()
            if att.attachment_type == "vpc" and att.resource_id in inspection_vpcs
        )
        inspection_vpc_id = next(iter(inspection_vpcs), None)

        on_prem_cidrs = _on_prem_cidrs(self.ec2, tgw_route_tables, attachments)
        if not on_prem_cidrs:
            warnings.append(
                "No on-prem CIDRs found (no TGW routes toward VPN/DX attachments "
                "and no VPN static routes)"
            )

        topology = NetworkTopology(
            route_tables=route_tables,
            security_groups=security_groups,
            nacls=nacls,
            tgw_route_tables=tgw_route_tables,
            subnet_to_route_table=subnet_to_route_table,
            subnet_to_nacl=subnet_to_nacl,
            eni_to_security_groups=eni_to_security_groups,
            subnet_to_vpc=subnet_to_vpc,
            tgw_attachment_to_route_table=attachment_to_rt,
            vpc_to_tgw_attachment=vpc_to_tgw_attachment,
            prefix_list_cidrs=prefix_list_cidrs,
            attachments=attachments,
            inspection_attachment_ids=inspection_attachment_ids,
            firewall_policies=firewall_policies,
            inspection_vpc_id=inspection_vpc_id,
            vpn_attachment_id=vpn_attachment_id,
            known_endpoints=known_endpoints,
            on_prem_cidrs=on_prem_cidrs,
            vpc_cidrs=vpc_cidrs,
            load_warnings=tuple(warnings),
        )
        logger.info(
            "Loaded live topology: %s VPCs, %s TGW attachments, %s firewall policies, %s warnings",
            len(vpcs),
            len(attachments),
            len(firewall_policies),
            len(warnings),
        )
        for warning in warnings:
            logger.warning("Topology import: %s", warning)
        return topology

    def _load_tgw_route_tables(
        self, attachments: dict[str, Any]
    ) -> tuple[dict[str, TgwRouteTableInfo], dict[str, str], list[str]]:
        tables: dict[str, TgwRouteTableInfo] = {}
        attachment_to_rt: dict[str, str] = {}
        warnings: list[str] = []

        for raw in self.ec2.list_tgw_route_tables():
            tgw_rt_id = raw.get("TransitGatewayRouteTableId")
            if not tgw_rt_id:
                continue
            try:
                parsed = self.ec2.get_tgw_route_table(str(tgw_rt_id))
            except Exception as exc:
                warnings.append(f"Failed to load TGW route table {tgw_rt_id}: {exc}")
                continue
            if parsed is None:
                continue
            tables[parsed.tgw_rt_id] = parsed
            for attachment_id in parsed.associations:
                attachment_to_rt[attachment_id] = parsed.tgw_rt_id

        for att in attachments.values():
            associated_rt = getattr(att, "associated_route_table_id", None)
            if associated_rt and att.attachment_id not in attachment_to_rt:
                attachment_to_rt[att.attachment_id] = str(associated_rt)

        return tables, attachment_to_rt, warnings


def _apply_main_route_tables(
    route_tables: dict[str, Any],
    subnets: list[dict[str, Any]],
    subnet_to_route_table: dict[str, str],
) -> None:
    main_by_vpc: dict[str, str] = {}
    # Re-read associations from already-parsed tables: main tables often have no subnet ids.
    # The raw describe is not retained, so leave implicit main mapping to caller via
    # get_subnet_route_table when needed. Explicit subnet associations are enough for analysis
    # when every subnet is associated, which is the common landing-zone case.
    for rt in route_tables.values():
        if rt.vpc_id and rt.route_table_id and not rt.subnet_associations:
            main_by_vpc.setdefault(rt.vpc_id, rt.route_table_id)
    for subnet in subnets:
        subnet_id = subnet.get("SubnetId")
        vpc_id = subnet.get("VpcId")
        if subnet_id and vpc_id and subnet_id not in subnet_to_route_table:
            main_rt = main_by_vpc.get(str(vpc_id))
            if main_rt:
                subnet_to_route_table[str(subnet_id)] = main_rt


def _inspection_vpcs_from_tags(vpcs: list[dict[str, Any]], attachments: dict[str, Any]) -> set[str]:
    found: set[str] = set()
    for vpc in vpcs:
        vpc_id = vpc.get("VpcId")
        if vpc_id and _looks_like_inspection(_get_name(vpc.get("Tags")), vpc.get("Tags")):
            found.add(str(vpc_id))
    for att in attachments.values():
        if att.attachment_type == "vpc" and _looks_like_inspection(att.name, None):
            found.add(att.resource_id)
    return found


def _looks_like_inspection(name: str | None, tags: Any) -> bool:
    haystacks = [name or ""]
    if tags:
        for tag in tags:
            if tag.get("Key") in {"Name", "Role", "aws-network-mcp:role"}:
                haystacks.append(str(tag.get("Value") or ""))
    return any("inspection" in value.lower() for value in haystacks)


def _get_name(tags: Any) -> str | None:
    if not tags:
        return None
    for tag in tags:
        if tag.get("Key") == "Name":
            value = tag.get("Value")
            return str(value) if value is not None else None
    return None


def _on_prem_cidrs(
    ec2: EC2Client,
    tgw_route_tables: dict[str, TgwRouteTableInfo],
    attachments: dict[str, Any],
) -> tuple[str, ...]:
    vpn_like = {
        att.attachment_id
        for att in attachments.values()
        if att.attachment_type in {"vpn", "direct-connect-gateway"}
    }
    cidrs: set[str] = set()
    for table in tgw_route_tables.values():
        for route in table.routes:
            if route.destination_cidr and (
                route.attachment_id in vpn_like
                or route.resource_type in {"vpn", "direct-connect-gateway"}
            ):
                cidrs.add(route.destination_cidr)
    with contextlib.suppress(Exception):
        for vpn in ec2.get_vpn_connections():
            cidrs.update(vpn.static_routes)
    return tuple(sorted(cidrs))
