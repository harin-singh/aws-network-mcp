"""Transit Gateway and VPN/Direct Connect tools."""

from __future__ import annotations

from typing import Any

from aws_network_mcp.analysis.path_analyzer import NetworkTopology
from aws_network_mcp.analysis.route_matcher import RouteMatcher
from aws_network_mcp.aws_client.ec2_client import EC2Client


def list_tgw_attachments(
    tgw_id: str | None = None,
    ec2_client: EC2Client | None = None,
    topology: NetworkTopology | None = None,
) -> dict[str, Any]:
    """
    List Transit Gateway attachments.

    Args:
        tgw_id: Optional TGW ID to filter by
        ec2_client: EC2 client for live AWS data
        topology: Pre-loaded topology for demo mode

    Returns:
        List of TGW attachments with their details
    """
    if ec2_client:
        attachments = ec2_client.list_tgw_attachments(tgw_id)
        return {
            "attachments": [
                {
                    "attachment_id": att.attachment_id,
                    "tgw_id": att.tgw_id,
                    "type": att.attachment_type,
                    "state": att.state,
                    "resource_id": att.resource_id,
                    "resource_owner": att.resource_owner_id,
                    "name": att.name,
                }
                for att in attachments
            ],
            "count": len(attachments),
        }

    if topology:
        attachments_list = []
        if topology.attachments:
            for att in topology.attachments.values():
                attachments_list.append(
                    {
                        "attachment_id": att.attachment_id,
                        "tgw_id": att.tgw_id,
                        "type": att.attachment_type,
                        "state": att.state,
                        "resource_id": att.resource_id,
                        "name": att.name,
                        "associated_route_table": topology.tgw_attachment_to_route_table.get(
                            att.attachment_id, "unknown"
                        ),
                    }
                )
        else:
            for vpc_id, att_id in topology.vpc_to_tgw_attachment.items():
                rt_id = topology.tgw_attachment_to_route_table.get(att_id, "unknown")
                attachments_list.append(
                    {
                        "attachment_id": att_id,
                        "tgw_id": "tgw-demo-001",
                        "type": "vpc",
                        "state": "available",
                        "resource_id": vpc_id,
                        "associated_route_table": rt_id,
                    }
                )
        return {
            "attachments": attachments_list,
            "count": len(attachments_list),
            "mode": "demo",
        }

    return {"error": "No data source available"}


def tgw_route_lookup(
    tgw_route_table_id: str,
    destination_cidr: str,
    ec2_client: EC2Client | None = None,
    topology: NetworkTopology | None = None,
) -> dict[str, Any]:
    """
    Perform longest-prefix match lookup in a TGW route table.

    Args:
        tgw_route_table_id: TGW route table ID
        destination_cidr: CIDR or IP to look up

    Returns:
        Matching routes with their details
    """
    matcher = RouteMatcher()

    if ec2_client:
        tgw_rt = ec2_client.get_tgw_route_table(tgw_route_table_id)
        if not tgw_rt:
            return {"error": f"TGW route table {tgw_route_table_id} not found"}
    elif topology:
        tgw_rt = topology.tgw_route_tables.get(tgw_route_table_id)
        if not tgw_rt:
            available = list(topology.tgw_route_tables.keys())
            return {
                "error": f"TGW route table {tgw_route_table_id} not found",
                "available_tables": available,
            }
    else:
        return {"error": "No data source available"}

    if "/" in destination_cidr:
        matches = matcher.lookup_tgw_route_for_cidr(tgw_rt, destination_cidr)
        return {
            "route_table_id": tgw_route_table_id,
            "route_table_name": tgw_rt.name,
            "lookup_cidr": destination_cidr,
            "matches": [
                {
                    "destination_cidr": route.destination_cidr,
                    "attachment_id": route.attachment_id,
                    "resource_type": route.resource_type,
                    "resource_id": route.resource_id,
                    "state": route.state,
                    "route_type": route.route_type,
                    "match_type": match_type,
                }
                for route, match_type in matches
            ],
            "associations": list(tgw_rt.associations),
            "propagations": list(tgw_rt.propagations),
        }
    else:
        route, verdict, details = matcher.find_tgw_route(tgw_rt, destination_cidr)
        return {
            "route_table_id": tgw_route_table_id,
            "route_table_name": tgw_rt.name,
            "lookup_ip": destination_cidr,
            "verdict": verdict.value,
            "details": details,
            "matched_route": {
                "destination_cidr": route.destination_cidr,
                "attachment_id": route.attachment_id,
                "resource_type": route.resource_type,
                "resource_id": route.resource_id,
                "state": route.state,
                "route_type": route.route_type,
            }
            if route
            else None,
            "associations": list(tgw_rt.associations),
            "propagations": list(tgw_rt.propagations),
        }


def inspect_vpn_bgp(
    vpn_id: str | None = None,
    ec2_client: EC2Client | None = None,
    topology: NetworkTopology | None = None,
) -> dict[str, Any]:
    """
    Inspect Site-to-Site VPN tunnel and BGP status.

    Also checks Direct Connect virtual interfaces if available.

    Args:
        vpn_id: Optional VPN connection ID to inspect
        ec2_client: EC2 client for live AWS data
        topology: Pre-loaded topology for demo mode

    Returns:
        VPN tunnel status, BGP status, and DX VIF status
    """
    if ec2_client:
        vpn_connections = ec2_client.get_vpn_connections(vpn_id)
        dx_vifs = ec2_client.get_dx_vifs()

        return {
            "vpn_connections": [
                {
                    "vpn_id": vpn.vpn_id,
                    "name": vpn.name,
                    "state": vpn.state,
                    "tgw_id": vpn.tgw_id,
                    "customer_gateway_ip": vpn.customer_gateway_ip[:50] + "..."
                    if len(vpn.customer_gateway_ip) > 50
                    else vpn.customer_gateway_ip,
                    "tunnels": [
                        {
                            "outside_ip": t.outside_ip,
                            "status": t.status,
                            "status_message": t.status_message,
                            "bgp_status": t.bgp_status,
                        }
                        for t in vpn.tunnels
                    ],
                    "tunnel_summary": {
                        "total": len(vpn.tunnels),
                        "up": sum(1 for t in vpn.tunnels if t.status == "UP"),
                        "down": sum(1 for t in vpn.tunnels if t.status == "DOWN"),
                    },
                }
                for vpn in vpn_connections
            ],
            "direct_connect_vifs": [
                {
                    "vif_id": vif.vif_id,
                    "type": vif.vif_type,
                    "state": vif.state,
                    "vlan": vif.vlan,
                    "bgp_status": vif.bgp_status,
                    "amazon_address": vif.amazon_address,
                    "customer_address": vif.customer_address,
                    "bgp_asn": vif.bgp_asn,
                }
                for vif in dx_vifs
            ],
        }

    if topology:
        return {
            "vpn_connections": [
                {
                    "vpn_id": "vpn-demo-001",
                    "name": "demo-onprem-vpn",
                    "state": "available",
                    "tgw_id": "tgw-demo-001",
                    "tunnels": [
                        {
                            "outside_ip": "203.0.113.1",
                            "status": "UP",
                            "bgp_status": "UP",
                        },
                        {
                            "outside_ip": "203.0.113.2",
                            "status": "UP",
                            "bgp_status": "UP",
                        },
                    ],
                    "tunnel_summary": {"total": 2, "up": 2, "down": 0},
                    "advertised_routes": ["10.200.0.0/16"],
                    "received_routes": ["10.1.0.0/16", "10.2.0.0/16", "10.3.0.0/16"],
                }
            ],
            "direct_connect_vifs": [],
            "mode": "demo",
        }

    return {"error": "No data source available"}
