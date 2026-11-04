"""EC2 API client for network resource discovery.

Provides read-only access to VPC, subnet, route table, security group,
NACL, Transit Gateway, VPN, and Direct Connect resources.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, cast

import boto3

from aws_network_mcp.models import (
    DxVifInfo,
    NaclInfo,
    NaclRule,
    NetworkEndpoint,
    ReachabilityAnalysisResult,
    RouteEntry,
    RouteTableInfo,
    SecurityGroupInfo,
    SecurityGroupRule,
    TgwAttachment,
    TgwRouteEntry,
    TgwRouteTableInfo,
    VpnConnectionInfo,
    VpnTunnelInfo,
)

if TYPE_CHECKING:
    from mypy_boto3_ec2.client import EC2Client as Boto3EC2Client
    from mypy_boto3_ec2.type_defs import (
        FilterTypeDef,
    )


def _get_name_tag(tags: Any) -> str | None:
    """Extract Name tag value from AWS tags list."""
    if not tags:
        return None
    for tag in tags:
        if tag.get("Key") == "Name":
            value = tag.get("Value")
            return str(value) if value is not None else None
    return None


class EC2Client:
    """Read-only EC2 client for network resource discovery."""

    def __init__(
        self,
        region: str | None = None,
        session: boto3.Session | None = None,
        client: Boto3EC2Client | None = None,
    ):
        self._session = session or boto3.Session()
        self._region = region or self._session.region_name or "us-east-1"
        self._client: Boto3EC2Client = client or self._session.client(
            "ec2", region_name=self._region
        )

    def get_instance_network_info(self, instance_id: str) -> NetworkEndpoint | None:
        """Get network endpoint info for an EC2 instance."""
        response = self._client.describe_instances(InstanceIds=[instance_id])
        reservations = response.get("Reservations", [])
        if not reservations:
            return None

        instances = reservations[0].get("Instances", [])
        if not instances:
            return None

        instance = instances[0]
        network_interfaces = instance.get("NetworkInterfaces", [])
        if not network_interfaces:
            return None

        primary_eni = network_interfaces[0]
        return NetworkEndpoint(
            ip=primary_eni.get("PrivateIpAddress", ""),
            vpc_id=instance.get("VpcId"),
            subnet_id=instance.get("SubnetId"),
            instance_id=instance_id,
            eni_id=primary_eni.get("NetworkInterfaceId"),
        )

    def get_eni_network_info(self, eni_id: str) -> NetworkEndpoint | None:
        """Get network endpoint info for an ENI."""
        response = self._client.describe_network_interfaces(NetworkInterfaceIds=[eni_id])
        interfaces = response.get("NetworkInterfaces", [])
        if not interfaces:
            return None

        eni = interfaces[0]
        return NetworkEndpoint(
            ip=eni.get("PrivateIpAddress", ""),
            vpc_id=eni.get("VpcId"),
            subnet_id=eni.get("SubnetId"),
            eni_id=eni_id,
            instance_id=eni.get("Attachment", {}).get("InstanceId"),
        )

    def get_ip_network_info(self, ip: str, vpc_id: str | None = None) -> NetworkEndpoint | None:
        """Find ENI by private IP address."""
        filters: list[FilterTypeDef] = [{"Name": "private-ip-address", "Values": [ip]}]
        if vpc_id:
            filters.append({"Name": "vpc-id", "Values": [vpc_id]})

        response = self._client.describe_network_interfaces(Filters=filters)
        interfaces = response.get("NetworkInterfaces", [])
        if not interfaces:
            return NetworkEndpoint(ip=ip, vpc_id=vpc_id, is_on_prem=vpc_id is None)

        eni = interfaces[0]
        return NetworkEndpoint(
            ip=ip,
            vpc_id=eni.get("VpcId"),
            subnet_id=eni.get("SubnetId"),
            eni_id=eni.get("NetworkInterfaceId"),
            instance_id=eni.get("Attachment", {}).get("InstanceId"),
        )

    def get_route_table(self, route_table_id: str) -> RouteTableInfo | None:
        """Get route table details."""
        response = self._client.describe_route_tables(RouteTableIds=[route_table_id])
        tables = response.get("RouteTables", [])
        if not tables:
            return None

        rt = tables[0]
        routes: list[RouteEntry] = []
        for route in rt.get("Routes", []):
            dest = route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock", "")
            target_type, target_id = self._extract_route_target(route)
            routes.append(
                RouteEntry(
                    destination_cidr=dest,
                    target_type=target_type,
                    target_id=target_id,
                    state="active" if route.get("State") == "active" else "blackhole",
                    prefix_list_id=route.get("DestinationPrefixListId"),
                )
            )

        associations = [
            a.get("SubnetId", "") for a in rt.get("Associations", []) if a.get("SubnetId")
        ]

        return RouteTableInfo(
            route_table_id=route_table_id,
            vpc_id=rt.get("VpcId", ""),
            name=_get_name_tag(rt.get("Tags")),
            routes=tuple(routes),
            subnet_associations=tuple(associations),
        )

    def _extract_route_target(self, route: Any) -> tuple[str, str]:
        """Extract target type and ID from a route."""
        if route.get("GatewayId"):
            return "gateway", route["GatewayId"]
        if route.get("NatGatewayId"):
            return "nat-gateway", route["NatGatewayId"]
        if route.get("TransitGatewayId"):
            return "transit-gateway", route["TransitGatewayId"]
        if route.get("VpcPeeringConnectionId"):
            return "vpc-peering", route["VpcPeeringConnectionId"]
        if route.get("NetworkInterfaceId"):
            return "network-interface", route["NetworkInterfaceId"]
        if route.get("LocalGatewayId"):
            return "local-gateway", route["LocalGatewayId"]
        return "local", "local"

    def get_route_tables_for_vpc(self, vpc_id: str) -> list[RouteTableInfo]:
        """Get all route tables in a VPC."""
        response = self._client.describe_route_tables(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )
        result = []
        for rt in response.get("RouteTables", []):
            rt_id = rt.get("RouteTableId", "")
            if rt_info := self.get_route_table(rt_id):
                result.append(rt_info)
        return result

    def get_subnet_route_table(self, subnet_id: str) -> RouteTableInfo | None:
        """Get the route table associated with a subnet."""
        response = self._client.describe_route_tables(
            Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
        )
        tables = response.get("RouteTables", [])
        if tables:
            rt_id = tables[0].get("RouteTableId", "")
            return self.get_route_table(rt_id)

        subnet_response = self._client.describe_subnets(SubnetIds=[subnet_id])
        subnets = subnet_response.get("Subnets", [])
        if not subnets:
            return None

        vpc_id = subnets[0].get("VpcId", "")
        main_response = self._client.describe_route_tables(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "association.main", "Values": ["true"]},
            ]
        )
        main_tables = main_response.get("RouteTables", [])
        if main_tables:
            rt_id = main_tables[0].get("RouteTableId", "")
            return self.get_route_table(rt_id)

        return None

    def get_security_group(self, sg_id: str) -> SecurityGroupInfo | None:
        """Get security group details."""
        response = self._client.describe_security_groups(GroupIds=[sg_id])
        groups = response.get("SecurityGroups", [])
        if not groups:
            return None

        sg = groups[0]
        rules: list[SecurityGroupRule] = []

        for rule in sg.get("IpPermissions", []):
            rules.extend(self._parse_sg_rules(rule, "ingress"))

        for rule in sg.get("IpPermissionsEgress", []):
            rules.extend(self._parse_sg_rules(rule, "egress"))

        return SecurityGroupInfo(
            sg_id=sg_id,
            name=sg.get("GroupName", ""),
            vpc_id=sg.get("VpcId", ""),
            rules=tuple(rules),
        )

    def _parse_sg_rules(
        self, rule: Any, direction: Literal["ingress", "egress"]
    ) -> list[SecurityGroupRule]:
        """Parse security group permission into rule objects."""
        results: list[SecurityGroupRule] = []
        protocol = str(rule.get("IpProtocol", "-1"))
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")

        for ip_range in rule.get("IpRanges", []):
            results.append(
                SecurityGroupRule(
                    direction=direction,
                    protocol=protocol,
                    from_port=from_port,
                    to_port=to_port,
                    cidr=ip_range.get("CidrIp"),
                    description=ip_range.get("Description"),
                )
            )

        for ip_range in rule.get("Ipv6Ranges", []):
            results.append(
                SecurityGroupRule(
                    direction=direction,
                    protocol=protocol,
                    from_port=from_port,
                    to_port=to_port,
                    cidr=ip_range.get("CidrIpv6"),
                    description=ip_range.get("Description"),
                )
            )

        for sg_ref in rule.get("UserIdGroupPairs", []):
            results.append(
                SecurityGroupRule(
                    direction=direction,
                    protocol=protocol,
                    from_port=from_port,
                    to_port=to_port,
                    source_sg_id=sg_ref.get("GroupId"),
                    description=sg_ref.get("Description"),
                )
            )

        for pl in rule.get("PrefixListIds", []):
            results.append(
                SecurityGroupRule(
                    direction=direction,
                    protocol=protocol,
                    from_port=from_port,
                    to_port=to_port,
                    prefix_list_id=pl.get("PrefixListId"),
                    description=pl.get("Description"),
                )
            )

        if not results:
            results.append(
                SecurityGroupRule(
                    direction=direction,
                    protocol=protocol,
                    from_port=from_port,
                    to_port=to_port,
                )
            )

        return results

    def get_eni_security_groups(self, eni_id: str) -> list[str]:
        """Get security group IDs attached to an ENI."""
        response = self._client.describe_network_interfaces(NetworkInterfaceIds=[eni_id])
        interfaces = response.get("NetworkInterfaces", [])
        if not interfaces:
            return []
        return [sg.get("GroupId", "") for sg in interfaces[0].get("Groups", [])]

    def get_nacl(self, nacl_id: str) -> NaclInfo | None:
        """Get Network ACL details."""
        response = self._client.describe_network_acls(NetworkAclIds=[nacl_id])
        acls = response.get("NetworkAcls", [])
        if not acls:
            return None

        nacl = acls[0]
        rules: list[NaclRule] = []

        for entry in nacl.get("Entries", []):
            direction: Literal["ingress", "egress"] = (
                "ingress" if not entry.get("Egress") else "egress"
            )
            protocol = str(entry.get("Protocol", "-1"))
            port_range = entry.get("PortRange", {})
            rules.append(
                NaclRule(
                    rule_number=entry.get("RuleNumber", 0),
                    direction=direction,
                    protocol=protocol,
                    from_port=port_range.get("From"),
                    to_port=port_range.get("To"),
                    cidr=entry.get("CidrBlock", ""),
                    action="allow" if entry.get("RuleAction") == "allow" else "deny",
                )
            )

        associations = [
            a.get("SubnetId", "") for a in nacl.get("Associations", []) if a.get("SubnetId")
        ]

        return NaclInfo(
            nacl_id=nacl_id,
            vpc_id=nacl.get("VpcId", ""),
            name=_get_name_tag(nacl.get("Tags")),
            rules=tuple(rules),
            subnet_associations=tuple(associations),
        )

    def get_subnet_nacl(self, subnet_id: str) -> NaclInfo | None:
        """Get the NACL associated with a subnet."""
        response = self._client.describe_network_acls(
            Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
        )
        acls = response.get("NetworkAcls", [])
        if acls:
            nacl_id = acls[0].get("NetworkAclId", "")
            return self.get_nacl(nacl_id)
        return None

    def list_tgw_attachments(self, tgw_id: str | None = None) -> list[TgwAttachment]:
        """List Transit Gateway attachments."""
        filters: list[FilterTypeDef] = []
        if tgw_id:
            filters.append({"Name": "transit-gateway-id", "Values": [tgw_id]})

        response = self._client.describe_transit_gateway_attachments(Filters=filters)
        result: list[TgwAttachment] = []

        for att in response.get("TransitGatewayAttachments", []):
            result.append(
                TgwAttachment(
                    attachment_id=att.get("TransitGatewayAttachmentId", ""),
                    tgw_id=att.get("TransitGatewayId", ""),
                    attachment_type=cast(
                        Literal["vpc", "vpn", "direct-connect-gateway", "peering", "connect"],
                        att.get("ResourceType", "vpc")
                        if att.get("ResourceType")
                        in {"vpc", "vpn", "direct-connect-gateway", "peering", "connect"}
                        else "vpc",
                    ),
                    state=att.get("State", ""),
                    resource_id=att.get("ResourceId", ""),
                    resource_owner_id=att.get("ResourceOwnerId", ""),
                    name=_get_name_tag(att.get("Tags")),
                )
            )

        return result

    def get_tgw_route_table(self, tgw_rt_id: str) -> TgwRouteTableInfo | None:
        """Get Transit Gateway route table with routes."""
        rt_response = self._client.describe_transit_gateway_route_tables(
            TransitGatewayRouteTableIds=[tgw_rt_id]
        )
        tables = rt_response.get("TransitGatewayRouteTables", [])
        if not tables:
            return None

        rt = tables[0]
        routes_response = self._client.search_transit_gateway_routes(
            TransitGatewayRouteTableId=tgw_rt_id,
            Filters=[{"Name": "state", "Values": ["active", "blackhole"]}],
        )

        routes: list[TgwRouteEntry] = []
        for route in routes_response.get("Routes", []):
            attachments = route.get("TransitGatewayAttachments", [])
            attachment = attachments[0] if attachments else {}
            routes.append(
                TgwRouteEntry(
                    destination_cidr=route.get("DestinationCidrBlock", ""),
                    attachment_id=attachment.get("TransitGatewayAttachmentId"),
                    resource_type=attachment.get("ResourceType"),
                    resource_id=attachment.get("ResourceId"),
                    state="active" if route.get("State") == "active" else "blackhole",
                    route_type="propagated" if route.get("Type") == "propagated" else "static",
                    prefix_list_id=route.get("PrefixListId"),
                )
            )

        assoc_response = self._client.get_transit_gateway_route_table_associations(
            TransitGatewayRouteTableId=tgw_rt_id
        )
        associations = [
            a.get("TransitGatewayAttachmentId", "") for a in assoc_response.get("Associations", [])
        ]

        prop_response = self._client.get_transit_gateway_route_table_propagations(
            TransitGatewayRouteTableId=tgw_rt_id
        )
        propagations = [
            p.get("TransitGatewayAttachmentId", "")
            for p in prop_response.get("TransitGatewayRouteTablePropagations", [])
        ]

        return TgwRouteTableInfo(
            tgw_rt_id=tgw_rt_id,
            tgw_id=rt.get("TransitGatewayId", ""),
            name=_get_name_tag(rt.get("Tags")),
            routes=tuple(routes),
            associations=tuple(associations),
            propagations=tuple(propagations),
        )

    def get_vpn_connections(self, vpn_id: str | None = None) -> list[VpnConnectionInfo]:
        """Get VPN connection details including tunnel status."""
        kwargs: dict[str, Any] = {}
        if vpn_id:
            kwargs["VpnConnectionIds"] = [vpn_id]

        response = self._client.describe_vpn_connections(**kwargs)
        result: list[VpnConnectionInfo] = []

        for vpn in response.get("VpnConnections", []):
            tunnels: list[VpnTunnelInfo] = []
            for tunnel in vpn.get("VgwTelemetry", []):
                tunnels.append(
                    VpnTunnelInfo(
                        tunnel_id=tunnel.get("OutsideIpAddress", ""),
                        outside_ip=tunnel.get("OutsideIpAddress", ""),
                        status="UP" if tunnel.get("Status") == "UP" else "DOWN",
                        status_message=tunnel.get("StatusMessage"),
                    )
                )

            result.append(
                VpnConnectionInfo(
                    vpn_id=vpn.get("VpnConnectionId", ""),
                    state=vpn.get("State", ""),
                    tgw_id=vpn.get("TransitGatewayId"),
                    customer_gateway_ip=vpn.get("CustomerGatewayConfiguration", ""),
                    tunnels=tuple(tunnels),
                    name=_get_name_tag(vpn.get("Tags")),
                )
            )

        return result

    def get_dx_vifs(self) -> list[DxVifInfo]:
        """Get Direct Connect virtual interfaces."""
        dx_client = self._session.client("directconnect", region_name=self._region)
        response = dx_client.describe_virtual_interfaces()
        result: list[DxVifInfo] = []

        for vif in response.get("virtualInterfaces", []):
            vif_type = vif.get("virtualInterfaceType", "private")
            if vif_type not in ("private", "public", "transit"):
                vif_type = "private"

            result.append(
                DxVifInfo(
                    vif_id=vif.get("virtualInterfaceId", ""),
                    vif_type=vif_type,
                    state=vif.get("virtualInterfaceState", ""),
                    bgp_status=vif.get("bgpPeers", [{}])[0].get("bgpStatus", "unknown")
                    if vif.get("bgpPeers")
                    else "unknown",
                    vlan=vif.get("vlan", 0),
                    amazon_address=vif.get("amazonAddress"),
                    customer_address=vif.get("customerAddress"),
                    bgp_asn=vif.get("asn"),
                )
            )

        return result

    def get_prefix_list_entries(self, prefix_list_id: str) -> list[str]:
        """Get CIDR entries from a managed prefix list."""
        response = self._client.get_managed_prefix_list_entries(PrefixListId=prefix_list_id)
        return [e.get("Cidr", "") for e in response.get("Entries", [])]

    def create_reachability_path(
        self,
        source: str,
        destination: str,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        destination_port: int | None = None,
        protocol: str = "tcp",
    ) -> str:
        """Create a VPC Reachability Analyzer path."""
        kwargs: dict[str, Any] = {
            "Source": source,
            "Destination": destination,
            "Protocol": protocol,
        }
        if source_ip:
            kwargs["SourceIp"] = source_ip
        if destination_ip:
            kwargs["DestinationIp"] = destination_ip
        if destination_port:
            kwargs["DestinationPort"] = destination_port

        response = self._client.create_network_insights_path(**kwargs)
        return response.get("NetworkInsightsPath", {}).get("NetworkInsightsPathId", "")

    def start_reachability_analysis(self, path_id: str) -> str:
        """Start a Reachability Analyzer analysis."""
        import uuid

        response = self._client.start_network_insights_analysis(
            NetworkInsightsPathId=path_id, ClientToken=str(uuid.uuid4())
        )
        return response.get("NetworkInsightsAnalysis", {}).get("NetworkInsightsAnalysisId", "")

    def get_reachability_analysis(self, analysis_id: str) -> ReachabilityAnalysisResult:
        """Get the results of a Reachability Analyzer analysis."""
        response = self._client.describe_network_insights_analyses(
            NetworkInsightsAnalysisIds=[analysis_id]
        )
        analyses = response.get("NetworkInsightsAnalyses", [])
        if not analyses:
            return ReachabilityAnalysisResult(
                analysis_id=analysis_id,
                path_id="",
                status="not_found",
                reachable=None,
            )

        analysis = analyses[0]
        explanations: list[str] = []
        for exp in analysis.get("Explanations", []):
            component = exp.get("Component", {})
            explanations.append(
                f"{exp.get('ExplanationCode', 'UNKNOWN')}: "
                f"{component.get('Name', component.get('Id', 'unknown'))}"
            )

        forward_path: list[str] = []
        for hop in analysis.get("ForwardPathComponents", []):
            component = hop.get("Component", {})
            forward_path.append(
                f"{component.get('Name', component.get('Id', 'unknown'))} "
                f"({hop.get('SequenceNumber', '?')})"
            )

        return ReachabilityAnalysisResult(
            analysis_id=analysis_id,
            path_id=analysis.get("NetworkInsightsPathId", ""),
            status=analysis.get("Status", "unknown"),
            reachable=analysis.get("NetworkPathFound"),
            explanations=explanations,
            forward_path=forward_path,
        )

    def delete_reachability_path(self, path_id: str) -> None:
        """Delete a Reachability Analyzer path."""
        self._client.delete_network_insights_path(NetworkInsightsPathId=path_id)
