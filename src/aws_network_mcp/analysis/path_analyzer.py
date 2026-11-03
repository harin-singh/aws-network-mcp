"""Path analysis orchestration for AWS network troubleshooting.

This module combines route matching, security group evaluation,
and NACL evaluation to provide complete hop-by-hop path analysis.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol as TypingProtocol

from aws_network_mcp.analysis.route_matcher import RouteMatcher
from aws_network_mcp.analysis.rule_evaluator import NaclEvaluator, SecurityGroupEvaluator
from aws_network_mcp.models import (
    HopAnalysis,
    NaclInfo,
    NetworkEndpoint,
    PathAnalysisResult,
    Protocol,
    RouteTableInfo,
    SecurityGroupInfo,
    TgwRouteTableInfo,
    Verdict,
)


@dataclass
class NetworkTopology:
    """Container for network topology data needed for path analysis."""

    route_tables: dict[str, RouteTableInfo]
    security_groups: dict[str, SecurityGroupInfo]
    nacls: dict[str, NaclInfo]
    tgw_route_tables: dict[str, TgwRouteTableInfo]
    subnet_to_route_table: dict[str, str]
    subnet_to_nacl: dict[str, str]
    eni_to_security_groups: dict[str, list[str]]
    subnet_to_vpc: dict[str, str]
    tgw_attachment_to_route_table: dict[str, str]
    vpc_to_tgw_attachment: dict[str, str]
    prefix_list_cidrs: dict[str, list[str]]


class TopologyProvider(TypingProtocol):
    """Protocol for providing network topology data."""

    def get_topology(self) -> NetworkTopology:
        """Return the current network topology."""
        ...


class PathAnalyzer:
    """Analyzes network paths through AWS infrastructure.

    This is the main orchestrator that combines route matching,
    security group evaluation, and NACL evaluation to determine
    if traffic can flow from source to destination.
    """

    def __init__(
        self,
        topology: NetworkTopology,
    ):
        self.topology = topology
        self.route_matcher = RouteMatcher()
        self.sg_evaluator = SecurityGroupEvaluator(topology.prefix_list_cidrs)
        self.nacl_evaluator = NaclEvaluator()

    def analyze_path(
        self,
        source: NetworkEndpoint,
        destination: NetworkEndpoint,
        port: int,
        protocol: Protocol = Protocol.TCP,
    ) -> PathAnalysisResult:
        """
        Analyze the full network path from source to destination.

        Evaluates:
        1. Source security group egress
        2. Source NACL egress
        3. Source subnet route table
        4. Transit Gateway routing (if cross-VPC)
        5. Destination subnet route table
        6. Destination NACL ingress
        7. Destination security group ingress
        8. Return path NACL rules (stateless check)

        Returns:
            PathAnalysisResult with hop-by-hop verdict and blocking rule if any
        """
        result = PathAnalysisResult(
            source=source,
            destination=destination,
            port=port,
            protocol=protocol,
            overall_verdict=Verdict.UNKNOWN,
            hops=[],
        )

        if not source.subnet_id:
            result.overall_verdict = Verdict.UNKNOWN
            result.summary = "Cannot analyze path: source subnet unknown"
            return result

        source_sg_hop = self._analyze_source_security_group(source, destination, port, protocol)
        result.hops.append(source_sg_hop)
        if source_sg_hop.verdict == Verdict.DENY:
            result.overall_verdict = Verdict.DENY
            result.blocking_hop = source_sg_hop
            result.summary = f"Blocked at source security group: {source_sg_hop.details}"
            return result

        source_nacl_hop = self._analyze_source_nacl(source, destination, port, protocol)
        result.hops.append(source_nacl_hop)
        if source_nacl_hop.verdict == Verdict.DENY:
            result.overall_verdict = Verdict.DENY
            result.blocking_hop = source_nacl_hop
            result.summary = f"Blocked at source NACL: {source_nacl_hop.details}"
            return result

        source_route_hop = self._analyze_source_route(source, destination)
        result.hops.append(source_route_hop)
        if source_route_hop.verdict in (Verdict.DENY, Verdict.BLACKHOLE):
            result.overall_verdict = source_route_hop.verdict
            result.blocking_hop = source_route_hop
            result.summary = f"Blocked at source routing: {source_route_hop.details}"
            return result

        source_vpc = self.topology.subnet_to_vpc.get(source.subnet_id)
        dest_vpc = (
            self.topology.subnet_to_vpc.get(destination.subnet_id)
            if destination.subnet_id
            else None
        )

        needs_tgw_check = (
            (source_vpc and dest_vpc and source_vpc != dest_vpc)
            or (source_vpc and destination.is_on_prem)
            or (
                source_route_hop.matched_route
                and "transit-gateway" in source_route_hop.matched_route.lower()
            )
        )

        if needs_tgw_check and source_vpc:
            tgw_hop = self._analyze_tgw_routing(source, destination, source_vpc, dest_vpc)
            result.hops.append(tgw_hop)
            if tgw_hop.verdict in (Verdict.DENY, Verdict.BLACKHOLE):
                result.overall_verdict = tgw_hop.verdict
                result.blocking_hop = tgw_hop
                result.summary = f"Blocked at Transit Gateway: {tgw_hop.details}"
                return result

        if destination.subnet_id:
            dest_route_hop = self._analyze_dest_route(source, destination)
            result.hops.append(dest_route_hop)
            if dest_route_hop.verdict in (Verdict.DENY, Verdict.BLACKHOLE):
                result.overall_verdict = dest_route_hop.verdict
                result.blocking_hop = dest_route_hop
                result.summary = f"Blocked at destination routing: {dest_route_hop.details}"
                return result

            dest_nacl_hop = self._analyze_dest_nacl(source, destination, port, protocol)
            result.hops.append(dest_nacl_hop)
            if dest_nacl_hop.verdict == Verdict.DENY:
                result.overall_verdict = Verdict.DENY
                result.blocking_hop = dest_nacl_hop
                result.summary = f"Blocked at destination NACL: {dest_nacl_hop.details}"
                return result

            return_nacl_hop = self._analyze_return_nacl(source, destination, port, protocol)
            result.hops.append(return_nacl_hop)
            if return_nacl_hop.verdict == Verdict.DENY:
                result.overall_verdict = Verdict.DENY
                result.blocking_hop = return_nacl_hop
                result.summary = (
                    f"Blocked on return path (NACL stateless): {return_nacl_hop.details}"
                )
                return result

        dest_sg_hop = self._analyze_dest_security_group(source, destination, port, protocol)
        result.hops.append(dest_sg_hop)
        if dest_sg_hop.verdict == Verdict.DENY:
            result.overall_verdict = Verdict.DENY
            result.blocking_hop = dest_sg_hop
            result.summary = f"Blocked at destination security group: {dest_sg_hop.details}"
            return result

        result.overall_verdict = Verdict.ALLOW
        result.summary = (
            f"Traffic ALLOWED from {source.ip} to {destination.ip}:{port}/{protocol.value}. "
            f"Path traverses {len(result.hops)} hops successfully."
        )
        return result

    def _analyze_source_security_group(
        self,
        source: NetworkEndpoint,
        destination: NetworkEndpoint,
        port: int,
        protocol: Protocol,
    ) -> HopAnalysis:
        """Analyze source security group egress rules."""
        if not source.eni_id:
            return HopAnalysis(
                hop_type="security_group",
                resource_id="unknown",
                resource_name=None,
                verdict=Verdict.UNKNOWN,
                details="Source ENI not specified, cannot evaluate security group",
            )

        sg_ids = self.topology.eni_to_security_groups.get(source.eni_id, [])
        if not sg_ids:
            return HopAnalysis(
                hop_type="security_group",
                resource_id=source.eni_id,
                resource_name=None,
                verdict=Verdict.ALLOW,
                details="No security groups attached to source ENI (default allow egress)",
            )

        for sg_id in sg_ids:
            sg = self.topology.security_groups.get(sg_id)
            if not sg:
                continue

            verdict, details, rule = self.sg_evaluator.evaluate_egress(
                sg, destination.ip, port, protocol
            )
            if verdict == Verdict.ALLOW:
                return HopAnalysis(
                    hop_type="security_group",
                    resource_id=sg_id,
                    resource_name=sg.name,
                    verdict=Verdict.ALLOW,
                    details=details,
                    matched_route=f"egress rule: {rule.cidr or rule.source_sg_id}"
                    if rule
                    else None,
                )

        return HopAnalysis(
            hop_type="security_group",
            resource_id=",".join(sg_ids),
            resource_name=None,
            verdict=Verdict.DENY,
            details=f"No security group allows egress to {destination.ip}:{port}/{protocol.value}",
            blocking_rule="No matching egress rule in any attached security group",
        )

    def _analyze_source_nacl(
        self,
        source: NetworkEndpoint,
        destination: NetworkEndpoint,
        port: int,
        protocol: Protocol,
    ) -> HopAnalysis:
        """Analyze source subnet NACL egress rules."""
        if not source.subnet_id:
            return HopAnalysis(
                hop_type="nacl",
                resource_id="unknown",
                resource_name=None,
                verdict=Verdict.UNKNOWN,
                details="Source subnet not specified",
            )

        nacl_id = self.topology.subnet_to_nacl.get(source.subnet_id)
        if not nacl_id:
            return HopAnalysis(
                hop_type="nacl",
                resource_id="default",
                resource_name=None,
                verdict=Verdict.ALLOW,
                details="Using default NACL (allows all traffic)",
            )

        nacl = self.topology.nacls.get(nacl_id)
        if not nacl:
            return HopAnalysis(
                hop_type="nacl",
                resource_id=nacl_id,
                resource_name=None,
                verdict=Verdict.UNKNOWN,
                details=f"NACL {nacl_id} not found in topology",
            )

        verdict, details, rule = self.nacl_evaluator.evaluate_egress(
            nacl, destination.ip, port, protocol
        )
        return HopAnalysis(
            hop_type="nacl",
            resource_id=nacl_id,
            resource_name=nacl.name,
            verdict=verdict,
            details=details,
            blocking_rule=f"rule #{rule.rule_number}" if rule and verdict == Verdict.DENY else None,
            matched_route=f"rule #{rule.rule_number}" if rule else None,
        )

    def _analyze_source_route(
        self, source: NetworkEndpoint, destination: NetworkEndpoint
    ) -> HopAnalysis:
        """Analyze source subnet route table."""
        if not source.subnet_id:
            return HopAnalysis(
                hop_type="route_table",
                resource_id="unknown",
                resource_name=None,
                verdict=Verdict.UNKNOWN,
                details="Source subnet not specified",
            )

        rt_id = self.topology.subnet_to_route_table.get(source.subnet_id)
        if not rt_id:
            return HopAnalysis(
                hop_type="route_table",
                resource_id="main",
                resource_name=None,
                verdict=Verdict.UNKNOWN,
                details="Using main route table (not explicitly associated)",
            )

        rt = self.topology.route_tables.get(rt_id)
        if not rt:
            return HopAnalysis(
                hop_type="route_table",
                resource_id=rt_id,
                resource_name=None,
                verdict=Verdict.UNKNOWN,
                details=f"Route table {rt_id} not found in topology",
            )

        route, verdict, details = self.route_matcher.find_matching_route(rt, destination.ip)
        return HopAnalysis(
            hop_type="route_table",
            resource_id=rt_id,
            resource_name=rt.name,
            verdict=verdict,
            details=details,
            matched_route=f"{route.destination_cidr} -> {route.target_id}" if route else None,
            blocking_rule=f"blackhole to {route.destination_cidr}"
            if verdict == Verdict.BLACKHOLE and route
            else None,
        )

    def _analyze_tgw_routing(
        self,
        source: NetworkEndpoint,  # noqa: ARG002
        destination: NetworkEndpoint,
        source_vpc: str,
        dest_vpc: str | None,
    ) -> HopAnalysis:
        """Analyze Transit Gateway routing between VPCs or to on-prem."""
        source_attachment = self.topology.vpc_to_tgw_attachment.get(source_vpc)
        if not source_attachment:
            return HopAnalysis(
                hop_type="transit_gateway",
                resource_id="none",
                resource_name=None,
                verdict=Verdict.DENY,
                details=f"Source VPC {source_vpc} has no Transit Gateway attachment",
            )

        tgw_rt_id = self.topology.tgw_attachment_to_route_table.get(source_attachment)
        if not tgw_rt_id:
            return HopAnalysis(
                hop_type="transit_gateway",
                resource_id=source_attachment,
                resource_name=None,
                verdict=Verdict.UNKNOWN,
                details=f"No TGW route table associated with attachment {source_attachment}",
            )

        tgw_rt = self.topology.tgw_route_tables.get(tgw_rt_id)
        if not tgw_rt:
            return HopAnalysis(
                hop_type="transit_gateway",
                resource_id=tgw_rt_id,
                resource_name=None,
                verdict=Verdict.UNKNOWN,
                details=f"TGW route table {tgw_rt_id} not found",
            )

        dest_attachment = self.topology.vpc_to_tgw_attachment.get(dest_vpc) if dest_vpc else None
        route, verdict, details = self.route_matcher.find_tgw_route(tgw_rt, destination.ip)

        if verdict == Verdict.BLACKHOLE:
            return HopAnalysis(
                hop_type="transit_gateway",
                resource_id=tgw_rt_id,
                resource_name=tgw_rt.name,
                verdict=Verdict.BLACKHOLE,
                details=details,
                blocking_rule=f"blackhole route for {route.destination_cidr}" if route else None,
            )

        if verdict == Verdict.DENY:
            propagations_str = ", ".join(tgw_rt.propagations) if tgw_rt.propagations else "none"
            return HopAnalysis(
                hop_type="transit_gateway",
                resource_id=tgw_rt_id,
                resource_name=tgw_rt.name,
                verdict=Verdict.DENY,
                details=f"{details}. Route table propagations: {propagations_str}",
                blocking_rule="missing route propagation or static route",
            )

        if route and route.attachment_id != dest_attachment:
            return HopAnalysis(
                hop_type="transit_gateway",
                resource_id=tgw_rt_id,
                resource_name=tgw_rt.name,
                verdict=Verdict.ALLOW,
                details=f"{details} (routes to attachment {route.attachment_id}, "
                f"destination VPC attachment is {dest_attachment})",
                matched_route=f"{route.destination_cidr} -> {route.attachment_id}",
            )

        return HopAnalysis(
            hop_type="transit_gateway",
            resource_id=tgw_rt_id,
            resource_name=tgw_rt.name,
            verdict=verdict,
            details=details,
            matched_route=f"{route.destination_cidr} -> {route.attachment_id}" if route else None,
        )

    def _analyze_dest_route(
        self, source: NetworkEndpoint, destination: NetworkEndpoint
    ) -> HopAnalysis:
        """Analyze destination subnet route table for return path."""
        if not destination.subnet_id:
            return HopAnalysis(
                hop_type="route_table",
                resource_id="unknown",
                resource_name=None,
                verdict=Verdict.UNKNOWN,
                details="Destination subnet not specified",
            )

        rt_id = self.topology.subnet_to_route_table.get(destination.subnet_id)
        if not rt_id:
            return HopAnalysis(
                hop_type="route_table",
                resource_id="main",
                resource_name=None,
                verdict=Verdict.ALLOW,
                details="Using main route table (implicit local route)",
            )

        rt = self.topology.route_tables.get(rt_id)
        if not rt:
            return HopAnalysis(
                hop_type="route_table",
                resource_id=rt_id,
                resource_name=None,
                verdict=Verdict.UNKNOWN,
                details=f"Route table {rt_id} not found",
            )

        route, verdict, details = self.route_matcher.find_matching_route(rt, source.ip)
        return HopAnalysis(
            hop_type="route_table",
            resource_id=rt_id,
            resource_name=rt.name,
            verdict=verdict,
            details=f"Return path: {details}",
            matched_route=f"{route.destination_cidr} -> {route.target_id}" if route else None,
        )

    def _analyze_dest_nacl(
        self,
        source: NetworkEndpoint,
        destination: NetworkEndpoint,
        port: int,
        protocol: Protocol,
    ) -> HopAnalysis:
        """Analyze destination subnet NACL ingress rules."""
        if not destination.subnet_id:
            return HopAnalysis(
                hop_type="nacl",
                resource_id="unknown",
                resource_name=None,
                verdict=Verdict.UNKNOWN,
                details="Destination subnet not specified",
            )

        nacl_id = self.topology.subnet_to_nacl.get(destination.subnet_id)
        if not nacl_id:
            return HopAnalysis(
                hop_type="nacl",
                resource_id="default",
                resource_name=None,
                verdict=Verdict.ALLOW,
                details="Using default NACL (allows all traffic)",
            )

        nacl = self.topology.nacls.get(nacl_id)
        if not nacl:
            return HopAnalysis(
                hop_type="nacl",
                resource_id=nacl_id,
                resource_name=None,
                verdict=Verdict.UNKNOWN,
                details=f"NACL {nacl_id} not found",
            )

        verdict, details, rule = self.nacl_evaluator.evaluate_ingress(
            nacl, source.ip, port, protocol
        )
        return HopAnalysis(
            hop_type="nacl",
            resource_id=nacl_id,
            resource_name=nacl.name,
            verdict=verdict,
            details=details,
            blocking_rule=f"rule #{rule.rule_number}" if rule and verdict == Verdict.DENY else None,
        )

    def _analyze_return_nacl(
        self,
        source: NetworkEndpoint,
        destination: NetworkEndpoint,
        port: int,
        protocol: Protocol,
    ) -> HopAnalysis:
        """Analyze NACL rules for return traffic (stateless check)."""
        if not source.subnet_id:
            return HopAnalysis(
                hop_type="nacl_return",
                resource_id="unknown",
                resource_name=None,
                verdict=Verdict.UNKNOWN,
                details="Source subnet not specified for return path analysis",
            )

        nacl_id = self.topology.subnet_to_nacl.get(source.subnet_id)
        if not nacl_id:
            return HopAnalysis(
                hop_type="nacl_return",
                resource_id="default",
                resource_name=None,
                verdict=Verdict.ALLOW,
                details="Using default NACL for return traffic (allows all)",
            )

        nacl = self.topology.nacls.get(nacl_id)
        if not nacl:
            return HopAnalysis(
                hop_type="nacl_return",
                resource_id=nacl_id,
                resource_name=None,
                verdict=Verdict.UNKNOWN,
                details=f"NACL {nacl_id} not found",
            )

        verdict, details, rule = self.nacl_evaluator.evaluate_return_traffic(
            nacl, source.ip, destination.ip, port, protocol
        )
        return HopAnalysis(
            hop_type="nacl_return",
            resource_id=nacl_id,
            resource_name=nacl.name,
            verdict=verdict,
            details=details,
            blocking_rule=f"rule #{rule.rule_number}" if rule and verdict == Verdict.DENY else None,
        )

    def _analyze_dest_security_group(
        self,
        source: NetworkEndpoint,
        destination: NetworkEndpoint,
        port: int,
        protocol: Protocol,
    ) -> HopAnalysis:
        """Analyze destination security group ingress rules."""
        if not destination.eni_id:
            return HopAnalysis(
                hop_type="security_group",
                resource_id="unknown",
                resource_name=None,
                verdict=Verdict.UNKNOWN,
                details="Destination ENI not specified, assuming on-prem or external",
            )

        sg_ids = self.topology.eni_to_security_groups.get(destination.eni_id, [])
        if not sg_ids:
            return HopAnalysis(
                hop_type="security_group",
                resource_id=destination.eni_id,
                resource_name=None,
                verdict=Verdict.DENY,
                details="No security groups attached to destination ENI (deny by default)",
            )

        source_sg_ids = set(self.topology.eni_to_security_groups.get(source.eni_id or "", []))

        for sg_id in sg_ids:
            sg = self.topology.security_groups.get(sg_id)
            if not sg:
                continue

            verdict, details, rule = self.sg_evaluator.evaluate_ingress(
                sg, source.ip, port, protocol, source_sg_ids
            )
            if verdict == Verdict.ALLOW:
                return HopAnalysis(
                    hop_type="security_group",
                    resource_id=sg_id,
                    resource_name=sg.name,
                    verdict=Verdict.ALLOW,
                    details=details,
                    matched_route=f"ingress rule: {rule.cidr or rule.source_sg_id}"
                    if rule
                    else None,
                )

        sg_names = [
            self.topology.security_groups[sg_id].name
            for sg_id in sg_ids
            if sg_id in self.topology.security_groups
        ]
        return HopAnalysis(
            hop_type="security_group",
            resource_id=",".join(sg_ids),
            resource_name=",".join(str(n) for n in sg_names if n),
            verdict=Verdict.DENY,
            details=f"No security group allows ingress from {source.ip}:{port}/{protocol.value}",
            blocking_rule=f"Missing ingress rule for source {source.ip} on port {port}/{protocol.value}",
        )
