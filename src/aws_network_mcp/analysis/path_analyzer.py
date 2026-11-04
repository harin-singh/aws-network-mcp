"""Path analysis orchestration for AWS hybrid network troubleshooting.

Walks security groups, NACLs, VPC route tables, Transit Gateway route tables
(static, propagated, blackhole), inspection VPC / Network Firewall policy, and
on-prem routes learned over VPN/Direct Connect BGP.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol as TypingProtocol

from aws_network_mcp.analysis.firewall_evaluator import FirewallEvaluator
from aws_network_mcp.analysis.route_matcher import RouteMatcher
from aws_network_mcp.analysis.rule_evaluator import NaclEvaluator, SecurityGroupEvaluator
from aws_network_mcp.models import (
    FirewallPolicy,
    HopAnalysis,
    NaclInfo,
    NetworkEndpoint,
    PathAnalysisResult,
    Protocol,
    RouteTableInfo,
    SecurityGroupInfo,
    TgwAttachment,
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
    attachments: dict[str, TgwAttachment] = field(default_factory=dict)
    inspection_attachment_ids: frozenset[str] = field(default_factory=frozenset)
    firewall_policies: dict[str, FirewallPolicy] = field(default_factory=dict)
    inspection_vpc_id: str | None = None
    vpn_attachment_id: str | None = None
    known_endpoints: dict[str, NetworkEndpoint] = field(default_factory=dict)
    on_prem_cidrs: tuple[str, ...] = ()

    def resolve_endpoint(self, ip: str) -> NetworkEndpoint:
        """Resolve an IP to a known endpoint, or classify it as on-prem/external."""
        if ip in self.known_endpoints:
            return self.known_endpoints[ip]
        matcher = RouteMatcher()
        for cidr in self.on_prem_cidrs:
            if matcher.ip_matches_cidr(ip, cidr):
                return NetworkEndpoint(ip=ip, is_on_prem=True)
        return NetworkEndpoint(ip=ip, is_on_prem=True)


class TopologyProvider(TypingProtocol):
    """Protocol for providing network topology data."""

    def get_topology(self) -> NetworkTopology:
        """Return the current network topology."""
        ...


class PathAnalyzer:
    """Analyzes network paths through AWS and hybrid infrastructure."""

    def __init__(self, topology: NetworkTopology) -> None:
        self.topology = topology
        self.route_matcher = RouteMatcher()
        self.sg_evaluator = SecurityGroupEvaluator(topology.prefix_list_cidrs)
        self.nacl_evaluator = NaclEvaluator()
        self.firewall_evaluator = FirewallEvaluator()

    def analyze_path(
        self,
        source: NetworkEndpoint,
        destination: NetworkEndpoint,
        port: int,
        protocol: Protocol = Protocol.TCP,
    ) -> PathAnalysisResult:
        """Analyze the full path and report the exact rule or route at each hop."""
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
            return self._deny(result, source_sg_hop, "Blocked at source security group")

        source_nacl_hop = self._analyze_source_nacl(source, destination, port, protocol)
        result.hops.append(source_nacl_hop)
        if source_nacl_hop.verdict == Verdict.DENY:
            return self._deny(result, source_nacl_hop, "Blocked at source NACL")

        source_route_hop = self._analyze_source_route(source, destination)
        result.hops.append(source_route_hop)
        if source_route_hop.verdict in (Verdict.DENY, Verdict.BLACKHOLE):
            return self._deny(result, source_route_hop, "Blocked at source routing")

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
            tgw_hops, tgw_verdict, findings, bypassed = self._analyze_tgw_and_inspection(
                source, destination, source_vpc, dest_vpc, port, protocol
            )
            result.hops.extend(tgw_hops)
            result.additional_findings.extend(findings)
            result.inspection_bypassed = bypassed
            if tgw_verdict in (Verdict.DENY, Verdict.BLACKHOLE):
                blocking = next(
                    (
                        h
                        for h in reversed(tgw_hops)
                        if h.verdict in (Verdict.DENY, Verdict.BLACKHOLE)
                    ),
                    tgw_hops[-1] if tgw_hops else None,
                )
                if blocking:
                    return self._deny(result, blocking, "Blocked at Transit Gateway / inspection")

        if destination.is_on_prem or not destination.subnet_id:
            on_prem_hop = HopAnalysis(
                hop_type="on_prem",
                resource_id=destination.ip,
                resource_name="on-premises",
                verdict=Verdict.ALLOW,
                details=(
                    f"Destination {destination.ip} is on-premises "
                    f"(CIDRs {', '.join(self.topology.on_prem_cidrs) or 'unspecified'}). "
                    "AWS security groups and NACLs do not apply. Customer-gateway and "
                    "on-prem firewalls are not evaluated."
                ),
                matched_route=f"vpn/dx attachment {self.topology.vpn_attachment_id}"
                if self.topology.vpn_attachment_id
                else None,
            )
            result.hops.append(on_prem_hop)
            return self._allow(result)

        dest_route_hop = self._analyze_dest_route(source, destination)
        result.hops.append(dest_route_hop)
        if dest_route_hop.verdict in (Verdict.DENY, Verdict.BLACKHOLE):
            return self._deny(result, dest_route_hop, "Blocked at destination routing")

        dest_nacl_hop = self._analyze_dest_nacl(source, destination, port, protocol)
        result.hops.append(dest_nacl_hop)
        if dest_nacl_hop.verdict == Verdict.DENY:
            return self._deny(result, dest_nacl_hop, "Blocked at destination NACL")

        return_nacl_hop = self._analyze_return_nacl(source, destination, port, protocol)
        result.hops.append(return_nacl_hop)
        if return_nacl_hop.verdict == Verdict.DENY:
            return self._deny(result, return_nacl_hop, "Blocked on return path (NACL stateless)")

        dest_sg_hop = self._analyze_dest_security_group(source, destination, port, protocol)
        result.hops.append(dest_sg_hop)
        if dest_sg_hop.verdict == Verdict.DENY:
            return self._deny(result, dest_sg_hop, "Blocked at destination security group")

        return self._allow(result)

    def _allow(self, result: PathAnalysisResult) -> PathAnalysisResult:
        result.overall_verdict = Verdict.ALLOW
        bypass = (
            " Inspection was bypassed by a more-specific TGW route."
            if result.inspection_bypassed
            else ""
        )
        extra = (
            f" Additional findings: {'; '.join(result.additional_findings)}."
            if result.additional_findings
            else ""
        )
        result.summary = (
            f"Traffic ALLOWED from {result.source.ip} to "
            f"{result.destination.ip}:{result.port}/{result.protocol.value}. "
            f"Path traverses {len(result.hops)} hops successfully.{bypass}{extra}"
        )
        return result

    def _deny(
        self, result: PathAnalysisResult, hop: HopAnalysis, prefix: str
    ) -> PathAnalysisResult:
        result.overall_verdict = hop.verdict
        result.blocking_hop = hop
        extra = (
            f" Additional findings: {'; '.join(result.additional_findings)}."
            if result.additional_findings
            else ""
        )
        result.summary = f"{prefix}: {hop.details}.{extra}"
        return result

    def _dest_attachment(self, dest_vpc: str | None, destination: NetworkEndpoint) -> str | None:
        if dest_vpc:
            return self.topology.vpc_to_tgw_attachment.get(dest_vpc)
        if destination.is_on_prem or self._is_on_prem_ip(destination.ip):
            return self.topology.vpn_attachment_id
        return None

    def _is_on_prem_ip(self, ip: str) -> bool:
        return any(
            self.route_matcher.ip_matches_cidr(ip, cidr) for cidr in self.topology.on_prem_cidrs
        )

    def _firewall_policy(self) -> FirewallPolicy | None:
        if not self.topology.firewall_policies:
            return None
        if self.topology.inspection_vpc_id:
            for policy in self.topology.firewall_policies.values():
                return policy
        return next(iter(self.topology.firewall_policies.values()), None)

    def _hypothetical_firewall_finding(
        self,
        source: NetworkEndpoint,
        destination: NetworkEndpoint,
        port: int,
        protocol: Protocol,
    ) -> str | None:
        policy = self._firewall_policy()
        if policy is None:
            return None
        verdict, details, rule = self.firewall_evaluator.evaluate(
            policy, source.ip, destination.ip, port, protocol
        )
        if verdict == Verdict.DENY:
            rule_ref = f"sid:{rule.sid}" if rule else policy.default_action
            return (
                f"Defense in depth: Network Firewall {policy.name} would also drop this "
                f"flow via {rule_ref} ({details})"
            )
        return None

    def _analyze_tgw_and_inspection(
        self,
        source: NetworkEndpoint,
        destination: NetworkEndpoint,
        source_vpc: str,
        dest_vpc: str | None,
        port: int,
        protocol: Protocol,
    ) -> tuple[list[HopAnalysis], Verdict, list[str], bool]:
        hops: list[HopAnalysis] = []
        findings: list[str] = []

        source_attachment = self.topology.vpc_to_tgw_attachment.get(source_vpc)
        if not source_attachment:
            hops.append(
                HopAnalysis(
                    hop_type="transit_gateway",
                    resource_id="none",
                    resource_name=None,
                    verdict=Verdict.DENY,
                    details=f"Source VPC {source_vpc} has no Transit Gateway attachment",
                    blocking_rule="missing TGW attachment",
                )
            )
            return hops, Verdict.DENY, findings, False

        tgw_rt_id = self.topology.tgw_attachment_to_route_table.get(source_attachment)
        if not tgw_rt_id:
            hops.append(
                HopAnalysis(
                    hop_type="transit_gateway",
                    resource_id=source_attachment,
                    resource_name=None,
                    verdict=Verdict.UNKNOWN,
                    details=f"No TGW route table associated with attachment {source_attachment}",
                )
            )
            return hops, Verdict.UNKNOWN, findings, False

        tgw_rt = self.topology.tgw_route_tables.get(tgw_rt_id)
        if not tgw_rt:
            hops.append(
                HopAnalysis(
                    hop_type="transit_gateway",
                    resource_id=tgw_rt_id,
                    resource_name=None,
                    verdict=Verdict.UNKNOWN,
                    details=f"TGW route table {tgw_rt_id} not found",
                )
            )
            return hops, Verdict.UNKNOWN, findings, False

        dest_attachment = self._dest_attachment(dest_vpc, destination)
        route, verdict, details = self.route_matcher.find_tgw_route(tgw_rt, destination.ip)
        matched = None
        if route:
            matched = (
                f"{route.destination_cidr} -> {route.attachment_id or 'none'} "
                f"({route.route_type}, {route.state})"
            )

        source_rt_hop = HopAnalysis(
            hop_type="transit_gateway",
            resource_id=tgw_rt_id,
            resource_name=tgw_rt.name,
            verdict=verdict,
            details=details,
            matched_route=matched,
            blocking_rule=(
                f"{route.route_type} {route.state} route {route.destination_cidr}"
                if route and verdict in (Verdict.DENY, Verdict.BLACKHOLE)
                else (
                    "missing route propagation or static route" if verdict == Verdict.DENY else None
                )
            ),
        )
        hops.append(source_rt_hop)

        if verdict in (Verdict.DENY, Verdict.BLACKHOLE):
            fw_finding = self._hypothetical_firewall_finding(source, destination, port, protocol)
            if fw_finding:
                findings.append(fw_finding)
            if verdict == Verdict.DENY and tgw_rt.propagations:
                source_rt_hop.details = (
                    f"{details}. Route table associations: {', '.join(tgw_rt.associations) or 'none'}; "
                    f"propagations: {', '.join(tgw_rt.propagations)}"
                )
            return hops, verdict, findings, False

        assert route is not None
        via_inspection = (
            bool(self.topology.inspection_attachment_ids)
            and route.attachment_id in self.topology.inspection_attachment_ids
        )

        if not via_inspection:
            if self.topology.inspection_attachment_ids and route.attachment_id:
                hops.append(
                    HopAnalysis(
                        hop_type="inspection_bypass",
                        resource_id=route.attachment_id,
                        resource_name="inspection skipped",
                        verdict=Verdict.ALLOW,
                        details=(
                            f"TGW route {matched} sends traffic directly to attachment "
                            f"{route.attachment_id} instead of an inspection attachment "
                            f"({', '.join(sorted(self.topology.inspection_attachment_ids))}). "
                            "A spoke prefix was propagated or statically installed on this RT, "
                            "bypassing Network Firewall."
                        ),
                        matched_route=matched,
                        blocking_rule=None,
                    )
                )
                findings.append(
                    f"Inspection bypass: {route.route_type} route {route.destination_cidr} "
                    f"on {tgw_rt_id} targets {route.attachment_id}"
                )
                return hops, Verdict.ALLOW, findings, True
            return hops, Verdict.ALLOW, findings, False

        policy = self._firewall_policy()
        if policy is None:
            hops.append(
                HopAnalysis(
                    hop_type="network_firewall",
                    resource_id="none",
                    resource_name=None,
                    verdict=Verdict.UNKNOWN,
                    details=(
                        "Traffic is steered to the inspection attachment but no "
                        "Network Firewall policy is loaded in the topology"
                    ),
                )
            )
        else:
            fw_verdict, fw_details, fw_rule = self.firewall_evaluator.evaluate(
                policy, source.ip, destination.ip, port, protocol
            )
            hops.append(
                HopAnalysis(
                    hop_type="network_firewall",
                    resource_id=policy.policy_id,
                    resource_name=policy.name,
                    verdict=fw_verdict,
                    details=fw_details,
                    matched_route=f"sid:{fw_rule.sid} {fw_rule.action}" if fw_rule else None,
                    blocking_rule=(
                        f"sid:{fw_rule.sid} ({fw_rule.message})"
                        if fw_rule and fw_verdict == Verdict.DENY
                        else (policy.default_action if fw_verdict == Verdict.DENY else None)
                    ),
                )
            )
            if fw_verdict == Verdict.DENY:
                return hops, Verdict.DENY, findings, False

        inspection_attachment = next(iter(self.topology.inspection_attachment_ids), None)
        insp_rt_id = (
            self.topology.tgw_attachment_to_route_table.get(inspection_attachment)
            if inspection_attachment
            else None
        )
        if not insp_rt_id:
            hops.append(
                HopAnalysis(
                    hop_type="transit_gateway",
                    resource_id="inspection",
                    resource_name=None,
                    verdict=Verdict.UNKNOWN,
                    details="Inspection attachment has no associated TGW route table",
                )
            )
            return hops, Verdict.UNKNOWN, findings, False

        insp_rt = self.topology.tgw_route_tables.get(insp_rt_id)
        if not insp_rt:
            hops.append(
                HopAnalysis(
                    hop_type="transit_gateway",
                    resource_id=insp_rt_id,
                    resource_name=None,
                    verdict=Verdict.UNKNOWN,
                    details=f"Inspection TGW route table {insp_rt_id} not found",
                )
            )
            return hops, Verdict.UNKNOWN, findings, False

        insp_route, insp_verdict, insp_details = self.route_matcher.find_tgw_route(
            insp_rt, destination.ip
        )
        insp_matched = None
        if insp_route:
            insp_matched = (
                f"{insp_route.destination_cidr} -> {insp_route.attachment_id or 'none'} "
                f"({insp_route.route_type}, {insp_route.state})"
            )
        hops.append(
            HopAnalysis(
                hop_type="transit_gateway",
                resource_id=insp_rt_id,
                resource_name=insp_rt.name,
                verdict=insp_verdict,
                details=f"Inspection return/forward lookup: {insp_details}",
                matched_route=insp_matched,
                blocking_rule=(
                    f"{insp_route.route_type} {insp_route.state} route {insp_route.destination_cidr}"
                    if insp_route and insp_verdict in (Verdict.DENY, Verdict.BLACKHOLE)
                    else (
                        "missing route propagation or static route on inspection RT"
                        if insp_verdict == Verdict.DENY
                        else None
                    )
                ),
            )
        )
        if insp_verdict in (Verdict.DENY, Verdict.BLACKHOLE):
            return hops, insp_verdict, findings, False

        if (
            insp_route
            and dest_attachment
            and insp_route.attachment_id
            and insp_route.attachment_id != dest_attachment
        ):
            hops[-1].details = (
                f"{hops[-1].details} (routes to {insp_route.attachment_id}, "
                f"expected destination attachment {dest_attachment})"
            )
        return hops, Verdict.ALLOW, findings, False

    def _analyze_source_security_group(
        self,
        source: NetworkEndpoint,
        destination: NetworkEndpoint,
        port: int,
        protocol: Protocol,
    ) -> HopAnalysis:
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

    def _analyze_dest_route(
        self, source: NetworkEndpoint, destination: NetworkEndpoint
    ) -> HopAnalysis:
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
            blocking_rule=(
                f"Missing ingress rule for source {source.ip} on port {port}/{protocol.value}"
            ),
        )
