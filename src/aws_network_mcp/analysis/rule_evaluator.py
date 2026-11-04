"""Security Group and NACL rule evaluation logic.

Pure Python evaluation of AWS security group and NACL rules
without any AWS SDK dependencies.
"""

from __future__ import annotations

from typing import Literal

from aws_network_mcp.analysis.route_matcher import RouteMatcher
from aws_network_mcp.models import (
    NaclInfo,
    NaclRule,
    Protocol,
    SecurityGroupInfo,
    SecurityGroupRule,
    Verdict,
    format_port_range,
)

EPHEMERAL_PORT_START = 1024
EPHEMERAL_PORT_END = 65535


class SecurityGroupEvaluator:
    """Evaluates traffic against security group rules."""

    def __init__(self, prefix_list_cidrs: dict[str, list[str]] | None = None):
        """
        Initialize evaluator.

        Args:
            prefix_list_cidrs: Mapping of prefix list IDs to their CIDR blocks
        """
        self.prefix_list_cidrs = prefix_list_cidrs or {}
        self._matcher = RouteMatcher()

    def _protocol_matches(self, rule_protocol: str, traffic_protocol: Protocol) -> bool:
        """Check if a rule's protocol matches the traffic protocol."""
        if rule_protocol == "-1" or rule_protocol == "all":
            return True
        protocol_map = {
            "6": Protocol.TCP,
            "17": Protocol.UDP,
            "1": Protocol.ICMP,
            "tcp": Protocol.TCP,
            "udp": Protocol.UDP,
            "icmp": Protocol.ICMP,
        }
        return protocol_map.get(rule_protocol.lower()) == traffic_protocol

    def _port_matches(
        self, from_port: int | None, to_port: int | None, traffic_port: int, protocol: Protocol
    ) -> bool:
        """Check if traffic port falls within rule's port range."""
        if protocol == Protocol.ICMP:
            return True

        if from_port is None or to_port is None:
            return True

        if from_port == -1 and to_port == -1:
            return True

        return from_port <= traffic_port <= to_port

    def _source_matches(
        self,
        rule: SecurityGroupRule,
        source_ip: str,
        source_sg_ids: set[str] | None = None,
    ) -> bool:
        """Check if source matches the rule's source specification."""
        if rule.cidr and self._matcher.ip_matches_cidr(source_ip, rule.cidr):
            return True

        if rule.source_sg_id and source_sg_ids and rule.source_sg_id in source_sg_ids:
            return True

        if rule.prefix_list_id:
            cidrs = self.prefix_list_cidrs.get(rule.prefix_list_id, [])
            for cidr in cidrs:
                if self._matcher.ip_matches_cidr(source_ip, cidr):
                    return True

        return False

    def evaluate_ingress(
        self,
        sg: SecurityGroupInfo,
        source_ip: str,
        port: int,
        protocol: Protocol,
        source_sg_ids: set[str] | None = None,
    ) -> tuple[Verdict, str, SecurityGroupRule | None]:
        """
        Evaluate if inbound traffic is allowed by security group.

        Security groups are stateful and deny-by-default.
        Any matching allow rule permits the traffic.

        Returns:
            Tuple of (verdict, explanation, matching_rule)
        """
        for rule in sg.rules:
            if rule.direction != "ingress":
                continue

            if not self._protocol_matches(rule.protocol, protocol):
                continue

            if not self._port_matches(rule.from_port, rule.to_port, port, protocol):
                continue

            if self._source_matches(rule, source_ip, source_sg_ids):
                desc = rule.description or "no description"
                source_desc = rule.cidr or rule.source_sg_id or rule.prefix_list_id or "any"
                return (
                    Verdict.ALLOW,
                    f"Allowed by SG {sg.sg_id} ingress rule: "
                    f"source={source_desc}, port={format_port_range(rule.from_port, rule.to_port)}, "
                    f"protocol={rule.protocol} ({desc})",
                    rule,
                )

        return (
            Verdict.DENY,
            f"No matching ingress rule in SG {sg.sg_id} ({sg.name}) "
            f"for source={source_ip}, port={port}, protocol={protocol.value}",
            None,
        )

    def evaluate_egress(
        self,
        sg: SecurityGroupInfo,
        destination_ip: str,
        port: int,
        protocol: Protocol,
        dest_sg_ids: set[str] | None = None,
    ) -> tuple[Verdict, str, SecurityGroupRule | None]:
        """
        Evaluate if outbound traffic is allowed by security group.

        Returns:
            Tuple of (verdict, explanation, matching_rule)
        """
        for rule in sg.rules:
            if rule.direction != "egress":
                continue

            if not self._protocol_matches(rule.protocol, protocol):
                continue

            if not self._port_matches(rule.from_port, rule.to_port, port, protocol):
                continue

            if self._source_matches(rule, destination_ip, dest_sg_ids):
                desc = rule.description or "no description"
                dest_desc = rule.cidr or rule.source_sg_id or rule.prefix_list_id or "any"
                return (
                    Verdict.ALLOW,
                    f"Allowed by SG {sg.sg_id} egress rule: "
                    f"destination={dest_desc}, port={format_port_range(rule.from_port, rule.to_port)}, "
                    f"protocol={rule.protocol} ({desc})",
                    rule,
                )

        return (
            Verdict.DENY,
            f"No matching egress rule in SG {sg.sg_id} ({sg.name}) "
            f"for destination={destination_ip}, port={port}, protocol={protocol.value}",
            None,
        )


class NaclEvaluator:
    """Evaluates traffic against Network ACL rules.

    NACLs are stateless and evaluated in rule number order.
    The first matching rule determines the action.
    """

    def __init__(self) -> None:
        self._matcher = RouteMatcher()

    def _protocol_matches(self, rule_protocol: str, traffic_protocol: Protocol) -> bool:
        """Check if a rule's protocol matches the traffic protocol."""
        if rule_protocol == "-1" or rule_protocol == "all":
            return True
        protocol_map = {
            "6": Protocol.TCP,
            "17": Protocol.UDP,
            "1": Protocol.ICMP,
            "tcp": Protocol.TCP,
            "udp": Protocol.UDP,
            "icmp": Protocol.ICMP,
        }
        return protocol_map.get(rule_protocol.lower()) == traffic_protocol

    def _port_matches(
        self, from_port: int | None, to_port: int | None, traffic_port: int, protocol: Protocol
    ) -> bool:
        """Check if traffic port falls within rule's port range."""
        if protocol == Protocol.ICMP:
            return True

        if from_port is None or to_port is None:
            return True

        return from_port <= traffic_port <= to_port

    def _evaluate_direction(
        self,
        nacl: NaclInfo,
        direction: Literal["ingress", "egress"],
        remote_ip: str,
        port: int,
        protocol: Protocol,
    ) -> tuple[Verdict, str, NaclRule | None]:
        """Evaluate NACL rules in one direction."""
        sorted_rules = sorted(
            [r for r in nacl.rules if r.direction == direction], key=lambda r: r.rule_number
        )

        for rule in sorted_rules:
            if rule.rule_number == 32767:
                continue

            if not self._protocol_matches(rule.protocol, protocol):
                continue

            if not self._port_matches(rule.from_port, rule.to_port, port, protocol):
                continue

            if not self._matcher.ip_matches_cidr(remote_ip, rule.cidr):
                continue

            if rule.action == "allow":
                return (
                    Verdict.ALLOW,
                    f"Allowed by NACL {nacl.nacl_id} rule #{rule.rule_number} "
                    f"({direction}): {rule.cidr} port {format_port_range(rule.from_port, rule.to_port)}",
                    rule,
                )
            else:
                return (
                    Verdict.DENY,
                    f"Denied by NACL {nacl.nacl_id} rule #{rule.rule_number} "
                    f"({direction}): {rule.cidr} port {format_port_range(rule.from_port, rule.to_port)}",
                    rule,
                )

        return (
            Verdict.DENY,
            f"Denied by NACL {nacl.nacl_id} default rule ({direction})",
            None,
        )

    def evaluate_ingress(
        self,
        nacl: NaclInfo,
        source_ip: str,
        port: int,
        protocol: Protocol,
    ) -> tuple[Verdict, str, NaclRule | None]:
        """
        Evaluate inbound NACL rules.

        Returns:
            Tuple of (verdict, explanation, matching_rule)
        """
        return self._evaluate_direction(nacl, "ingress", source_ip, port, protocol)

    def evaluate_egress(
        self,
        nacl: NaclInfo,
        destination_ip: str,
        port: int,
        protocol: Protocol,
    ) -> tuple[Verdict, str, NaclRule | None]:
        """
        Evaluate outbound NACL rules.

        Returns:
            Tuple of (verdict, explanation, matching_rule)
        """
        return self._evaluate_direction(nacl, "egress", destination_ip, port, protocol)

    def evaluate_return_traffic(
        self,
        nacl: NaclInfo,
        original_source_ip: str,  # noqa: ARG002
        original_dest_ip: str,
        original_dest_port: int,
        protocol: Protocol,
    ) -> tuple[Verdict, str, NaclRule | None]:
        """
        Evaluate return traffic for stateless NACL.

        For TCP/UDP, return traffic uses ephemeral source ports.
        This checks if the NACL allows the return path.

        Returns:
            Tuple of (verdict, explanation, matching_rule)
        """
        if protocol == Protocol.ICMP:
            return self._evaluate_direction(
                nacl, "ingress", original_dest_ip, original_dest_port, protocol
            )

        for ephemeral_start, ephemeral_end in [
            (EPHEMERAL_PORT_START, EPHEMERAL_PORT_END),
        ]:
            sorted_rules = sorted(
                [r for r in nacl.rules if r.direction == "ingress"], key=lambda r: r.rule_number
            )

            for rule in sorted_rules:
                if rule.rule_number == 32767:
                    continue

                if not self._protocol_matches(rule.protocol, protocol):
                    continue

                if not self._matcher.ip_matches_cidr(original_dest_ip, rule.cidr):
                    continue

                rule_from = rule.from_port if rule.from_port is not None else 0
                rule_to = rule.to_port if rule.to_port is not None else 65535
                if rule_from <= ephemeral_start and rule_to >= ephemeral_end:
                    if rule.action == "allow":
                        return (
                            Verdict.ALLOW,
                            f"Return traffic allowed by NACL {nacl.nacl_id} rule #{rule.rule_number}: "
                            f"ephemeral ports {ephemeral_start}-{ephemeral_end} from {rule.cidr}",
                            rule,
                        )
                    else:
                        return (
                            Verdict.DENY,
                            f"Return traffic BLOCKED by NACL {nacl.nacl_id} rule #{rule.rule_number}: "
                            f"ephemeral ports not allowed from {original_dest_ip}. "
                            f"NACLs are stateless - you need to allow return traffic on ports "
                            f"{ephemeral_start}-{ephemeral_end}.",
                            rule,
                        )

        return (
            Verdict.DENY,
            f"Return traffic blocked by NACL {nacl.nacl_id}: no rule allows "
            f"ephemeral ports ({EPHEMERAL_PORT_START}-{EPHEMERAL_PORT_END}) from {original_dest_ip}. "
            f"NACLs are stateless - add an ingress rule for return traffic.",
            None,
        )
