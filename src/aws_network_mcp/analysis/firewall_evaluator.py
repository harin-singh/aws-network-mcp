"""AWS Network Firewall policy evaluation (STRICT_ORDER + default action)."""

from __future__ import annotations

from aws_network_mcp.analysis.route_matcher import RouteMatcher
from aws_network_mcp.models import FirewallPolicy, FirewallRule, Protocol, Verdict


class FirewallEvaluator:
    """Evaluate a 5-tuple against a Network Firewall stateful policy."""

    def __init__(self) -> None:
        self._matcher = RouteMatcher()

    def _protocol_matches(self, rule_protocol: str, traffic_protocol: Protocol) -> bool:
        if rule_protocol in ("ip", "any", "-1"):
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

    def _cidrs_match(self, ip: str, cidrs: tuple[str, ...], negate: bool = False) -> bool:
        matched = any(self._matcher.ip_matches_cidr(ip, cidr) for cidr in cidrs)
        return (not matched) if negate else matched

    def _port_matches(self, port: int, dest_ports: tuple[str, ...]) -> bool:
        if not dest_ports or "any" in dest_ports:
            return True
        for spec in dest_ports:
            if ":" in spec:
                start_s, end_s = spec.split(":", 1)
                try:
                    if int(start_s) <= port <= int(end_s):
                        return True
                except ValueError:
                    continue
            else:
                try:
                    if port == int(spec):
                        return True
                except ValueError:
                    continue
        return False

    def evaluate(
        self,
        policy: FirewallPolicy,
        source_ip: str,
        dest_ip: str,
        port: int,
        protocol: Protocol,
    ) -> tuple[Verdict, str, FirewallRule | None]:
        """Return the first STRICT_ORDER match, or the policy default action."""
        for rule in policy.rules:
            if not self._protocol_matches(rule.protocol, protocol):
                continue
            if not self._cidrs_match(source_ip, rule.source_cidrs, negate=rule.source_negate):
                continue
            if not self._cidrs_match(dest_ip, rule.dest_cidrs, negate=rule.dest_negate):
                continue
            if not self._port_matches(port, rule.dest_ports):
                continue

            if rule.action == "pass":
                return (
                    Verdict.ALLOW,
                    (
                        f"Allowed by Network Firewall {policy.name} rule sid:{rule.sid} "
                        f"({rule.message or 'pass'}) for {source_ip} -> {dest_ip}:{port}/{protocol.value}"
                    ),
                    rule,
                )
            return (
                Verdict.DENY,
                (
                    f"Dropped by Network Firewall {policy.name} rule sid:{rule.sid} "
                    f"({rule.message or 'drop'}) for {source_ip} -> {dest_ip}:{port}/{protocol.value}"
                ),
                rule,
            )

        default = policy.default_action
        if default in ("aws:drop_established", "aws:drop", "drop"):
            return (
                Verdict.DENY,
                (
                    f"Dropped by Network Firewall {policy.name} default action {default} "
                    f"(rule_order={policy.rule_order}); no explicit pass rule matched "
                    f"{source_ip} -> {dest_ip}:{port}/{protocol.value}"
                ),
                None,
            )
        return (
            Verdict.ALLOW,
            (
                f"Allowed by Network Firewall {policy.name} default action {default} "
                f"for {source_ip} -> {dest_ip}:{port}/{protocol.value}"
            ),
            None,
        )
