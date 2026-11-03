"""Route 53 Resolver API client for DNS troubleshooting."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

import boto3

from aws_network_mcp.models import DnsForwardingRule, ResolverEndpoint

if TYPE_CHECKING:
    from mypy_boto3_route53resolver.client import Route53ResolverClient as Boto3R53Client


class Route53ResolverClient:
    """Read-only Route 53 Resolver client for DNS troubleshooting."""

    def __init__(self, region: str | None = None, session: boto3.Session | None = None):
        self._session = session or boto3.Session()
        self._region = region or self._session.region_name
        self._client: Boto3R53Client = self._session.client(
            "route53resolver", region_name=self._region
        )

    def list_resolver_endpoints(self, vpc_id: str | None = None) -> list[ResolverEndpoint]:
        """List Route 53 Resolver endpoints."""
        kwargs: dict[str, Any] = {}
        if vpc_id:
            kwargs["Filters"] = [{"Name": "HostVPCId", "Values": [vpc_id]}]

        response = self._client.list_resolver_endpoints(**kwargs)
        result: list[ResolverEndpoint] = []

        for ep in response.get("ResolverEndpoints", []):
            ep_id = ep.get("Id", "")
            ip_response = self._client.list_resolver_endpoint_ip_addresses(ResolverEndpointId=ep_id)
            ips = [
                addr.get("Ip", "") for addr in ip_response.get("IpAddresses", []) if addr.get("Ip")
            ]

            direction_raw = ep.get("Direction", "OUTBOUND")
            direction: Literal["INBOUND", "OUTBOUND"] = (
                "INBOUND" if direction_raw == "INBOUND" else "OUTBOUND"
            )

            result.append(
                ResolverEndpoint(
                    endpoint_id=ep_id,
                    direction=direction,
                    vpc_id=ep.get("HostVPCId", ""),
                    ip_addresses=tuple(ips),
                    status=ep.get("Status", ""),
                    name=ep.get("Name"),
                )
            )

        return result

    def list_forwarding_rules(self, vpc_id: str | None = None) -> list[DnsForwardingRule]:
        """List Route 53 Resolver forwarding rules."""
        response = self._client.list_resolver_rules()
        result: list[DnsForwardingRule] = []

        for rule in response.get("ResolverRules", []):
            rule_id = rule.get("Id", "")

            assoc_response = self._client.list_resolver_rule_associations(
                Filters=[{"Name": "ResolverRuleId", "Values": [rule_id]}]
            )
            vpc_associations = [
                a.get("VPCId", "")
                for a in assoc_response.get("ResolverRuleAssociations", [])
                if a.get("VPCId")
            ]

            if vpc_id and vpc_id not in vpc_associations:
                continue

            target_ips = [t.get("Ip", "") for t in rule.get("TargetIps", []) if t.get("Ip")]

            rule_type_raw = rule.get("RuleType", "FORWARD")
            if rule_type_raw == "SYSTEM":
                rule_type: Literal["FORWARD", "SYSTEM", "RECURSIVE"] = "SYSTEM"
            elif rule_type_raw == "RECURSIVE":
                rule_type = "RECURSIVE"
            else:
                rule_type = "FORWARD"

            result.append(
                DnsForwardingRule(
                    rule_id=rule_id,
                    domain_name=rule.get("DomainName", ""),
                    rule_type=rule_type,
                    target_ips=tuple(target_ips),
                    vpc_associations=tuple(vpc_associations),
                    name=rule.get("Name"),
                )
            )

        return result

    def get_forwarding_rule_for_domain(self, domain: str, vpc_id: str) -> DnsForwardingRule | None:
        """Find the most specific forwarding rule that applies to a domain."""
        rules = self.list_forwarding_rules(vpc_id)
        best_match: DnsForwardingRule | None = None
        best_specificity = -1

        for rule in rules:
            if vpc_id not in rule.vpc_associations:
                continue

            rule_domain = rule.domain_name.lower().rstrip(".")
            query_domain = domain.lower().rstrip(".")

            if rule_domain == ".":
                specificity = 0
            elif query_domain == rule_domain or query_domain.endswith("." + rule_domain):
                specificity = len(rule_domain.split("."))
            else:
                continue

            if specificity > best_specificity:
                best_specificity = specificity
                best_match = rule

        return best_match
