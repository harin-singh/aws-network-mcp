"""DNS resolution and Route 53 Resolver tools."""

from __future__ import annotations

from typing import Any

from aws_network_mcp.aws_client.route53_client import Route53ResolverClient


def check_dns_resolution(
    domain: str,
    vpc_id: str,
    route53_client: Route53ResolverClient | None = None,
) -> dict[str, Any]:
    """
    Check how DNS for a domain would be resolved from a VPC.

    Examines Route 53 Resolver forwarding rules and endpoints
    to determine if queries are forwarded to on-premises DNS
    or resolved through Route 53.

    Args:
        domain: Domain name to check (e.g., "internal.corp.example.com")
        vpc_id: VPC ID to check resolution from

    Returns:
        DNS resolution path and any forwarding rules that apply
    """
    if route53_client is None:
        return _demo_dns_resolution(domain, vpc_id)

    try:
        endpoints = route53_client.list_resolver_endpoints(vpc_id)
        matching_rule = route53_client.get_forwarding_rule_for_domain(domain, vpc_id)
        all_rules = route53_client.list_forwarding_rules(vpc_id)

        return {
            "domain": domain,
            "vpc_id": vpc_id,
            "resolution_path": _determine_resolution_path(matching_rule),
            "matching_rule": {
                "rule_id": matching_rule.rule_id,
                "name": matching_rule.name,
                "domain_name": matching_rule.domain_name,
                "rule_type": matching_rule.rule_type,
                "target_ips": list(matching_rule.target_ips),
            }
            if matching_rule
            else None,
            "resolver_endpoints": [
                {
                    "endpoint_id": ep.endpoint_id,
                    "name": ep.name,
                    "direction": ep.direction,
                    "vpc_id": ep.vpc_id,
                    "ip_addresses": list(ep.ip_addresses),
                    "status": ep.status,
                }
                for ep in endpoints
            ],
            "all_forwarding_rules": [
                {
                    "rule_id": r.rule_id,
                    "name": r.name,
                    "domain_name": r.domain_name,
                    "rule_type": r.rule_type,
                    "target_ips": list(r.target_ips),
                    "associated_vpcs": list(r.vpc_associations),
                }
                for r in all_rules
            ],
        }

    except Exception as e:
        return {
            "error": str(e),
            "domain": domain,
            "vpc_id": vpc_id,
        }


def _determine_resolution_path(
    rule: Any,
) -> str:
    """Determine how DNS will be resolved based on the matching rule."""
    if rule is None:
        return "Route 53 Resolver (default - no forwarding rule)"

    if rule.rule_type == "FORWARD":
        targets = ", ".join(rule.target_ips) if rule.target_ips else "no targets"
        return f"Forwarded to on-premises DNS: {targets}"

    if rule.rule_type == "SYSTEM":
        return "Route 53 Resolver (SYSTEM rule - uses Route 53 private hosted zones)"

    return f"Unknown resolution type: {rule.rule_type}"


def _demo_dns_resolution(domain: str, vpc_id: str) -> dict[str, Any]:
    """Demo mode DNS resolution."""
    is_internal = any(
        domain.endswith(suffix) for suffix in [".internal", ".corp", ".local", ".example.corp"]
    )

    if is_internal:
        return {
            "domain": domain,
            "vpc_id": vpc_id,
            "resolution_path": "Forwarded to on-premises DNS: 10.200.0.53, 10.200.0.54",
            "matching_rule": {
                "rule_id": "rslvr-rr-demo-001",
                "name": "forward-internal-domains",
                "domain_name": ".".join(domain.split(".")[-2:]),
                "rule_type": "FORWARD",
                "target_ips": ["10.200.0.53", "10.200.0.54"],
            },
            "resolver_endpoints": [
                {
                    "endpoint_id": "rslvr-out-demo-001",
                    "name": "outbound-to-onprem",
                    "direction": "OUTBOUND",
                    "vpc_id": "vpc-shared-003",
                    "ip_addresses": ["10.3.0.10", "10.3.0.11"],
                    "status": "OPERATIONAL",
                },
                {
                    "endpoint_id": "rslvr-in-demo-001",
                    "name": "inbound-from-onprem",
                    "direction": "INBOUND",
                    "vpc_id": "vpc-shared-003",
                    "ip_addresses": ["10.3.0.20", "10.3.0.21"],
                    "status": "OPERATIONAL",
                },
            ],
            "mode": "demo",
        }
    else:
        return {
            "domain": domain,
            "vpc_id": vpc_id,
            "resolution_path": "Route 53 Resolver (default - no forwarding rule)",
            "matching_rule": None,
            "resolver_endpoints": [],
            "mode": "demo",
        }
