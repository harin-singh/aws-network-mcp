"""Route matching logic for VPC and Transit Gateway route tables.

This module implements longest-prefix matching and route evaluation
without any AWS SDK dependencies.
"""

from __future__ import annotations

import ipaddress
from typing import TypeVar

from aws_network_mcp.models import (
    RouteEntry,
    RouteTableInfo,
    TgwRouteEntry,
    TgwRouteTableInfo,
    Verdict,
)

R = TypeVar("R", RouteEntry, TgwRouteEntry)


class RouteMatcher:
    """Performs route table lookups using longest-prefix matching."""

    @staticmethod
    def ip_matches_cidr(ip: str, cidr: str) -> bool:
        """Check if an IP address falls within a CIDR block."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            network = ipaddress.ip_network(cidr, strict=False)
            return ip_obj in network
        except ValueError:
            return False

    @staticmethod
    def get_prefix_length(cidr: str) -> int:
        """Extract the prefix length from a CIDR notation."""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return network.prefixlen
        except ValueError:
            return -1

    @staticmethod
    def cidr_contains(outer: str, inner: str) -> bool:
        """Check if outer CIDR contains inner CIDR."""
        try:
            outer_net = ipaddress.ip_network(outer, strict=False)
            inner_net = ipaddress.ip_network(inner, strict=False)
            if outer_net.version != inner_net.version:
                return False
            return int(inner_net.network_address) >= int(outer_net.network_address) and int(
                inner_net.broadcast_address
            ) <= int(outer_net.broadcast_address)
        except ValueError:
            return False

    def find_matching_route(
        self, route_table: RouteTableInfo, destination_ip: str
    ) -> tuple[RouteEntry | None, Verdict, str]:
        """
        Find the longest-prefix matching route for a destination IP.

        Returns:
            Tuple of (matched_route, verdict, explanation)
        """
        best_match: RouteEntry | None = None
        best_prefix_len = -1

        for route in route_table.routes:
            if not route.destination_cidr:
                continue

            if self.ip_matches_cidr(destination_ip, route.destination_cidr):
                prefix_len = self.get_prefix_length(route.destination_cidr)
                if prefix_len > best_prefix_len:
                    best_match = route
                    best_prefix_len = prefix_len

        if best_match is None:
            return None, Verdict.DENY, f"No route found for {destination_ip}"

        if best_match.state == "blackhole":
            return (
                best_match,
                Verdict.BLACKHOLE,
                f"Route to {best_match.destination_cidr} via {best_match.target_id} is blackholed",
            )

        return (
            best_match,
            Verdict.ALLOW,
            f"Matched route {best_match.destination_cidr} -> {best_match.target_type}:{best_match.target_id}",
        )

    def find_tgw_route(
        self, tgw_rt: TgwRouteTableInfo, destination_ip: str
    ) -> tuple[TgwRouteEntry | None, Verdict, str]:
        """
        Find the longest-prefix matching route in a TGW route table.

        Returns:
            Tuple of (matched_route, verdict, explanation)
        """
        best_match: TgwRouteEntry | None = None
        best_prefix_len = -1

        for route in tgw_rt.routes:
            if not route.destination_cidr:
                continue

            if self.ip_matches_cidr(destination_ip, route.destination_cidr):
                prefix_len = self.get_prefix_length(route.destination_cidr)
                if prefix_len > best_prefix_len:
                    best_match = route
                    best_prefix_len = prefix_len

        if best_match is None:
            return (
                None,
                Verdict.DENY,
                f"No TGW route found for {destination_ip} in {tgw_rt.tgw_rt_id}",
            )

        if best_match.state == "blackhole":
            return (
                best_match,
                Verdict.BLACKHOLE,
                f"TGW route to {best_match.destination_cidr} is blackholed "
                f"(attachment: {best_match.attachment_id or 'none'})",
            )

        return (
            best_match,
            Verdict.ALLOW,
            f"Matched TGW route {best_match.destination_cidr} -> "
            f"{best_match.resource_type}:{best_match.attachment_id} ({best_match.route_type})",
        )

    def lookup_tgw_route_for_cidr(
        self, tgw_rt: TgwRouteTableInfo, destination_cidr: str
    ) -> list[tuple[TgwRouteEntry, str]]:
        """
        Find all TGW routes that match or contain a given CIDR.

        Useful for understanding routing for a network range.

        Returns:
            List of (route, match_type) tuples where match_type is
            'exact', 'more-specific', or 'less-specific'
        """
        results: list[tuple[TgwRouteEntry, str]] = []

        for route in tgw_rt.routes:
            if not route.destination_cidr:
                continue

            if route.destination_cidr == destination_cidr:
                results.append((route, "exact"))
            elif self.cidr_contains(route.destination_cidr, destination_cidr):
                results.append((route, "less-specific"))
            elif self.cidr_contains(destination_cidr, route.destination_cidr):
                results.append((route, "more-specific"))

        results.sort(
            key=lambda x: (
                0 if x[1] == "exact" else 1 if x[1] == "more-specific" else 2,
                -self.get_prefix_length(x[0].destination_cidr),
            )
        )

        return results
