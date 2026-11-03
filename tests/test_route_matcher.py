"""Tests for route matching logic."""

from __future__ import annotations

from aws_network_mcp.analysis.route_matcher import RouteMatcher
from aws_network_mcp.models import (
    RouteEntry,
    RouteTableInfo,
    TgwRouteEntry,
    TgwRouteTableInfo,
    Verdict,
)


class TestRouteMatcher:
    """Tests for RouteMatcher class."""

    def test_ip_matches_cidr_exact(self) -> None:
        """Test IP matching within CIDR."""
        matcher = RouteMatcher()
        assert matcher.ip_matches_cidr("10.0.0.1", "10.0.0.0/24")
        assert matcher.ip_matches_cidr("10.0.0.255", "10.0.0.0/24")
        assert not matcher.ip_matches_cidr("10.0.1.1", "10.0.0.0/24")

    def test_ip_matches_cidr_wide(self) -> None:
        """Test IP matching with wide CIDR."""
        matcher = RouteMatcher()
        assert matcher.ip_matches_cidr("10.255.255.255", "10.0.0.0/8")
        assert not matcher.ip_matches_cidr("11.0.0.1", "10.0.0.0/8")

    def test_ip_matches_cidr_default_route(self) -> None:
        """Test IP matching with default route."""
        matcher = RouteMatcher()
        assert matcher.ip_matches_cidr("1.2.3.4", "0.0.0.0/0")
        assert matcher.ip_matches_cidr("192.168.1.1", "0.0.0.0/0")

    def test_get_prefix_length(self) -> None:
        """Test prefix length extraction."""
        matcher = RouteMatcher()
        assert matcher.get_prefix_length("10.0.0.0/24") == 24
        assert matcher.get_prefix_length("10.0.0.0/16") == 16
        assert matcher.get_prefix_length("10.0.0.0/8") == 8
        assert matcher.get_prefix_length("0.0.0.0/0") == 0

    def test_get_prefix_length_invalid(self) -> None:
        """Test prefix length with invalid CIDR."""
        matcher = RouteMatcher()
        assert matcher.get_prefix_length("invalid") == -1

    def test_cidr_contains(self) -> None:
        """Test CIDR containment check."""
        matcher = RouteMatcher()
        assert matcher.cidr_contains("10.0.0.0/8", "10.0.0.0/16")
        assert matcher.cidr_contains("10.0.0.0/8", "10.1.2.0/24")
        assert not matcher.cidr_contains("10.0.0.0/16", "10.0.0.0/8")

    def test_find_matching_route_longest_prefix(self) -> None:
        """Test longest prefix match selection."""
        matcher = RouteMatcher()
        rt = RouteTableInfo(
            route_table_id="rtb-001",
            vpc_id="vpc-001",
            name="test",
            routes=(
                RouteEntry("10.0.0.0/8", "gateway", "igw-001", "active"),
                RouteEntry("10.0.0.0/16", "nat-gateway", "nat-001", "active"),
                RouteEntry("10.0.1.0/24", "transit-gateway", "tgw-001", "active"),
            ),
            subnet_associations=(),
        )

        route, verdict, _ = matcher.find_matching_route(rt, "10.0.1.50")
        assert route is not None
        assert route.destination_cidr == "10.0.1.0/24"
        assert verdict == Verdict.ALLOW

    def test_find_matching_route_no_match(self) -> None:
        """Test when no route matches."""
        matcher = RouteMatcher()
        rt = RouteTableInfo(
            route_table_id="rtb-001",
            vpc_id="vpc-001",
            name="test",
            routes=(RouteEntry("10.0.0.0/8", "gateway", "igw-001", "active"),),
            subnet_associations=(),
        )

        route, verdict, details = matcher.find_matching_route(rt, "192.168.1.1")
        assert route is None
        assert verdict == Verdict.DENY
        assert "No route found" in details

    def test_find_matching_route_blackhole(self) -> None:
        """Test blackhole route detection."""
        matcher = RouteMatcher()
        rt = RouteTableInfo(
            route_table_id="rtb-001",
            vpc_id="vpc-001",
            name="test",
            routes=(RouteEntry("10.0.0.0/8", "transit-gateway", "tgw-001", "blackhole"),),
            subnet_associations=(),
        )

        route, verdict, details = matcher.find_matching_route(rt, "10.0.1.1")
        assert route is not None
        assert verdict == Verdict.BLACKHOLE
        assert "blackhole" in details.lower()

    def test_find_tgw_route(self) -> None:
        """Test TGW route lookup."""
        matcher = RouteMatcher()
        tgw_rt = TgwRouteTableInfo(
            tgw_rt_id="tgw-rtb-001",
            tgw_id="tgw-001",
            name="test",
            routes=(
                TgwRouteEntry(
                    "10.0.0.0/16", "tgw-att-001", "vpc", "vpc-001", "active", "propagated"
                ),
                TgwRouteEntry("10.1.0.0/16", "tgw-att-002", "vpc", "vpc-002", "active", "static"),
            ),
            associations=(),
            propagations=(),
        )

        route, verdict, _ = matcher.find_tgw_route(tgw_rt, "10.1.0.50")
        assert route is not None
        assert route.attachment_id == "tgw-att-002"
        assert verdict == Verdict.ALLOW

    def test_find_tgw_route_blackhole(self) -> None:
        """Test TGW blackhole route."""
        matcher = RouteMatcher()
        tgw_rt = TgwRouteTableInfo(
            tgw_rt_id="tgw-rtb-001",
            tgw_id="tgw-001",
            name="test",
            routes=(
                TgwRouteEntry(
                    "10.200.0.0/16", "tgw-att-vpn", "vpn", "vpn-001", "blackhole", "propagated"
                ),
            ),
            associations=(),
            propagations=(),
        )

        route, verdict, details = matcher.find_tgw_route(tgw_rt, "10.200.1.1")
        assert verdict == Verdict.BLACKHOLE
        assert route is not None
        assert "blackhole" in details.lower()

    def test_lookup_tgw_route_for_cidr(self) -> None:
        """Test CIDR-based TGW route lookup."""
        matcher = RouteMatcher()
        tgw_rt = TgwRouteTableInfo(
            tgw_rt_id="tgw-rtb-001",
            tgw_id="tgw-001",
            name="test",
            routes=(
                TgwRouteEntry(
                    "10.0.0.0/8", "tgw-att-001", "vpc", "vpc-001", "active", "propagated"
                ),
                TgwRouteEntry("10.0.0.0/16", "tgw-att-002", "vpc", "vpc-002", "active", "static"),
                TgwRouteEntry("10.0.1.0/24", "tgw-att-003", "vpc", "vpc-003", "active", "static"),
            ),
            associations=(),
            propagations=(),
        )

        matches = matcher.lookup_tgw_route_for_cidr(tgw_rt, "10.0.0.0/16")
        assert len(matches) == 3
        assert matches[0][1] == "exact"
        assert matches[1][1] == "more-specific"
        assert matches[2][1] == "less-specific"
