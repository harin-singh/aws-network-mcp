"""Tests for MCP tool implementations."""

from __future__ import annotations

from aws_network_mcp.fixtures.topology import load_demo_topology
from aws_network_mcp.tools.connectivity import describe_path, explain_connectivity
from aws_network_mcp.tools.dns import check_dns_resolution
from aws_network_mcp.tools.tgw import list_tgw_attachments, tgw_route_lookup


class TestConnectivityTools:
    """Tests for connectivity analysis tools."""

    def test_describe_path_demo_mode(self) -> None:
        """Test describe_path in demo mode."""
        topology = load_demo_topology()
        result = describe_path(
            source_ip="10.10.0.10",
            dest_ip="10.20.0.10",
            port=443,
            topology=topology,
        )

        assert "error" not in result or result.get("error") is None
        assert "overall_verdict" in result

    def test_describe_path_missing_params(self) -> None:
        """Test describe_path with missing parameters."""
        topology = load_demo_topology()
        result = describe_path(topology=topology)

        assert "error" in result

    def test_describe_path_no_topology(self) -> None:
        """Test describe_path without topology or client."""
        result = describe_path(
            source_ip="10.0.0.1",
            dest_ip="10.1.0.1",
        )

        assert "error" in result
        assert "topology" in result["error"].lower() or "No topology" in result["error"]

    def test_explain_connectivity_demo_mode(self) -> None:
        """Test explain_connectivity in demo mode."""
        topology = load_demo_topology()
        result = explain_connectivity(
            source_ip="10.10.0.10",
            dest_ip="10.20.0.10",
            port=443,
            topology=topology,
        )

        assert "explanation" in result
        assert "verdict" in result
        assert "raw_result" in result

    def test_explain_connectivity_formats_nicely(self) -> None:
        """Test that explain_connectivity produces readable output."""
        topology = load_demo_topology()
        result = explain_connectivity(
            source_ip="10.10.0.10",
            dest_ip="10.1.0.10",
            port=443,
            topology=topology,
        )

        explanation = result["explanation"]
        assert "Connectivity analysis" in explanation
        assert "Verdict" in explanation
        assert "Path analysis" in explanation


class TestTgwTools:
    """Tests for Transit Gateway tools."""

    def test_list_tgw_attachments_demo_mode(self) -> None:
        """Test list_tgw_attachments in demo mode."""
        topology = load_demo_topology()
        result = list_tgw_attachments(topology=topology)

        assert "attachments" in result
        assert "count" in result
        assert result["count"] > 0
        assert result["mode"] == "demo"

    def test_tgw_route_lookup_ip(self) -> None:
        """Test TGW route lookup by IP."""
        topology = load_demo_topology()
        result = tgw_route_lookup(
            tgw_route_table_id="tgw-rtb-prod-001",
            destination_cidr="10.200.1.50",
            topology=topology,
        )

        assert "verdict" in result
        assert "matched_route" in result
        assert result["route_table_id"] == "tgw-rtb-prod-001"

    def test_tgw_route_lookup_cidr(self) -> None:
        """Test TGW route lookup by CIDR."""
        topology = load_demo_topology()
        result = tgw_route_lookup(
            tgw_route_table_id="tgw-rtb-prod-001",
            destination_cidr="10.10.0.0/24",
            topology=topology,
        )

        assert "matches" in result
        assert len(result["matches"]) > 0

    def test_tgw_route_lookup_not_found(self) -> None:
        """Test TGW route lookup with non-existent table."""
        topology = load_demo_topology()
        result = tgw_route_lookup(
            tgw_route_table_id="tgw-rtb-nonexistent",
            destination_cidr="10.0.0.1",
            topology=topology,
        )

        assert "error" in result


class TestDnsTools:
    """Tests for DNS resolution tools."""

    def test_check_dns_resolution_internal_domain(self) -> None:
        """Test DNS resolution for internal domain."""
        result = check_dns_resolution(
            domain="app.internal.corp",
            vpc_id="vpc-prod-001",
        )

        assert "domain" in result
        assert "resolution_path" in result
        assert result["mode"] == "demo"
        assert "on-premises" in result["resolution_path"].lower()
        assert "10.200.0.10" in result["resolution_path"]

    def test_check_dns_resolution_external_domain(self) -> None:
        """Test DNS resolution for external domain."""
        result = check_dns_resolution(
            domain="example.com",
            vpc_id="vpc-prod-001",
        )

        assert "domain" in result
        assert "resolution_path" in result
        assert "Route 53" in result["resolution_path"]

    def test_check_dns_resolution_with_endpoints(self) -> None:
        """Test that resolver endpoints are included."""
        result = check_dns_resolution(
            domain="db.internal.corp",
            vpc_id="vpc-shared-001",
        )

        assert "resolver_endpoints" in result
        if result.get("mode") == "demo":
            assert len(result["resolver_endpoints"]) > 0
