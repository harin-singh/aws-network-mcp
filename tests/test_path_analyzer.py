"""Tests for path analysis orchestration."""

from __future__ import annotations

from aws_network_mcp.analysis.path_analyzer import NetworkTopology, PathAnalyzer
from aws_network_mcp.models import (
    NetworkEndpoint,
    Protocol,
    Verdict,
)


class TestPathAnalyzer:
    """Tests for PathAnalyzer class."""

    def test_analyze_path_allow(
        self,
        simple_topology: NetworkTopology,
        source_endpoint: NetworkEndpoint,
        dest_endpoint: NetworkEndpoint,
    ) -> None:
        """Test path analysis that should be allowed."""
        analyzer = PathAnalyzer(simple_topology)
        result = analyzer.analyze_path(source_endpoint, dest_endpoint, 443, Protocol.TCP)

        assert result.overall_verdict == Verdict.ALLOW
        assert len(result.hops) > 0
        assert result.blocking_hop is None

    def test_analyze_path_sg_block(
        self,
        simple_topology: NetworkTopology,
        source_endpoint: NetworkEndpoint,
        dest_endpoint: NetworkEndpoint,
    ) -> None:
        """Test path analysis blocked by security group."""
        analyzer = PathAnalyzer(simple_topology)
        result = analyzer.analyze_path(source_endpoint, dest_endpoint, 22, Protocol.TCP)

        assert result.overall_verdict == Verdict.DENY
        assert result.blocking_hop is not None
        assert result.blocking_hop.hop_type == "security_group"

    def test_analyze_path_cross_vpc(self, simple_topology: NetworkTopology) -> None:
        """Test cross-VPC path analysis via TGW."""
        analyzer = PathAnalyzer(simple_topology)

        source = NetworkEndpoint(
            ip="10.0.0.100",
            vpc_id="vpc-001",
            subnet_id="subnet-001",
            eni_id="eni-001",
        )
        dest = NetworkEndpoint(
            ip="10.1.0.100",
            vpc_id="vpc-002",
            subnet_id="subnet-002",
            eni_id="eni-002",
        )

        result = analyzer.analyze_path(source, dest, 443, Protocol.TCP)

        tgw_hops = [h for h in result.hops if h.hop_type == "transit_gateway"]
        assert len(tgw_hops) == 1
        assert result.overall_verdict == Verdict.ALLOW

    def test_analyze_path_missing_source_subnet(self) -> None:
        """Test path analysis with missing source subnet."""
        from aws_network_mcp.fixtures.topology import load_demo_topology

        topology = load_demo_topology()
        analyzer = PathAnalyzer(topology)

        source = NetworkEndpoint(ip="10.0.0.100")
        dest = NetworkEndpoint(ip="10.1.0.100")

        result = analyzer.analyze_path(source, dest, 443, Protocol.TCP)
        assert result.overall_verdict == Verdict.UNKNOWN

    def test_analyze_path_includes_all_hop_types(
        self,
        simple_topology: NetworkTopology,
        source_endpoint: NetworkEndpoint,
        dest_endpoint: NetworkEndpoint,
    ) -> None:
        """Test that path analysis includes all expected hop types."""
        analyzer = PathAnalyzer(simple_topology)
        result = analyzer.analyze_path(source_endpoint, dest_endpoint, 443, Protocol.TCP)

        hop_types = {h.hop_type for h in result.hops}
        assert "security_group" in hop_types
        assert "nacl" in hop_types
        assert "route_table" in hop_types


class TestPathAnalyzerScenarios:
    """Test path analyzer against demo scenarios."""

    def test_scenario_missing_tgw_propagation(self) -> None:
        """Test detection of missing TGW route propagation."""
        from aws_network_mcp.fixtures.scenarios import get_scenario

        result = get_scenario("missing_tgw_propagation")
        assert result is not None
        scenario, topology = result

        analyzer = PathAnalyzer(topology)
        analysis = analyzer.analyze_path(
            scenario.source, scenario.destination, scenario.port, scenario.protocol
        )

        assert analysis.overall_verdict == Verdict.DENY
        assert analysis.blocking_hop is not None
        assert analysis.blocking_hop.hop_type == "transit_gateway"

    def test_scenario_blackhole_route(self) -> None:
        """Test detection of blackhole route."""
        from aws_network_mcp.fixtures.scenarios import get_scenario

        result = get_scenario("blackhole_route")
        assert result is not None
        scenario, topology = result

        analyzer = PathAnalyzer(topology)
        analysis = analyzer.analyze_path(
            scenario.source, scenario.destination, scenario.port, scenario.protocol
        )

        assert analysis.overall_verdict == Verdict.BLACKHOLE
        assert analysis.blocking_hop is not None
        assert "blackhole" in analysis.summary.lower()

    def test_scenario_sg_missing_return_rule(self) -> None:
        """Test detection of wrong security group reference."""
        from aws_network_mcp.fixtures.scenarios import get_scenario

        result = get_scenario("sg_missing_return_rule")
        assert result is not None
        scenario, topology = result

        analyzer = PathAnalyzer(topology)
        analysis = analyzer.analyze_path(
            scenario.source, scenario.destination, scenario.port, scenario.protocol
        )

        assert analysis.overall_verdict == Verdict.DENY
        assert analysis.blocking_hop is not None
        assert analysis.blocking_hop.hop_type == "security_group"

    def test_scenario_sg_wrong_port(self) -> None:
        """Test detection of wrong port in security group."""
        from aws_network_mcp.fixtures.scenarios import get_scenario

        result = get_scenario("sg_wrong_port")
        assert result is not None
        scenario, topology = result

        analyzer = PathAnalyzer(topology)
        analysis = analyzer.analyze_path(
            scenario.source, scenario.destination, scenario.port, scenario.protocol
        )

        assert analysis.overall_verdict == Verdict.DENY
        assert analysis.blocking_hop is not None
        assert analysis.blocking_hop.hop_type == "security_group"

    def test_scenario_nacl_blocking_ephemeral(self) -> None:
        """Test detection of NACL blocking ephemeral ports."""
        from aws_network_mcp.fixtures.scenarios import get_scenario

        result = get_scenario("nacl_blocking_ephemeral")
        assert result is not None
        scenario, topology = result

        analyzer = PathAnalyzer(topology)
        analysis = analyzer.analyze_path(
            scenario.source, scenario.destination, scenario.port, scenario.protocol
        )

        assert analysis.overall_verdict == Verdict.DENY
        assert analysis.blocking_hop is not None
        assert "nacl" in analysis.blocking_hop.hop_type.lower()

    def test_all_scenarios_detect_issues(self) -> None:
        """Test that all demo scenarios are correctly identified as broken."""
        from aws_network_mcp.fixtures.scenarios import DEMO_SCENARIOS

        for scenario_name, (scenario, topology) in DEMO_SCENARIOS.items():
            analyzer = PathAnalyzer(topology)
            analysis = analyzer.analyze_path(
                scenario.source, scenario.destination, scenario.port, scenario.protocol
            )

            assert analysis.overall_verdict != Verdict.ALLOW, (
                f"Scenario {scenario_name} should not be ALLOW"
            )
