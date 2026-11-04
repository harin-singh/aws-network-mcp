"""Demo scenarios for hybrid path analysis.

Includes the original TGW-propagation case plus landing-zone segmentation
from https://github.com/harin-singh/aws-hybrid-network-landing-zone
"""

from __future__ import annotations

from dataclasses import dataclass

from aws_network_mcp.analysis.path_analyzer import NetworkTopology
from aws_network_mcp.fixtures.topology import DemoTopology
from aws_network_mcp.models import (
    NaclInfo,
    NaclRule,
    NetworkEndpoint,
    Protocol,
    SecurityGroupInfo,
    SecurityGroupRule,
    TgwRouteEntry,
    TgwRouteTableInfo,
    Verdict,
)


@dataclass
class DemoScenario:
    """A demo scenario with an expected path-analysis verdict."""

    name: str
    description: str
    expected_diagnosis: str
    source: NetworkEndpoint
    destination: NetworkEndpoint
    port: int
    protocol: Protocol
    topology_modifier: str
    expected_verdict: Verdict
    expected_blocking_hop_type: str | None = None
    expect_inspection_bypass: bool = False


def _copy_replace_tgw_rt(
    topology: NetworkTopology,
    rt_id: str,
    routes: tuple[TgwRouteEntry, ...],
    propagations: tuple[str, ...],
) -> None:
    existing = topology.tgw_route_tables[rt_id]
    topology.tgw_route_tables[rt_id] = TgwRouteTableInfo(
        tgw_rt_id=existing.tgw_rt_id,
        tgw_id=existing.tgw_id,
        name=existing.name,
        routes=routes,
        associations=existing.associations,
        propagations=propagations,
    )


def _scenario_missing_tgw_propagation() -> tuple[DemoScenario, NetworkTopology]:
    """Inspection RT is missing the BGP-learned on-prem prefix."""
    topology = DemoTopology.build_healthy_topology()
    insp = topology.tgw_route_tables[DemoTopology.TGW_RT_INSPECTION]
    new_routes = tuple(
        r
        for r in insp.routes
        if r.destination_cidr not in (DemoTopology.CIDR_ONPREM, DemoTopology.CIDR_ONPREM_VPC)
    )
    new_props = tuple(p for p in insp.propagations if p != DemoTopology.TGW_ATT_VPN)
    _copy_replace_tgw_rt(topology, DemoTopology.TGW_RT_INSPECTION, new_routes, new_props)

    scenario = DemoScenario(
        name="missing_tgw_propagation",
        description="Prod cannot reach on-prem — VPN prefix not propagated to the inspection RT",
        expected_diagnosis=(
            "Inspection TGW route table has no route for 10.200.1.50 because the VPN "
            "attachment is not propagating"
        ),
        source=topology.known_endpoints[DemoTopology.IP_PROD_APP],
        destination=topology.known_endpoints[DemoTopology.IP_ONPREM],
        port=443,
        protocol=Protocol.TCP,
        topology_modifier="removed VPN propagation and on-prem routes from inspection TGW RT",
        expected_verdict=Verdict.DENY,
        expected_blocking_hop_type="transit_gateway",
    )
    return scenario, topology


def _scenario_blackhole_route() -> tuple[DemoScenario, NetworkTopology]:
    """On-prem route on the inspection RT is blackholed (VPN attachment gone)."""
    topology = DemoTopology.build_healthy_topology()
    insp = topology.tgw_route_tables[DemoTopology.TGW_RT_INSPECTION]
    new_routes = tuple(
        TgwRouteEntry(
            r.destination_cidr,
            r.attachment_id,
            r.resource_type,
            r.resource_id,
            "blackhole" if r.destination_cidr == DemoTopology.CIDR_ONPREM else r.state,
            r.route_type,
        )
        for r in insp.routes
    )
    _copy_replace_tgw_rt(topology, DemoTopology.TGW_RT_INSPECTION, new_routes, insp.propagations)

    scenario = DemoScenario(
        name="blackhole_route",
        description="Prod cannot reach on-prem — inspection RT blackholes the BGP prefix",
        expected_diagnosis="TGW route to 10.200.0.0/16 is blackholed on the inspection route table",
        source=topology.known_endpoints[DemoTopology.IP_PROD_APP],
        destination=topology.known_endpoints[DemoTopology.IP_ONPREM],
        port=443,
        protocol=Protocol.TCP,
        topology_modifier="set 10.200.0.0/16 to blackhole on inspection TGW RT",
        expected_verdict=Verdict.BLACKHOLE,
        expected_blocking_hop_type="transit_gateway",
    )
    return scenario, topology


def _scenario_prod_nonprod_blocked() -> tuple[DemoScenario, NetworkTopology]:
    topology = DemoTopology.build_healthy_topology()
    scenario = DemoScenario(
        name="prod_nonprod_blocked",
        description="Prod to nonprod is dropped by a TGW blackhole; firewall would also drop",
        expected_diagnosis=(
            "Prod TGW RT has a static blackhole for 10.20.0.0/24; Network Firewall "
            "sid:1000001 would also drop the flow"
        ),
        source=topology.known_endpoints[DemoTopology.IP_PROD_APP],
        destination=topology.known_endpoints[DemoTopology.IP_NONPROD_APP],
        port=443,
        protocol=Protocol.TCP,
        topology_modifier="none (landing-zone segmentation)",
        expected_verdict=Verdict.BLACKHOLE,
        expected_blocking_hop_type="transit_gateway",
    )
    return scenario, topology


def _scenario_nonprod_onprem_blocked() -> tuple[DemoScenario, NetworkTopology]:
    topology = DemoTopology.build_healthy_topology()
    scenario = DemoScenario(
        name="nonprod_onprem_blocked",
        description="Nonprod to on-prem is dropped by a TGW blackhole; firewall would also drop",
        expected_diagnosis=(
            "Nonprod TGW RT blackholes 10.200.0.0/16; Network Firewall sid:1000003 "
            "would also drop nonprod to on-prem"
        ),
        source=topology.known_endpoints[DemoTopology.IP_NONPROD_APP],
        destination=topology.known_endpoints[DemoTopology.IP_ONPREM],
        port=443,
        protocol=Protocol.TCP,
        topology_modifier="none (landing-zone segmentation)",
        expected_verdict=Verdict.BLACKHOLE,
        expected_blocking_hop_type="transit_gateway",
    )
    return scenario, topology


def _scenario_spoke_onprem_via_inspection() -> tuple[DemoScenario, NetworkTopology]:
    topology = DemoTopology.build_healthy_topology()
    scenario = DemoScenario(
        name="spoke_onprem_via_inspection",
        description="Prod reaches on-prem via inspection (static to NFW, then BGP-learned VPN route)",
        expected_diagnosis=(
            "Prod RT 10.200.0.0/16 static via inspection; firewall sid:2000005 pass; "
            "inspection RT 10.200.0.0/16 propagated to the VPN attachment"
        ),
        source=topology.known_endpoints[DemoTopology.IP_PROD_APP],
        destination=topology.known_endpoints[DemoTopology.IP_ONPREM],
        port=443,
        protocol=Protocol.TCP,
        topology_modifier="none (allowed landing-zone path)",
        expected_verdict=Verdict.ALLOW,
    )
    return scenario, topology


def _scenario_inspection_bypass() -> tuple[DemoScenario, NetworkTopology]:
    """Nonprod attachment is propagated onto the prod RT, skipping inspection."""
    topology = DemoTopology.build_healthy_topology()
    prod_rt = topology.tgw_route_tables[DemoTopology.TGW_RT_PROD]
    new_routes = tuple(
        r for r in prod_rt.routes if r.destination_cidr != DemoTopology.CIDR_NONPROD
    ) + (
        TgwRouteEntry(
            DemoTopology.CIDR_NONPROD,
            DemoTopology.TGW_ATT_NONPROD,
            "vpc",
            DemoTopology.VPC_NONPROD,
            "active",
            "propagated",
        ),
    )
    _copy_replace_tgw_rt(
        topology,
        DemoTopology.TGW_RT_PROD,
        new_routes,
        (DemoTopology.TGW_ATT_NONPROD,),
    )

    scenario = DemoScenario(
        name="inspection_bypass_propagation",
        description="Nonprod prefix is propagated onto the prod RT, bypassing inspection",
        expected_diagnosis=(
            "More-specific propagated route 10.20.0.0/24 -> tgw-attach-nonprod-002 "
            "skips the inspection attachment"
        ),
        source=topology.known_endpoints[DemoTopology.IP_PROD_APP],
        destination=topology.known_endpoints[DemoTopology.IP_NONPROD_APP],
        port=443,
        protocol=Protocol.TCP,
        topology_modifier="replaced prod blackhole with a propagated route to the nonprod attachment",
        expected_verdict=Verdict.ALLOW,
        expect_inspection_bypass=True,
    )
    return scenario, topology


def _scenario_sg_missing_return_rule() -> tuple[DemoScenario, NetworkTopology]:
    topology = DemoTopology.build_healthy_topology()
    wrong_sg = SecurityGroupInfo(
        sg_id="sg-wrong-app-001",
        name="wrong-app-sg",
        vpc_id=DemoTopology.VPC_PROD,
        rules=(
            SecurityGroupRule("ingress", "6", 443, 443, "10.0.0.0/8", description="HTTPS"),
            SecurityGroupRule(
                "egress", "-1", None, None, "0.0.0.0/0", description="Allow all outbound"
            ),
        ),
    )
    topology.security_groups["sg-wrong-app-001"] = wrong_sg
    topology.eni_to_security_groups[DemoTopology.ENI_PROD_APP] = ["sg-wrong-app-001"]

    scenario = DemoScenario(
        name="sg_missing_return_rule",
        description="App cannot connect to DB — wrong security group reference",
        expected_diagnosis="DB SG only allows ingress from sg-prod-app-001, but the app uses sg-wrong-app-001",
        source=topology.known_endpoints[DemoTopology.IP_PROD_APP],
        destination=topology.known_endpoints[DemoTopology.IP_PROD_DB],
        port=5432,
        protocol=Protocol.TCP,
        topology_modifier="changed app ENI to a security group the DB SG does not reference",
        expected_verdict=Verdict.DENY,
        expected_blocking_hop_type="security_group",
    )
    return scenario, topology


def _scenario_sg_wrong_port() -> tuple[DemoScenario, NetworkTopology]:
    topology = DemoTopology.build_healthy_topology()
    topology.security_groups[DemoTopology.SG_SHARED_DNS] = SecurityGroupInfo(
        sg_id=DemoTopology.SG_SHARED_DNS,
        name="shared-dns-sg",
        vpc_id=DemoTopology.VPC_SHARED,
        rules=(
            SecurityGroupRule("ingress", "6", 80, 80, "10.0.0.0/8", description="HTTP only"),
            SecurityGroupRule(
                "egress", "-1", None, None, "0.0.0.0/0", description="Allow all outbound"
            ),
        ),
    )

    scenario = DemoScenario(
        name="sg_wrong_port",
        description="Prod to shared HTTPS fails — destination SG only allows HTTP",
        expected_diagnosis="Shared SG allows port 80 but the connection is on port 443",
        source=topology.known_endpoints[DemoTopology.IP_PROD_APP],
        destination=topology.known_endpoints[DemoTopology.IP_SHARED_DNS],
        port=443,
        protocol=Protocol.TCP,
        topology_modifier="changed shared-dns-sg to only allow port 80",
        expected_verdict=Verdict.DENY,
        expected_blocking_hop_type="security_group",
    )
    return scenario, topology


def _scenario_nacl_blocking_ephemeral() -> tuple[DemoScenario, NetworkTopology]:
    topology = DemoTopology.build_healthy_topology()
    topology.nacls[DemoTopology.NACL_PROD] = NaclInfo(
        nacl_id=DemoTopology.NACL_PROD,
        vpc_id=DemoTopology.VPC_PROD,
        name="prod-nacl-strict",
        rules=(
            NaclRule(100, "ingress", "6", 443, 443, "10.0.0.0/8", "allow"),
            NaclRule(110, "ingress", "6", 22, 22, "10.0.0.0/8", "allow"),
            NaclRule(32767, "ingress", "-1", None, None, "0.0.0.0/0", "deny"),
            NaclRule(100, "egress", "-1", None, None, "0.0.0.0/0", "allow"),
            NaclRule(32767, "egress", "-1", None, None, "0.0.0.0/0", "deny"),
        ),
        subnet_associations=(DemoTopology.SUBNET_PROD_APP, DemoTopology.SUBNET_PROD_DB),
    )

    scenario = DemoScenario(
        name="nacl_blocking_ephemeral",
        description="Prod to shared hangs — source NACL blocks ephemeral return traffic",
        expected_diagnosis="NACL is stateless — no rule for ephemeral return ports 1024-65535",
        source=topology.known_endpoints[DemoTopology.IP_PROD_APP],
        destination=topology.known_endpoints[DemoTopology.IP_SHARED_DNS],
        port=443,
        protocol=Protocol.TCP,
        topology_modifier="removed ephemeral port ingress rule from prod NACL",
        expected_verdict=Verdict.DENY,
        expected_blocking_hop_type="nacl_return",
    )
    return scenario, topology


DEMO_SCENARIOS: dict[str, tuple[DemoScenario, NetworkTopology]] = {
    "missing_tgw_propagation": _scenario_missing_tgw_propagation(),
    "blackhole_route": _scenario_blackhole_route(),
    "prod_nonprod_blocked": _scenario_prod_nonprod_blocked(),
    "nonprod_onprem_blocked": _scenario_nonprod_onprem_blocked(),
    "spoke_onprem_via_inspection": _scenario_spoke_onprem_via_inspection(),
    "inspection_bypass_propagation": _scenario_inspection_bypass(),
    "sg_missing_return_rule": _scenario_sg_missing_return_rule(),
    "sg_wrong_port": _scenario_sg_wrong_port(),
    "nacl_blocking_ephemeral": _scenario_nacl_blocking_ephemeral(),
}


def get_scenario(name: str) -> tuple[DemoScenario, NetworkTopology] | None:
    """Get a scenario by name."""
    return DEMO_SCENARIOS.get(name)


def list_scenarios() -> list[str]:
    """List all available scenario names."""
    return list(DEMO_SCENARIOS.keys())
