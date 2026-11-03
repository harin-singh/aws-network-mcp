"""Demo scenarios showing common AWS network misconfigurations.

Each scenario represents a realistic broken configuration that
the path analyzer should diagnose correctly.
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
)


@dataclass
class DemoScenario:
    """A demo scenario with a broken configuration."""

    name: str
    description: str
    expected_diagnosis: str
    source: NetworkEndpoint
    destination: NetworkEndpoint
    port: int
    protocol: Protocol
    topology_modifier: str


def _scenario_missing_tgw_propagation() -> tuple[DemoScenario, NetworkTopology]:
    """
    Scenario: Dev VPC cannot reach prod VPC because TGW route propagation
    is missing for the prod attachment in the dev route table.
    Note: Also removes the default route to ensure the missing propagation is detected.
    """
    topology = DemoTopology.build_healthy_topology()

    dev_tgw_rt = topology.tgw_route_tables[DemoTopology.TGW_RT_DEV]
    new_routes = tuple(
        r
        for r in dev_tgw_rt.routes
        if r.destination_cidr not in ("10.1.0.0/16", "0.0.0.0/0")
    )
    new_propagations = tuple(p for p in dev_tgw_rt.propagations if p != DemoTopology.TGW_ATT_PROD)
    topology.tgw_route_tables[DemoTopology.TGW_RT_DEV] = TgwRouteTableInfo(
        tgw_rt_id=dev_tgw_rt.tgw_rt_id,
        tgw_id=dev_tgw_rt.tgw_id,
        name=dev_tgw_rt.name,
        routes=new_routes,
        associations=dev_tgw_rt.associations,
        propagations=new_propagations,
    )

    scenario = DemoScenario(
        name="missing_tgw_propagation",
        description="Dev VPC cannot reach Prod VPC - TGW propagation missing",
        expected_diagnosis="No TGW route found for 10.1.0.50 - prod VPC attachment not propagating to dev route table",
        source=NetworkEndpoint(
            ip="10.2.0.100",
            vpc_id=DemoTopology.VPC_DEV,
            subnet_id=DemoTopology.SUBNET_DEV_APP,
            eni_id=DemoTopology.ENI_DEV_APP,
        ),
        destination=NetworkEndpoint(
            ip="10.1.0.50",
            vpc_id=DemoTopology.VPC_PROD,
            subnet_id=DemoTopology.SUBNET_PROD_APP,
            eni_id=DemoTopology.ENI_PROD_APP,
        ),
        port=443,
        protocol=Protocol.TCP,
        topology_modifier="removed prod propagation from dev TGW route table",
    )

    return scenario, topology


def _scenario_blackhole_route() -> tuple[DemoScenario, NetworkTopology]:
    """
    Scenario: Traffic to on-prem goes to a blackhole because the VPN
    attachment was deleted but the route remains pointing to it.
    """
    topology = DemoTopology.build_healthy_topology()

    prod_tgw_rt = topology.tgw_route_tables[DemoTopology.TGW_RT_PROD]
    new_routes: list[TgwRouteEntry] = []
    for route in prod_tgw_rt.routes:
        if route.destination_cidr == "10.200.0.0/16":
            new_routes.append(
                TgwRouteEntry(
                    destination_cidr=route.destination_cidr,
                    attachment_id=route.attachment_id,
                    resource_type=route.resource_type,
                    resource_id=route.resource_id,
                    state="blackhole",
                    route_type=route.route_type,
                )
            )
        else:
            new_routes.append(route)

    topology.tgw_route_tables[DemoTopology.TGW_RT_PROD] = TgwRouteTableInfo(
        tgw_rt_id=prod_tgw_rt.tgw_rt_id,
        tgw_id=prod_tgw_rt.tgw_id,
        name=prod_tgw_rt.name,
        routes=tuple(new_routes),
        associations=prod_tgw_rt.associations,
        propagations=prod_tgw_rt.propagations,
    )

    scenario = DemoScenario(
        name="blackhole_route",
        description="Prod VPC cannot reach on-prem - TGW route is blackholed",
        expected_diagnosis="TGW route to 10.200.0.0/16 is blackholed - VPN attachment may be deleted or detached",
        source=NetworkEndpoint(
            ip="10.1.0.100",
            vpc_id=DemoTopology.VPC_PROD,
            subnet_id=DemoTopology.SUBNET_PROD_APP,
            eni_id=DemoTopology.ENI_PROD_APP,
        ),
        destination=NetworkEndpoint(
            ip="10.200.1.50",
            is_on_prem=True,
        ),
        port=443,
        protocol=Protocol.TCP,
        topology_modifier="set on-prem route to blackhole state",
    )

    return scenario, topology


def _scenario_sg_missing_return_rule() -> tuple[DemoScenario, NetworkTopology]:
    """
    Scenario: App server cannot connect to database because the DB security
    group only allows connections from a specific security group, but the
    app is using a different one.
    """
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
        description="App cannot connect to DB - wrong security group reference",
        expected_diagnosis="DB security group only allows ingress from sg-prod-app-001, but app is using sg-wrong-app-001",
        source=NetworkEndpoint(
            ip="10.1.0.100",
            vpc_id=DemoTopology.VPC_PROD,
            subnet_id=DemoTopology.SUBNET_PROD_APP,
            eni_id=DemoTopology.ENI_PROD_APP,
        ),
        destination=NetworkEndpoint(
            ip="10.1.1.50",
            vpc_id=DemoTopology.VPC_PROD,
            subnet_id=DemoTopology.SUBNET_PROD_DB,
            eni_id=DemoTopology.ENI_PROD_DB,
        ),
        port=5432,
        protocol=Protocol.TCP,
        topology_modifier="changed app server to use different security group",
    )

    return scenario, topology


def _scenario_sg_wrong_port() -> tuple[DemoScenario, NetworkTopology]:
    """
    Scenario: Service connection fails because security group allows
    port 80 but application is trying to connect on port 8080.
    """
    topology = DemoTopology.build_healthy_topology()

    wrong_port_sg = SecurityGroupInfo(
        sg_id=DemoTopology.SG_PROD_APP,
        name="prod-app-sg",
        vpc_id=DemoTopology.VPC_PROD,
        rules=(
            SecurityGroupRule("ingress", "6", 80, 80, "10.0.0.0/8", description="HTTP only"),
            SecurityGroupRule("ingress", "6", 22, 22, "10.3.0.0/16", description="SSH from shared"),
            SecurityGroupRule(
                "egress", "-1", None, None, "0.0.0.0/0", description="Allow all outbound"
            ),
        ),
    )
    topology.security_groups[DemoTopology.SG_PROD_APP] = wrong_port_sg

    scenario = DemoScenario(
        name="sg_wrong_port",
        description="HTTPS connection fails - security group only allows HTTP",
        expected_diagnosis="Security group allows port 80 but connection attempt is on port 443",
        source=NetworkEndpoint(
            ip="10.2.0.100",
            vpc_id=DemoTopology.VPC_DEV,
            subnet_id=DemoTopology.SUBNET_DEV_APP,
            eni_id=DemoTopology.ENI_DEV_APP,
        ),
        destination=NetworkEndpoint(
            ip="10.1.0.100",
            vpc_id=DemoTopology.VPC_PROD,
            subnet_id=DemoTopology.SUBNET_PROD_APP,
            eni_id=DemoTopology.ENI_PROD_APP,
        ),
        port=443,
        protocol=Protocol.TCP,
        topology_modifier="changed prod-app-sg to only allow port 80",
    )

    return scenario, topology


def _scenario_nacl_blocking_ephemeral() -> tuple[DemoScenario, NetworkTopology]:
    """
    Scenario: Connection hangs because NACL doesn't allow return traffic
    on ephemeral ports. NACLs are stateless!

    The source (dev) NACL only allows specific ports, not ephemeral return traffic.
    """
    topology = DemoTopology.build_healthy_topology()

    strict_nacl = NaclInfo(
        nacl_id=DemoTopology.NACL_DEV,
        vpc_id=DemoTopology.VPC_DEV,
        name="dev-nacl-strict",
        rules=(
            NaclRule(100, "ingress", "6", 443, 443, "10.0.0.0/8", "allow"),
            NaclRule(110, "ingress", "6", 22, 22, "10.0.0.0/8", "allow"),
            NaclRule(32767, "ingress", "-1", None, None, "0.0.0.0/0", "deny"),
            NaclRule(100, "egress", "-1", None, None, "0.0.0.0/0", "allow"),
            NaclRule(32767, "egress", "-1", None, None, "0.0.0.0/0", "deny"),
        ),
        subnet_associations=(DemoTopology.SUBNET_DEV_APP,),
    )
    topology.nacls[DemoTopology.NACL_DEV] = strict_nacl

    scenario = DemoScenario(
        name="nacl_blocking_ephemeral",
        description="Connections from dev hang - NACL blocks return traffic",
        expected_diagnosis="NACL is stateless - allows egress but no rule for ephemeral return ports 1024-65535",
        source=NetworkEndpoint(
            ip="10.2.0.100",
            vpc_id=DemoTopology.VPC_DEV,
            subnet_id=DemoTopology.SUBNET_DEV_APP,
            eni_id=DemoTopology.ENI_DEV_APP,
        ),
        destination=NetworkEndpoint(
            ip="10.1.0.100",
            vpc_id=DemoTopology.VPC_PROD,
            subnet_id=DemoTopology.SUBNET_PROD_APP,
            eni_id=DemoTopology.ENI_PROD_APP,
        ),
        port=443,
        protocol=Protocol.TCP,
        topology_modifier="removed ephemeral port ingress rule from dev NACL",
    )

    return scenario, topology


def _scenario_asymmetric_routing() -> tuple[DemoScenario, NetworkTopology]:
    """
    Scenario: Traffic from shared-services to dev works, but return traffic
    goes through inspection VPC, causing asymmetric routing issues.
    """
    topology = DemoTopology.build_healthy_topology()

    dev_tgw_rt = topology.tgw_route_tables[DemoTopology.TGW_RT_DEV]
    new_routes = tuple(
        TgwRouteEntry(
            destination_cidr=r.destination_cidr,
            attachment_id=DemoTopology.TGW_ATT_INSPECTION
            if r.destination_cidr == "10.3.0.0/16"
            else r.attachment_id,
            resource_type="vpc" if r.destination_cidr == "10.3.0.0/16" else r.resource_type,
            resource_id=DemoTopology.VPC_INSPECTION
            if r.destination_cidr == "10.3.0.0/16"
            else r.resource_id,
            state=r.state,
            route_type="static" if r.destination_cidr == "10.3.0.0/16" else r.route_type,
        )
        for r in dev_tgw_rt.routes
    )
    topology.tgw_route_tables[DemoTopology.TGW_RT_DEV] = TgwRouteTableInfo(
        tgw_rt_id=dev_tgw_rt.tgw_rt_id,
        tgw_id=dev_tgw_rt.tgw_id,
        name=dev_tgw_rt.name,
        routes=new_routes,
        associations=dev_tgw_rt.associations,
        propagations=dev_tgw_rt.propagations,
    )

    scenario = DemoScenario(
        name="asymmetric_routing",
        description="Dev to shared-services has asymmetric routing through inspection VPC",
        expected_diagnosis="Return traffic routes through inspection VPC instead of direct path - may cause connection issues with stateful firewalls",
        source=NetworkEndpoint(
            ip="10.2.0.100",
            vpc_id=DemoTopology.VPC_DEV,
            subnet_id=DemoTopology.SUBNET_DEV_APP,
            eni_id=DemoTopology.ENI_DEV_APP,
        ),
        destination=NetworkEndpoint(
            ip="10.3.0.50",
            vpc_id=DemoTopology.VPC_SHARED,
            subnet_id=DemoTopology.SUBNET_SHARED_DNS,
            eni_id=DemoTopology.ENI_SHARED_DNS,
        ),
        port=53,
        protocol=Protocol.UDP,
        topology_modifier="dev-to-shared route goes through inspection VPC",
    )

    return scenario, topology


DEMO_SCENARIOS: dict[str, tuple[DemoScenario, NetworkTopology]] = {
    "missing_tgw_propagation": _scenario_missing_tgw_propagation(),
    "blackhole_route": _scenario_blackhole_route(),
    "sg_missing_return_rule": _scenario_sg_missing_return_rule(),
    "sg_wrong_port": _scenario_sg_wrong_port(),
    "nacl_blocking_ephemeral": _scenario_nacl_blocking_ephemeral(),
}

INFORMATIONAL_SCENARIOS: dict[str, tuple[DemoScenario, NetworkTopology]] = {
    "asymmetric_routing": _scenario_asymmetric_routing(),
}


def get_scenario(name: str) -> tuple[DemoScenario, NetworkTopology] | None:
    """Get a scenario by name."""
    return DEMO_SCENARIOS.get(name)


def list_scenarios() -> list[str]:
    """List all available scenario names."""
    return list(DEMO_SCENARIOS.keys())
