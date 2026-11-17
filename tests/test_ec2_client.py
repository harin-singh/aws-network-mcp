"""Tests for the live AWS client layer using moto and botocore Stubber."""

from __future__ import annotations

from typing import Any

import boto3
from botocore.stub import Stubber
from moto import mock_aws

from aws_network_mcp.aws_client.ec2_client import EC2Client
from aws_network_mcp.aws_client.logs_client import CloudWatchLogsClient


@mock_aws
def test_get_instance_and_eni_network_info() -> None:
    """Parse instance and ENI details from moto-backed EC2."""
    region = "us-east-1"
    raw = boto3.client("ec2", region_name=region)
    vpc = raw.create_vpc(CidrBlock="10.10.0.0/24")["Vpc"]
    subnet = raw.create_subnet(VpcId=vpc["VpcId"], CidrBlock="10.10.0.0/24")["Subnet"]
    sg = raw.create_security_group(GroupName="prod-app", Description="test", VpcId=vpc["VpcId"])
    image = raw.describe_images()["Images"][0]["ImageId"]
    instance = raw.run_instances(
        ImageId=image,
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet["SubnetId"],
        SecurityGroupIds=[sg["GroupId"]],
    )["Instances"][0]

    client = EC2Client(region=region)
    endpoint = client.get_instance_network_info(instance["InstanceId"])
    assert endpoint is not None
    assert endpoint.vpc_id == vpc["VpcId"]
    assert endpoint.subnet_id == subnet["SubnetId"]
    assert endpoint.instance_id == instance["InstanceId"]
    assert endpoint.eni_id
    assert endpoint.ip

    eni = client.get_eni_network_info(endpoint.eni_id)
    assert eni is not None
    assert eni.ip == endpoint.ip
    assert eni.vpc_id == vpc["VpcId"]

    by_ip = client.get_ip_network_info(endpoint.ip, vpc["VpcId"])
    assert by_ip is not None
    assert by_ip.eni_id == endpoint.eni_id

    groups = client.get_eni_security_groups(endpoint.eni_id)
    assert sg["GroupId"] in groups


@mock_aws
def test_get_route_table_security_group_and_nacl() -> None:
    """Parse route tables, security groups, and NACLs from moto."""
    region = "us-east-1"
    raw = boto3.client("ec2", region_name=region)
    vpc = raw.create_vpc(CidrBlock="10.10.0.0/24")["Vpc"]
    subnet = raw.create_subnet(VpcId=vpc["VpcId"], CidrBlock="10.10.0.0/24")["Subnet"]
    raw.create_tags(Resources=[vpc["VpcId"]], Tags=[{"Key": "Name", "Value": "prod"}])

    tables = raw.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}])[
        "RouteTables"
    ]
    rt_id = tables[0]["RouteTableId"]

    sg = raw.create_security_group(GroupName="web", Description="web", VpcId=vpc["VpcId"])
    raw.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "10.0.0.0/8", "Description": "HTTPS"}],
            }
        ],
    )

    client = EC2Client(region=region)
    rt = client.get_route_table(rt_id)
    assert rt is not None
    assert rt.vpc_id == vpc["VpcId"]
    assert any(route.destination_cidr.startswith("10.10.0.0") for route in rt.routes)

    associated = client.get_subnet_route_table(subnet["SubnetId"])
    assert associated is not None

    sg_info = client.get_security_group(sg["GroupId"])
    assert sg_info is not None
    assert sg_info.name == "web"
    ingress = [r for r in sg_info.rules if r.direction == "ingress"]
    assert any(r.from_port == 443 and r.cidr == "10.0.0.0/8" for r in ingress)

    nacl = client.get_subnet_nacl(subnet["SubnetId"])
    assert nacl is not None
    assert nacl.vpc_id == vpc["VpcId"]
    assert nacl.rules


def test_get_tgw_route_table_with_stubber() -> None:
    """Parse TGW route table search results via botocore Stubber."""
    session = boto3.Session(region_name="us-east-1")
    raw = session.client("ec2")
    stubber = Stubber(raw)
    stubber.add_response(
        "describe_transit_gateway_route_tables",
        {
            "TransitGatewayRouteTables": [
                {
                    "TransitGatewayRouteTableId": "tgw-rtb-prod-001",
                    "TransitGatewayId": "tgw-demo-001",
                    "Tags": [{"Key": "Name", "Value": "prod-tgw-rt"}],
                }
            ]
        },
        {"TransitGatewayRouteTableIds": ["tgw-rtb-prod-001"]},
    )
    stubber.add_response(
        "search_transit_gateway_routes",
        {
            "Routes": [
                {
                    "DestinationCidrBlock": "10.20.0.0/24",
                    "State": "blackhole",
                    "Type": "static",
                    "TransitGatewayAttachments": [],
                },
                {
                    "DestinationCidrBlock": "10.200.0.0/16",
                    "State": "active",
                    "Type": "propagated",
                    "TransitGatewayAttachments": [
                        {
                            "TransitGatewayAttachmentId": "tgw-attach-vpn-005",
                            "ResourceType": "vpn",
                            "ResourceId": "vpn-demo-001",
                        }
                    ],
                },
            ]
        },
        {
            "TransitGatewayRouteTableId": "tgw-rtb-prod-001",
            "Filters": [{"Name": "state", "Values": ["active", "blackhole"]}],
        },
    )
    stubber.add_response(
        "get_transit_gateway_route_table_associations",
        {"Associations": [{"TransitGatewayAttachmentId": "tgw-attach-prod-001"}]},
        {"TransitGatewayRouteTableId": "tgw-rtb-prod-001"},
    )
    stubber.add_response(
        "get_transit_gateway_route_table_propagations",
        {"TransitGatewayRouteTablePropagations": []},
        {"TransitGatewayRouteTableId": "tgw-rtb-prod-001"},
    )

    with stubber:
        client = EC2Client(region="us-east-1", session=session, client=raw)
        table = client.get_tgw_route_table("tgw-rtb-prod-001")

    assert table is not None
    assert table.name == "prod-tgw-rt"
    assert table.associations == ("tgw-attach-prod-001",)
    blackhole = next(r for r in table.routes if r.destination_cidr == "10.20.0.0/24")
    assert blackhole.state == "blackhole"
    assert blackhole.route_type == "static"
    bgp = next(r for r in table.routes if r.destination_cidr == "10.200.0.0/16")
    assert bgp.route_type == "propagated"
    assert bgp.attachment_id == "tgw-attach-vpn-005"


def test_get_reachability_analysis_with_stubber() -> None:
    """Parse Reachability Analyzer output via Stubber."""
    session = boto3.Session(region_name="us-east-1")
    raw = session.client("ec2")
    stubber = Stubber(raw)
    stubber.add_response(
        "describe_network_insights_analyses",
        {
            "NetworkInsightsAnalyses": [
                {
                    "NetworkInsightsAnalysisId": "nia-001",
                    "NetworkInsightsPathId": "nip-001",
                    "Status": "succeeded",
                    "NetworkPathFound": False,
                    "Explanations": [
                        {
                            "ExplanationCode": "SG_MISSING",
                            "Component": {"Id": "sg-001", "Name": "prod-app-sg"},
                        }
                    ],
                    "ForwardPathComponents": [
                        {"SequenceNumber": 1, "Component": {"Id": "eni-001", "Name": "src"}}
                    ],
                }
            ]
        },
        {"NetworkInsightsAnalysisIds": ["nia-001"]},
    )

    with stubber:
        client = EC2Client(region="us-east-1", session=session, client=raw)
        result = client.get_reachability_analysis("nia-001")

    assert result.status == "succeeded"
    assert result.reachable is False
    assert result.explanations[0].startswith("SG_MISSING")
    assert "src" in result.forward_path[0]


def test_query_flow_logs_with_stubber() -> None:
    """Parse CloudWatch Logs Insights rows via Stubber."""
    session = boto3.Session(region_name="us-east-1")
    raw = session.client("logs")
    stubber = Stubber(raw)
    start_kwargs: dict[str, Any] = {
        "logGroupName": "/vpc/flow",
        "startTime": 1000,
        "endTime": 2000,
        "queryString": (
            "fields @timestamp, srcAddr, dstAddr, srcPort, dstPort, protocol, action, "
            "logStatus, interfaceId\n"
            "| filter srcAddr = '10.10.0.10' and dstAddr = '10.200.1.50' "
            "and dstPort = 443 and action = 'ACCEPT'\n"
            "| sort @timestamp desc\n"
            "| limit 10"
        ),
    }
    stubber.add_response("start_query", {"queryId": "q-1"}, start_kwargs)
    stubber.add_response(
        "get_query_results",
        {
            "status": "Complete",
            "results": [
                [
                    {"field": "@timestamp", "value": "2026-01-01T00:00:00Z"},
                    {"field": "srcAddr", "value": "10.10.0.10"},
                    {"field": "dstAddr", "value": "10.200.1.50"},
                    {"field": "srcPort", "value": "51234"},
                    {"field": "dstPort", "value": "443"},
                    {"field": "protocol", "value": "6"},
                    {"field": "action", "value": "ACCEPT"},
                    {"field": "logStatus", "value": "OK"},
                    {"field": "interfaceId", "value": "eni-prod-app-001"},
                ]
            ],
        },
        {"queryId": "q-1"},
    )

    with stubber:
        client = CloudWatchLogsClient(region="us-east-1", session=session, client=raw)
        entries = client.query_flow_logs(
            log_group="/vpc/flow",
            src_addr="10.10.0.10",
            dst_addr="10.200.1.50",
            dst_port=443,
            action="ACCEPT",
            start_time_ms=1_000_000,
            end_time_ms=2_000_000,
            limit=10,
        )

    assert len(entries) == 1
    assert entries[0].src_addr == "10.10.0.10"
    assert entries[0].dst_addr == "10.200.1.50"
    assert entries[0].action == "ACCEPT"
    assert entries[0].dst_port == 443
