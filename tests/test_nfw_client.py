"""Stubber tests for Network Firewall policy import."""

from __future__ import annotations

import boto3
from botocore.stub import Stubber

from aws_network_mcp.analysis.firewall_evaluator import FirewallEvaluator
from aws_network_mcp.aws_client.nfw_client import NetworkFirewallClient
from aws_network_mcp.models import Protocol, Verdict

RULES = (
    'drop ip 10.10.0.0/24 any -> 10.20.0.0/24 any (msg:"Deny prod to nonprod"; sid:1000001;)\n'
    'pass ip 10.10.0.0/24 any -> 10.200.0.0/16 any (msg:"Allow prod to onprem"; sid:2000005;)\n'
)


def test_load_policies_from_stubbed_describe_calls() -> None:
    session = boto3.Session(region_name="us-east-1")
    raw = session.client("network-firewall")
    stubber = Stubber(raw)
    policy_arn = "arn:aws:network-firewall:us-east-1:123456789012:firewall-policy/hybrid"
    group_arn = "arn:aws:network-firewall:us-east-1:123456789012:stateful-rulegroup/sids"
    stubber.add_response(
        "list_firewalls",
        {
            "Firewalls": [
                {
                    "FirewallName": "insp",
                    "FirewallArn": "arn:aws:network-firewall:us-east-1:123456789012:firewall/insp",
                }
            ]
        },
    )
    stubber.add_response(
        "describe_firewall",
        {
            "Firewall": {
                "FirewallName": "insp",
                "FirewallId": "12345678-1234-1234-1234-123456789012",
                "FirewallArn": "arn:aws:network-firewall:us-east-1:123456789012:firewall/insp",
                "FirewallPolicyArn": policy_arn,
                "VpcId": "vpc-inspection-001",
                "SubnetMappings": [{"SubnetId": "subnet-inspection-001"}],
            }
        },
        {
            "FirewallName": "insp",
            "FirewallArn": "arn:aws:network-firewall:us-east-1:123456789012:firewall/insp",
        },
    )
    stubber.add_response(
        "describe_firewall_policy",
        {
            "UpdateToken": "00000000-0000-0000-0000-000000000001",
            "FirewallPolicy": {
                "StatelessDefaultActions": ["aws:forward_to_sfe"],
                "StatelessFragmentDefaultActions": ["aws:forward_to_sfe"],
                "StatefulDefaultActions": ["aws:drop_established"],
                "StatefulEngineOptions": {"RuleOrder": "STRICT_ORDER"},
                "StatefulRuleGroupReferences": [{"ResourceArn": group_arn, "Priority": 1}],
                "PolicyVariables": {
                    "RuleVariables": {
                        "HOME_NET": {
                            "Definition": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
                        }
                    }
                },
            },
            "FirewallPolicyResponse": {
                "FirewallPolicyArn": policy_arn,
                "FirewallPolicyName": "hybrid-network-inspection-policy",
                "FirewallPolicyId": "abcdef12-3456-7890-abcd-ef1234567890",
            },
        },
        {"FirewallPolicyArn": policy_arn},
    )
    stubber.add_response(
        "describe_rule_group",
        {
            "UpdateToken": "00000000-0000-0000-0000-000000000002",
            "RuleGroup": {"RulesSource": {"RulesString": RULES}},
            "RuleGroupResponse": {
                "RuleGroupArn": group_arn,
                "RuleGroupName": "hybrid-stateful",
                "RuleGroupId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "Type": "STATEFUL",
            },
        },
        {"RuleGroupArn": group_arn},
    )

    with stubber:
        client = NetworkFirewallClient(region="us-east-1", session=session, client=raw)
        policies, vpcs, warnings = client.load_policies()

    assert "vpc-inspection-001" in vpcs
    policy = next(iter(policies.values()))
    assert policy.rule_order == "STRICT_ORDER"
    assert policy.default_action == "aws:drop_established"
    assert any(rule.sid == "1000001" for rule in policy.rules)
    evaluator = FirewallEvaluator()
    verdict, _, rule = evaluator.evaluate(policy, "10.10.0.10", "10.20.0.10", 443, Protocol.TCP)
    assert verdict == Verdict.DENY
    assert rule is not None and rule.sid == "1000001"
    assert isinstance(warnings, tuple)
