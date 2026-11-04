"""Tests for Suricata / 5-tuple Network Firewall rule parsing."""

from __future__ import annotations

from aws_network_mcp.analysis.firewall_evaluator import FirewallEvaluator
from aws_network_mcp.analysis.suricata_parser import (
    parse_stateful_5tuple_rules,
    parse_suricata_rules,
)
from aws_network_mcp.models import Protocol, Verdict

LANDING_ZONE_RULES = """
# landing-zone STRICT_ORDER policy
drop ip 10.10.0.0/24 any -> 10.20.0.0/24 any (msg:"Deny prod to nonprod"; sid:1000001; rev:1;)
drop ip 10.20.0.0/24 any -> 10.10.0.0/24 any (msg:"Deny nonprod to prod"; sid:1000002; rev:1;)
drop ip 10.20.0.0/24 any -> [10.200.0.0/16,192.168.100.0/24] any (msg:"Deny nonprod to onprem"; sid:1000003; rev:1;)
pass ip 10.10.0.0/24 any -> 10.1.0.0/24 any (msg:"Allow prod to shared"; sid:2000001; rev:1;)
pass ip 10.10.0.0/24 any -> [10.200.0.0/16,192.168.100.0/24] any (msg:"Allow prod to onprem"; sid:2000005; rev:1;)
pass ip $HOME_NET any -> !$HOME_NET any (msg:"Allow inspected egress to internet"; sid:3000001; rev:1;)
alert http any any -> any any (msg:"http inspector"; sid:9; content:"evil";)
drop tls any any -> any any (msg:"tls inspector"; sid:10; tls.sni; content:"bad";)
"""


def test_parse_landing_zone_common_shapes() -> None:
    parsed = parse_suricata_rules(LANDING_ZONE_RULES)
    sids = {rule.sid for rule in parsed.rules}
    assert {"1000001", "2000001", "2000005", "3000001"} <= sids
    drop = next(rule for rule in parsed.rules if rule.sid == "1000001")
    assert drop.action == "drop"
    assert drop.source_cidrs == ("10.10.0.0/24",)
    assert drop.dest_cidrs == ("10.20.0.0/24",)
    egress = next(rule for rule in parsed.rules if rule.sid == "3000001")
    assert egress.dest_negate is True
    assert any("unsupported protocol" in note or "skipped:" in note for note in parsed.unsupported)
    assert any("alert action" in note for note in parsed.unsupported)


def test_parsed_rules_evaluate_like_fixtures() -> None:
    from aws_network_mcp.models import FirewallPolicy

    parsed = parse_suricata_rules(LANDING_ZONE_RULES)
    policy = FirewallPolicy(
        policy_id="parsed",
        name="hybrid-network-inspection-policy",
        rule_order="STRICT_ORDER",
        default_action="aws:drop_established",
        rules=tuple(parsed.rules),
    )
    evaluator = FirewallEvaluator()
    deny, _, rule = evaluator.evaluate(policy, "10.10.0.10", "10.20.0.10", 443, Protocol.TCP)
    assert deny == Verdict.DENY
    assert rule is not None and rule.sid == "1000001"
    allow, _, rule = evaluator.evaluate(policy, "10.10.0.10", "10.200.1.50", 443, Protocol.TCP)
    assert allow == Verdict.ALLOW
    assert rule is not None and rule.sid == "2000005"
    egress, _, rule = evaluator.evaluate(policy, "10.10.0.10", "8.8.8.8", 443, Protocol.TCP)
    assert egress == Verdict.ALLOW
    assert rule is not None and rule.sid == "3000001"


def test_parse_stateful_5tuple() -> None:
    parsed = parse_stateful_5tuple_rules(
        [
            {
                "Action": "DROP",
                "Header": {
                    "Protocol": "IP",
                    "Source": "10.10.0.0/24",
                    "SourcePort": "ANY",
                    "Direction": "FORWARD",
                    "Destination": "10.20.0.0/24",
                    "DestinationPort": "ANY",
                },
                "RuleOptions": [
                    {"Keyword": "sid", "Settings": ["1000001"]},
                    {"Keyword": "msg", "Settings": ["Deny prod to nonprod"]},
                ],
            }
        ]
    )
    assert len(parsed.rules) == 1
    assert parsed.rules[0].sid == "1000001"
    assert parsed.rules[0].action == "drop"
