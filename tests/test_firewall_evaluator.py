"""Tests for Network Firewall STRICT_ORDER evaluation."""

from __future__ import annotations

from aws_network_mcp.analysis.firewall_evaluator import FirewallEvaluator
from aws_network_mcp.fixtures.topology import DemoTopology
from aws_network_mcp.models import FirewallPolicy, FirewallRule, Protocol, Verdict


class TestFirewallEvaluator:
    """Tests for FirewallEvaluator."""

    def test_landing_zone_prod_to_nonprod_drop(self) -> None:
        policy = DemoTopology._build_firewall_policy()
        evaluator = FirewallEvaluator()
        verdict, details, rule = evaluator.evaluate(
            policy, "10.10.0.10", "10.20.0.10", 443, Protocol.TCP
        )
        assert verdict == Verdict.DENY
        assert rule is not None
        assert rule.sid == "1000001"
        assert "Deny prod to nonprod" in details

    def test_landing_zone_prod_to_onprem_pass(self) -> None:
        policy = DemoTopology._build_firewall_policy()
        evaluator = FirewallEvaluator()
        verdict, details, rule = evaluator.evaluate(
            policy, "10.10.0.10", "10.200.1.50", 443, Protocol.TCP
        )
        assert verdict == Verdict.ALLOW
        assert rule is not None
        assert rule.sid == "2000005"
        assert "Allow prod to onprem" in details

    def test_default_drop_when_no_rule_matches(self) -> None:
        policy = FirewallPolicy(
            policy_id="fw-1",
            name="empty",
            rule_order="STRICT_ORDER",
            default_action="aws:drop_established",
            rules=(),
        )
        verdict, details, rule = FirewallEvaluator().evaluate(
            policy, "1.1.1.1", "8.8.8.8", 443, Protocol.TCP
        )
        assert verdict == Verdict.DENY
        assert rule is None
        assert "aws:drop_established" in details

    def test_negated_dest_matches_internet(self) -> None:
        policy = FirewallPolicy(
            policy_id="fw-1",
            name="egress",
            rule_order="STRICT_ORDER",
            default_action="aws:drop_established",
            rules=(
                FirewallRule(
                    "3000001",
                    "pass",
                    "ip",
                    ("10.0.0.0/8",),
                    ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"),
                    dest_negate=True,
                    message="inspected egress",
                ),
            ),
        )
        evaluator = FirewallEvaluator()
        allow, _, rule = evaluator.evaluate(policy, "10.10.0.10", "8.8.8.8", 443, Protocol.TCP)
        assert allow == Verdict.ALLOW
        assert rule is not None
        deny, _, _ = evaluator.evaluate(policy, "10.10.0.10", "10.1.0.10", 443, Protocol.TCP)
        assert deny == Verdict.DENY
