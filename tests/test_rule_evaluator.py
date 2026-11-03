"""Tests for security group and NACL rule evaluation."""

from __future__ import annotations

from aws_network_mcp.analysis.rule_evaluator import NaclEvaluator, SecurityGroupEvaluator
from aws_network_mcp.models import (
    NaclInfo,
    NaclRule,
    Protocol,
    SecurityGroupInfo,
    SecurityGroupRule,
    Verdict,
)


class TestSecurityGroupEvaluator:
    """Tests for SecurityGroupEvaluator class."""

    def test_evaluate_ingress_allow_cidr(self) -> None:
        """Test ingress allowed by CIDR rule."""
        evaluator = SecurityGroupEvaluator()
        sg = SecurityGroupInfo(
            sg_id="sg-001",
            name="test-sg",
            vpc_id="vpc-001",
            rules=(SecurityGroupRule("ingress", "6", 443, 443, "10.0.0.0/8"),),
        )

        verdict, details, rule = evaluator.evaluate_ingress(sg, "10.1.2.3", 443, Protocol.TCP)
        assert verdict == Verdict.ALLOW
        assert rule is not None

    def test_evaluate_ingress_deny_wrong_port(self) -> None:
        """Test ingress denied due to wrong port."""
        evaluator = SecurityGroupEvaluator()
        sg = SecurityGroupInfo(
            sg_id="sg-001",
            name="test-sg",
            vpc_id="vpc-001",
            rules=(SecurityGroupRule("ingress", "6", 443, 443, "10.0.0.0/8"),),
        )

        verdict, details, rule = evaluator.evaluate_ingress(sg, "10.1.2.3", 8080, Protocol.TCP)
        assert verdict == Verdict.DENY
        assert rule is None
        assert "8080" in details

    def test_evaluate_ingress_deny_wrong_source(self) -> None:
        """Test ingress denied due to source not matching."""
        evaluator = SecurityGroupEvaluator()
        sg = SecurityGroupInfo(
            sg_id="sg-001",
            name="test-sg",
            vpc_id="vpc-001",
            rules=(SecurityGroupRule("ingress", "6", 443, 443, "10.0.0.0/8"),),
        )

        verdict, details, rule = evaluator.evaluate_ingress(sg, "192.168.1.1", 443, Protocol.TCP)
        assert verdict == Verdict.DENY
        assert "192.168.1.1" in details

    def test_evaluate_ingress_allow_all_protocol(self) -> None:
        """Test ingress allowed by all-protocol rule."""
        evaluator = SecurityGroupEvaluator()
        sg = SecurityGroupInfo(
            sg_id="sg-001",
            name="test-sg",
            vpc_id="vpc-001",
            rules=(SecurityGroupRule("ingress", "-1", None, None, "0.0.0.0/0"),),
        )

        verdict, _, _ = evaluator.evaluate_ingress(sg, "1.2.3.4", 22, Protocol.TCP)
        assert verdict == Verdict.ALLOW

    def test_evaluate_ingress_sg_reference(self) -> None:
        """Test ingress allowed by security group reference."""
        evaluator = SecurityGroupEvaluator()
        sg = SecurityGroupInfo(
            sg_id="sg-dest",
            name="dest-sg",
            vpc_id="vpc-001",
            rules=(SecurityGroupRule("ingress", "6", 5432, 5432, source_sg_id="sg-source"),),
        )

        verdict, _, _ = evaluator.evaluate_ingress(
            sg, "10.0.0.50", 5432, Protocol.TCP, source_sg_ids={"sg-source"}
        )
        assert verdict == Verdict.ALLOW

    def test_evaluate_ingress_sg_reference_not_match(self) -> None:
        """Test ingress denied when SG reference doesn't match."""
        evaluator = SecurityGroupEvaluator()
        sg = SecurityGroupInfo(
            sg_id="sg-dest",
            name="dest-sg",
            vpc_id="vpc-001",
            rules=(SecurityGroupRule("ingress", "6", 5432, 5432, source_sg_id="sg-source"),),
        )

        verdict, _, _ = evaluator.evaluate_ingress(
            sg, "10.0.0.50", 5432, Protocol.TCP, source_sg_ids={"sg-other"}
        )
        assert verdict == Verdict.DENY

    def test_evaluate_egress_allow(self) -> None:
        """Test egress allowed."""
        evaluator = SecurityGroupEvaluator()
        sg = SecurityGroupInfo(
            sg_id="sg-001",
            name="test-sg",
            vpc_id="vpc-001",
            rules=(SecurityGroupRule("egress", "-1", None, None, "0.0.0.0/0"),),
        )

        verdict, _, _ = evaluator.evaluate_egress(sg, "8.8.8.8", 443, Protocol.TCP)
        assert verdict == Verdict.ALLOW

    def test_evaluate_egress_deny(self) -> None:
        """Test egress denied."""
        evaluator = SecurityGroupEvaluator()
        sg = SecurityGroupInfo(
            sg_id="sg-001",
            name="test-sg",
            vpc_id="vpc-001",
            rules=(SecurityGroupRule("egress", "6", 443, 443, "10.0.0.0/8"),),
        )

        verdict, _, _ = evaluator.evaluate_egress(sg, "8.8.8.8", 443, Protocol.TCP)
        assert verdict == Verdict.DENY

    def test_evaluate_with_prefix_list(self) -> None:
        """Test evaluation with prefix list."""
        evaluator = SecurityGroupEvaluator(
            prefix_list_cidrs={"pl-001": ["10.0.0.0/8", "172.16.0.0/12"]}
        )
        sg = SecurityGroupInfo(
            sg_id="sg-001",
            name="test-sg",
            vpc_id="vpc-001",
            rules=(SecurityGroupRule("ingress", "6", 443, 443, prefix_list_id="pl-001"),),
        )

        verdict, _, _ = evaluator.evaluate_ingress(sg, "172.16.1.1", 443, Protocol.TCP)
        assert verdict == Verdict.ALLOW


class TestNaclEvaluator:
    """Tests for NaclEvaluator class."""

    def test_evaluate_ingress_allow(self) -> None:
        """Test NACL ingress allowed."""
        evaluator = NaclEvaluator()
        nacl = NaclInfo(
            nacl_id="acl-001",
            vpc_id="vpc-001",
            name="test-nacl",
            rules=(
                NaclRule(100, "ingress", "6", 443, 443, "10.0.0.0/8", "allow"),
                NaclRule(32767, "ingress", "-1", None, None, "0.0.0.0/0", "deny"),
            ),
            subnet_associations=(),
        )

        verdict, details, rule = evaluator.evaluate_ingress(nacl, "10.1.2.3", 443, Protocol.TCP)
        assert verdict == Verdict.ALLOW
        assert rule is not None
        assert rule.rule_number == 100

    def test_evaluate_ingress_deny_explicit(self) -> None:
        """Test NACL ingress denied by explicit rule."""
        evaluator = NaclEvaluator()
        nacl = NaclInfo(
            nacl_id="acl-001",
            vpc_id="vpc-001",
            name="test-nacl",
            rules=(
                NaclRule(50, "ingress", "6", 22, 22, "0.0.0.0/0", "deny"),
                NaclRule(100, "ingress", "-1", None, None, "0.0.0.0/0", "allow"),
            ),
            subnet_associations=(),
        )

        verdict, details, rule = evaluator.evaluate_ingress(nacl, "1.2.3.4", 22, Protocol.TCP)
        assert verdict == Verdict.DENY
        assert rule is not None
        assert rule.rule_number == 50

    def test_evaluate_ingress_rule_order(self) -> None:
        """Test NACL rules evaluated in order."""
        evaluator = NaclEvaluator()
        nacl = NaclInfo(
            nacl_id="acl-001",
            vpc_id="vpc-001",
            name="test-nacl",
            rules=(
                NaclRule(200, "ingress", "-1", None, None, "0.0.0.0/0", "allow"),
                NaclRule(100, "ingress", "6", 22, 22, "0.0.0.0/0", "deny"),
            ),
            subnet_associations=(),
        )

        verdict, _, rule = evaluator.evaluate_ingress(nacl, "1.2.3.4", 22, Protocol.TCP)
        assert verdict == Verdict.DENY
        assert rule is not None
        assert rule.rule_number == 100

    def test_evaluate_egress(self) -> None:
        """Test NACL egress evaluation."""
        evaluator = NaclEvaluator()
        nacl = NaclInfo(
            nacl_id="acl-001",
            vpc_id="vpc-001",
            name="test-nacl",
            rules=(
                NaclRule(100, "egress", "-1", None, None, "0.0.0.0/0", "allow"),
                NaclRule(32767, "egress", "-1", None, None, "0.0.0.0/0", "deny"),
            ),
            subnet_associations=(),
        )

        verdict, _, _ = evaluator.evaluate_egress(nacl, "8.8.8.8", 443, Protocol.TCP)
        assert verdict == Verdict.ALLOW

    def test_evaluate_return_traffic_allowed(self) -> None:
        """Test NACL return traffic allowed with ephemeral ports."""
        evaluator = NaclEvaluator()
        nacl = NaclInfo(
            nacl_id="acl-001",
            vpc_id="vpc-001",
            name="test-nacl",
            rules=(
                NaclRule(100, "ingress", "6", 443, 443, "0.0.0.0/0", "allow"),
                NaclRule(200, "ingress", "6", 1024, 65535, "0.0.0.0/0", "allow"),
                NaclRule(32767, "ingress", "-1", None, None, "0.0.0.0/0", "deny"),
            ),
            subnet_associations=(),
        )

        verdict, details, _ = evaluator.evaluate_return_traffic(
            nacl, "10.0.0.1", "10.1.0.1", 443, Protocol.TCP
        )
        assert verdict == Verdict.ALLOW
        assert "ephemeral" in details.lower()

    def test_evaluate_return_traffic_blocked(self) -> None:
        """Test NACL return traffic blocked when ephemeral ports not allowed."""
        evaluator = NaclEvaluator()
        nacl = NaclInfo(
            nacl_id="acl-001",
            vpc_id="vpc-001",
            name="test-nacl",
            rules=(
                NaclRule(100, "ingress", "6", 443, 443, "0.0.0.0/0", "allow"),
                NaclRule(32767, "ingress", "-1", None, None, "0.0.0.0/0", "deny"),
            ),
            subnet_associations=(),
        )

        verdict, details, _ = evaluator.evaluate_return_traffic(
            nacl, "10.0.0.1", "10.1.0.1", 443, Protocol.TCP
        )
        assert verdict == Verdict.DENY
        assert "ephemeral" in details.lower()
        assert "stateless" in details.lower()

    def test_evaluate_default_deny(self) -> None:
        """Test default deny when no rules match."""
        evaluator = NaclEvaluator()
        nacl = NaclInfo(
            nacl_id="acl-001",
            vpc_id="vpc-001",
            name="test-nacl",
            rules=(
                NaclRule(100, "ingress", "6", 22, 22, "10.0.0.0/8", "allow"),
                NaclRule(32767, "ingress", "-1", None, None, "0.0.0.0/0", "deny"),
            ),
            subnet_associations=(),
        )

        verdict, details, _ = evaluator.evaluate_ingress(nacl, "192.168.1.1", 443, Protocol.TCP)
        assert verdict == Verdict.DENY
        assert "default" in details.lower()
