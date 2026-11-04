"""Read-only AWS Network Firewall client for policy import."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal, cast

import boto3

from aws_network_mcp.analysis.suricata_parser import (
    DEFAULT_HOME_NET,
    ParseResult,
    parse_stateful_5tuple_rules,
    parse_suricata_rules,
)
from aws_network_mcp.models import FirewallPolicy

if TYPE_CHECKING:
    from mypy_boto3_network_firewall.client import NetworkFirewallClient as Boto3NfwClient


class NetworkFirewallClient:
    """Read-only Network Firewall client."""

    def __init__(
        self,
        region: str | None = None,
        session: boto3.Session | None = None,
        client: Boto3NfwClient | None = None,
    ) -> None:
        self._session = session or boto3.Session()
        self._region = region or self._session.region_name or "us-east-1"
        self._client: Boto3NfwClient = client or self._session.client(
            "network-firewall", region_name=self._region
        )

    def list_firewalls(self) -> list[dict[str, Any]]:
        """Return ListFirewalls entries."""
        items: list[Any] = []
        token: str | None = None
        while True:
            kwargs: dict[str, Any] = {}
            if token:
                kwargs["NextToken"] = token
            response = self._client.list_firewalls(**kwargs)
            items.extend(list(response.get("Firewalls", [])))
            next_token = response.get("NextToken")
            if not next_token:
                break
            token = str(next_token)
        return items

    def describe_firewall(self, name: str | None = None, arn: str | None = None) -> dict[str, Any]:
        """Return the Firewall object from DescribeFirewall."""
        kwargs: dict[str, str] = {}
        if name:
            kwargs["FirewallName"] = name
        if arn:
            kwargs["FirewallArn"] = arn
        response = self._client.describe_firewall(**kwargs)
        return dict(response.get("Firewall", {}))

    def describe_firewall_policy(self, policy_arn: str) -> dict[str, Any]:
        """Return FirewallPolicy plus name/ARN metadata."""
        response = self._client.describe_firewall_policy(FirewallPolicyArn=policy_arn)
        policy = dict(response.get("FirewallPolicy", {}))
        response_policy = response.get("FirewallPolicyResponse", {})
        policy["_arn"] = response_policy.get("FirewallPolicyArn", policy_arn)
        policy["_name"] = response_policy.get("FirewallPolicyName", policy_arn.split("/")[-1])
        policy["_id"] = response_policy.get("FirewallPolicyId", policy_arn)
        return policy

    def describe_rule_group(self, rule_group_arn: str) -> dict[str, Any]:
        """Return RuleGroup plus name/ARN metadata."""
        response = self._client.describe_rule_group(RuleGroupArn=rule_group_arn)
        group = dict(response.get("RuleGroup", {}))
        meta = response.get("RuleGroupResponse", {})
        group["_arn"] = meta.get("RuleGroupArn", rule_group_arn)
        group["_name"] = meta.get("RuleGroupName", rule_group_arn.split("/")[-1])
        group["_type"] = meta.get("Type", group.get("Type", "STATEFUL"))
        return group

    def load_policies(self) -> tuple[dict[str, FirewallPolicy], frozenset[str], tuple[str, ...]]:
        """Import every firewall's stateful policy.

        Returns:
            policies keyed by policy id, VPC IDs that host a firewall, and
            unsupported-feature notes from rule parsing.
        """
        policies: dict[str, FirewallPolicy] = {}
        inspection_vpcs: set[str] = set()
        warnings: list[str] = []

        for entry in self.list_firewalls():
            name = entry.get("FirewallName")
            arn = entry.get("FirewallArn")
            try:
                firewall = self.describe_firewall(name=name, arn=arn)
            except Exception as exc:
                warnings.append(f"DescribeFirewall failed for {name or arn}: {exc}")
                continue
            vpc_id = firewall.get("VpcId")
            if vpc_id:
                inspection_vpcs.add(str(vpc_id))
            policy_arn = firewall.get("FirewallPolicyArn")
            if not policy_arn:
                warnings.append(f"Firewall {name or arn} has no FirewallPolicyArn")
                continue
            if (
                policy_arn in {p.policy_id for p in policies.values()}
                or str(policy_arn) in policies
            ):
                continue
            try:
                policy_doc = self.describe_firewall_policy(str(policy_arn))
                policy, notes = self._policy_from_document(policy_doc)
            except Exception as exc:
                warnings.append(f"DescribeFirewallPolicy failed for {policy_arn}: {exc}")
                continue
            policies[policy.policy_id] = policy
            warnings.extend(notes)

        return policies, frozenset(inspection_vpcs), tuple(warnings)

    def _policy_from_document(self, document: dict[str, Any]) -> tuple[FirewallPolicy, list[str]]:
        home_net = _home_net_from_policy(document)
        rule_order = str(
            document.get("StatefulEngineOptions", {}).get("RuleOrder")
            or document.get("StatefulEngineOptions", {}).get("ruleOrder")
            or "DEFAULT_ACTION_ORDER"
        )
        if rule_order not in {"STRICT_ORDER", "DEFAULT_ACTION_ORDER"}:
            rule_order = "DEFAULT_ACTION_ORDER"
        defaults = document.get("StatefulDefaultActions") or []
        default_action = _pick_default_action([str(item) for item in defaults])

        references = list(document.get("StatefulRuleGroupReferences") or [])
        references.sort(key=lambda ref: int(ref.get("Priority") or ref.get("priority") or 0))

        parsed = ParseResult()
        for ref in references:
            arn = ref.get("ResourceArn") or ref.get("resourceArn")
            if not arn:
                parsed.unsupported.append("StatefulRuleGroupReferences entry missing ResourceArn")
                continue
            try:
                group = self.describe_rule_group(str(arn))
            except Exception as exc:
                parsed.unsupported.append(f"DescribeRuleGroup failed for {arn}: {exc}")
                continue
            group_type = str(group.get("_type") or group.get("Type") or "STATEFUL").upper()
            if group_type == "STATELESS":
                parsed.unsupported.append(
                    f"{group.get('_name', arn)}: stateless rule groups are not evaluated "
                    f"(STRICT_ORDER uses stateful rules + StatefulDefaultActions)"
                )
                continue
            parsed = _merge_parse(parsed, _parse_rule_group(group, home_net))

        policy = FirewallPolicy(
            policy_id=str(
                document.get("_id") or document.get("_arn") or document.get("_name") or "nfw"
            ),
            name=str(document.get("_name") or "imported-firewall-policy"),
            rule_order=cast(Literal["STRICT_ORDER", "DEFAULT_ACTION_ORDER"], rule_order),
            default_action=default_action,
            rules=tuple(parsed.rules),
        )
        return policy, parsed.unsupported


def _home_net_from_policy(document: dict[str, Any]) -> tuple[str, ...]:
    variables = (
        document.get("PolicyVariables", {}).get("RuleVariables")
        or document.get("RuleVariables")
        or {}
    )
    home = variables.get("HOME_NET") or variables.get("IPSets", {}).get("HOME_NET") or {}
    definition = home.get("Definition") if isinstance(home, dict) else None
    if isinstance(definition, list) and definition:
        return tuple(str(item) for item in definition)
    return DEFAULT_HOME_NET


def _pick_default_action(actions: list[str]) -> str:
    for action in actions:
        lowered = action.lower()
        if "drop" in lowered:
            return action
    return actions[0] if actions else "aws:drop_established"


def _parse_rule_group(group: dict[str, Any], home_net: tuple[str, ...]) -> ParseResult:
    name = str(group.get("_name") or group.get("_arn") or "rule-group")
    source = group.get("RulesSource") or {}
    if source.get("RulesSourceList"):
        result = ParseResult()
        result.unsupported.append(
            f"{name}: domain-list rule groups (TLS_SNI / HTTP_HOST) are not evaluated"
        )
        return result
    if source.get("RulesString"):
        return parse_suricata_rules(str(source["RulesString"]), home_net=home_net, source_name=name)
    stateful = source.get("StatefulRules")
    if isinstance(stateful, list):
        return parse_stateful_5tuple_rules(stateful, home_net=home_net, source_name=name)
    result = ParseResult()
    result.unsupported.append(f"{name}: empty or unknown RulesSource")
    return result


def _merge_parse(left: ParseResult, right: ParseResult) -> ParseResult:
    return ParseResult(
        rules=[*left.rules, *right.rules],
        unsupported=[*left.unsupported, *right.unsupported],
    )
