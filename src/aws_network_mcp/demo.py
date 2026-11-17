#!/usr/bin/env python3
"""Demo runner for hybrid path-analysis scenarios.

Run with: python -m aws_network_mcp.demo
Or: make demo
"""

from __future__ import annotations

import sys
from typing import Any

from aws_network_mcp.analysis.path_analyzer import PathAnalyzer
from aws_network_mcp.fixtures.scenarios import DEMO_SCENARIOS


def print_header(text: str) -> None:
    """Print a formatted header."""
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)


def print_hop(hop_num: int, hop: dict[str, Any]) -> None:
    """Print a single hop analysis."""
    icons = {
        "ALLOW": "✓",
        "DENY": "✗",
        "BLACKHOLE": "⚫",
        "UNKNOWN": "?",
    }
    icon = icons.get(hop["verdict"], "?")
    color_start = ""
    color_end = ""

    if sys.stdout.isatty():
        colors = {
            "ALLOW": "\033[92m",
            "DENY": "\033[91m",
            "BLACKHOLE": "\033[93m",
            "UNKNOWN": "\033[90m",
        }
        color_start = colors.get(hop["verdict"], "")
        color_end = "\033[0m"

    print(f"  {hop_num}. [{color_start}{icon}{color_end}] {hop['hop_type']}: {hop['resource_id']}")
    print(f"      {hop['details']}")
    if hop.get("matched_route"):
        print(f"      └─ route/rule: {hop['matched_route']}")
    if hop.get("blocking_rule"):
        print(f"      └─ BLOCKING: {hop['blocking_rule']}")


def run_demo() -> None:
    """Run all demo scenarios and check expected verdicts."""
    print("\n" + "=" * 70)
    print("  AWS Network MCP — Hybrid Path Analysis Demo")
    print("  Landing-zone TGW, inspection VPC, Network Firewall, on-prem BGP")
    print("=" * 70)

    passed = 0
    failed = 0

    for scenario_name, (scenario, topology) in DEMO_SCENARIOS.items():
        print_header(f"Scenario: {scenario.name}")
        print(f"\nDescription: {scenario.description}")
        print(f"Modified: {scenario.topology_modifier}")
        print(
            f"\nTest: {scenario.source.ip} → {scenario.destination.ip}:"
            f"{scenario.port}/{scenario.protocol.value}"
        )
        print(f"Expected verdict: {scenario.expected_verdict.value}")

        analyzer = PathAnalyzer(topology)
        result = analyzer.analyze_path(
            source=scenario.source,
            destination=scenario.destination,
            port=scenario.port,
            protocol=scenario.protocol,
        )

        print(f"\nVerdict: {result.overall_verdict.value}")
        print(f"Summary: {result.summary}")
        if result.inspection_bypassed:
            print("Inspection bypassed: yes")
        if result.additional_findings:
            print("Additional findings:")
            for finding in result.additional_findings:
                print(f"  - {finding}")

        print("\nPath Analysis:")
        for i, hop in enumerate(result.hops, 1):
            print_hop(
                i,
                {
                    "verdict": hop.verdict.value,
                    "hop_type": hop.hop_type,
                    "resource_id": hop.resource_id,
                    "details": hop.details,
                    "blocking_rule": hop.blocking_rule,
                    "matched_route": hop.matched_route,
                },
            )

        if result.blocking_hop:
            print("\nBlocking hop:")
            print(f"   Type: {result.blocking_hop.hop_type}")
            print(f"   Resource: {result.blocking_hop.resource_id}")
            print(f"   Details: {result.blocking_hop.details}")
            if result.blocking_hop.blocking_rule:
                print(f"   Rule: {result.blocking_hop.blocking_rule}")

        verdict_ok = result.overall_verdict == scenario.expected_verdict
        hop_ok = True
        if scenario.expected_blocking_hop_type:
            hop_ok = (
                result.blocking_hop is not None
                and result.blocking_hop.hop_type == scenario.expected_blocking_hop_type
            )
        bypass_ok = result.inspection_bypassed == scenario.expect_inspection_bypass

        if verdict_ok and hop_ok and bypass_ok:
            passed += 1
            print(f"\n✓ {scenario_name} matched expected analysis")
        else:
            failed += 1
            print(f"\n✗ {scenario_name} did not match expected analysis")
            if not verdict_ok:
                print(f"   got verdict {result.overall_verdict.value}")
            if not hop_ok:
                got = result.blocking_hop.hop_type if result.blocking_hop else None
                print(f"   expected blocking hop {scenario.expected_blocking_hop_type}, got {got}")
            if not bypass_ok:
                print(f"   expected inspection_bypassed={scenario.expect_inspection_bypass}")

    print_header("Demo Summary")
    print(f"\nTotal scenarios: {len(DEMO_SCENARIOS)}")
    print(f"Matched expected analysis: {passed}")
    print(f"Mismatched: {failed}")

    if failed == 0:
        print("\n✓ All scenarios diagnosed correctly!")
        return
    print(f"\n{failed} scenario(s) were not diagnosed as expected")
    sys.exit(1)


def main() -> None:
    """Entry point."""
    run_demo()


if __name__ == "__main__":
    main()
