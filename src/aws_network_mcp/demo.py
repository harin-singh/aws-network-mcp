#!/usr/bin/env python3
"""Demo runner showing AWS network troubleshooting scenarios.

Run with: python -m aws_network_mcp.demo
Or: make demo
"""

from __future__ import annotations

import sys

from aws_network_mcp.analysis.path_analyzer import PathAnalyzer
from aws_network_mcp.fixtures.scenarios import DEMO_SCENARIOS
from aws_network_mcp.models import Verdict


def print_header(text: str) -> None:
    """Print a formatted header."""
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)


def print_hop(hop_num: int, hop: dict) -> None:  # type: ignore[type-arg]
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
    if hop.get("blocking_rule"):
        print(f"      └─ BLOCKING: {hop['blocking_rule']}")


def run_demo() -> None:
    """Run all demo scenarios and show diagnoses."""
    print("\n" + "=" * 70)
    print("  AWS Network MCP - Troubleshooting Demo")
    print("  Diagnosing common AWS network misconfigurations")
    print("=" * 70)

    passed = 0
    failed = 0

    for _scenario_name, (scenario, topology) in DEMO_SCENARIOS.items():
        print_header(f"Scenario: {scenario.name}")
        print(f"\nDescription: {scenario.description}")
        print(f"Modified: {scenario.topology_modifier}")
        print(
            f"\nTest: {scenario.source.ip} → {scenario.destination.ip}:{scenario.port}/{scenario.protocol.value}"
        )

        analyzer = PathAnalyzer(topology)
        result = analyzer.analyze_path(
            source=scenario.source,
            destination=scenario.destination,
            port=scenario.port,
            protocol=scenario.protocol,
        )

        print(f"\nVerdict: {result.overall_verdict.value}")
        print(f"Summary: {result.summary}")

        print("\nPath Analysis:")
        for i, hop in enumerate(result.hops, 1):
            hop_dict = {
                "verdict": hop.verdict.value,
                "hop_type": hop.hop_type,
                "resource_id": hop.resource_id,
                "details": hop.details,
                "blocking_rule": hop.blocking_rule,
            }
            print_hop(i, hop_dict)

        if result.blocking_hop:
            print("\n⚠️  Blocking Issue Found:")
            print(f"   Type: {result.blocking_hop.hop_type}")
            print(f"   Resource: {result.blocking_hop.resource_id}")
            print(f"   Details: {result.blocking_hop.details}")
            if result.blocking_hop.blocking_rule:
                print(f"   Rule: {result.blocking_hop.blocking_rule}")

        if result.overall_verdict != Verdict.ALLOW:
            passed += 1
            print("\n✓ Correctly identified connectivity issue")
        else:
            failed += 1
            print("\n✗ Expected to find a connectivity issue but path is ALLOW")

    print_header("Demo Summary")
    print(f"\nTotal scenarios: {len(DEMO_SCENARIOS)}")
    print(f"Issues correctly identified: {passed}")
    print(f"Missed issues: {failed}")

    if failed == 0:
        print("\n✓ All scenarios diagnosed correctly!")
    else:
        print(f"\n⚠️  {failed} scenario(s) were not diagnosed as expected")
        sys.exit(1)


def main() -> None:
    """Entry point."""
    run_demo()


if __name__ == "__main__":
    main()
