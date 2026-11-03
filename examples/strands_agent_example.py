#!/usr/bin/env python3
"""Example: Using AWS Network MCP with Amazon Bedrock Strands Agent.

This example shows how to integrate the AWS Network MCP server
with a Strands-based agent running on Amazon Bedrock.

Prerequisites:
- pip install strands-agents boto3
- AWS credentials configured with Bedrock access
- AWS Network MCP server installed
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any


def create_mcp_tool_config() -> dict[str, Any]:
    """Create the MCP tool configuration for Strands."""
    return {
        "name": "aws-network-mcp",
        "description": "AWS network troubleshooting tools",
        "transport": {
            "type": "stdio",
            "command": [sys.executable, "-m", "aws_network_mcp.server"],
            "env": {
                "AWS_REGION": "us-east-1",
            },
        },
    }


def run_with_strands() -> None:
    """Run a network troubleshooting session with Strands agent."""
    try:
        from strands import Agent
        from strands.models import BedrockModel
    except ImportError:
        print("Strands not installed. Install with: pip install strands-agents")
        print("\nShowing example configuration instead:\n")
        print(json.dumps(create_mcp_tool_config(), indent=2))
        return

    model = BedrockModel(
        model_id="anthropic.claude-3-sonnet-20240229-v1:0",
        region_name="us-east-1",
    )

    agent = Agent(
        model=model,
        system_prompt="""You are a network troubleshooting assistant with deep expertise 
in AWS networking including VPCs, Transit Gateway, security groups, NACLs, 
VPN, and Direct Connect. 

When asked "Why can't A talk to B?", use the available tools to:
1. First use describe_path or explain_connectivity to analyze the network path
2. Check each hop: security groups, NACLs, route tables, Transit Gateway
3. Identify the exact blocking rule or missing route
4. Provide a clear diagnosis with remediation steps

Be specific about which resource and rule is causing the issue.""",
        mcp_servers=[create_mcp_tool_config()],
    )

    print("AWS Network Troubleshooting Agent")
    print("=" * 40)
    print("Example queries:")
    print("- Why can't my app server reach the database?")
    print("- Check connectivity from 10.1.0.100 to 10.2.0.50 on port 443")
    print("- What TGW routes exist for the prod VPC?")
    print("\nType 'quit' to exit.\n")

    while True:
        try:
            query = input("You: ").strip()
            if query.lower() in ("quit", "exit", "q"):
                break
            if not query:
                continue

            response = agent.run(query)
            print(f"\nAgent: {response}\n")

        except KeyboardInterrupt:
            break

    print("\nGoodbye!")


def demo_without_strands() -> None:
    """Demo the MCP server directly without Strands."""
    print("Running MCP server in demo mode...")
    print("This shows what tools are available:\n")

    result = subprocess.run(
        [sys.executable, "-m", "aws_network_mcp.demo"],
        capture_output=False,
        text=True,
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AWS Network MCP with Strands Agent")
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run demo mode without Strands",
    )
    args = parser.parse_args()

    if args.demo:
        demo_without_strands()
    else:
        run_with_strands()
