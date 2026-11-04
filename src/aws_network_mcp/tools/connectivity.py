"""Connectivity analysis tools for the MCP server."""

from __future__ import annotations

import time
from typing import Any

from aws_network_mcp.analysis.path_analyzer import NetworkTopology, PathAnalyzer
from aws_network_mcp.aws_client.ec2_client import EC2Client
from aws_network_mcp.models import (
    HopAnalysis,
    NetworkEndpoint,
    PathAnalysisResult,
    Protocol,
    ReachabilityAnalysisResult,
)


def _endpoint_from_input(
    ec2_client: EC2Client | None,
    instance_id: str | None = None,
    eni_id: str | None = None,
    ip: str | None = None,
    vpc_id: str | None = None,
    topology: NetworkTopology | None = None,
) -> NetworkEndpoint | None:
    """Resolve input parameters to a NetworkEndpoint."""
    if instance_id and ec2_client:
        return ec2_client.get_instance_network_info(instance_id)
    if eni_id and ec2_client:
        return ec2_client.get_eni_network_info(eni_id)
    if ip and ec2_client:
        return ec2_client.get_ip_network_info(ip, vpc_id)
    if ip and topology:
        return topology.resolve_endpoint(ip)
    if ip:
        return NetworkEndpoint(ip=ip, vpc_id=vpc_id, is_on_prem=vpc_id is None)
    return None


def _format_hop(hop: HopAnalysis) -> dict[str, Any]:
    """Format a hop analysis for JSON output."""
    return {
        "hop_type": hop.hop_type,
        "resource_id": hop.resource_id,
        "resource_name": hop.resource_name,
        "verdict": hop.verdict.value,
        "details": hop.details,
        "blocking_rule": hop.blocking_rule,
        "matched_route": hop.matched_route,
    }


def _format_result(result: PathAnalysisResult) -> dict[str, Any]:
    """Format path analysis result for JSON output."""
    return {
        "source": {
            "ip": result.source.ip,
            "vpc_id": result.source.vpc_id,
            "subnet_id": result.source.subnet_id,
            "eni_id": result.source.eni_id,
            "instance_id": result.source.instance_id,
        },
        "destination": {
            "ip": result.destination.ip,
            "vpc_id": result.destination.vpc_id,
            "subnet_id": result.destination.subnet_id,
            "is_on_prem": result.destination.is_on_prem,
        },
        "port": result.port,
        "protocol": result.protocol.value,
        "overall_verdict": result.overall_verdict.value,
        "summary": result.summary,
        "hops": [_format_hop(hop) for hop in result.hops],
        "blocking_hop": _format_hop(result.blocking_hop) if result.blocking_hop else None,
        "additional_findings": result.additional_findings,
        "inspection_bypassed": result.inspection_bypassed,
    }


def describe_path(
    source_instance_id: str | None = None,
    source_eni_id: str | None = None,
    source_ip: str | None = None,
    dest_instance_id: str | None = None,
    dest_eni_id: str | None = None,
    dest_ip: str | None = None,
    dest_vpc_id: str | None = None,
    port: int = 443,
    protocol: str = "tcp",
    ec2_client: EC2Client | None = None,
    topology: NetworkTopology | None = None,
) -> dict[str, Any]:
    """
    Analyze network path from source to destination.

    Walks through each hop: security groups, NACLs, route tables,
    Transit Gateway, and returns a verdict with blocking rule if any.

    Args:
        source_instance_id: EC2 instance ID of source
        source_eni_id: ENI ID of source
        source_ip: IP address of source
        dest_instance_id: EC2 instance ID of destination
        dest_eni_id: ENI ID of destination
        dest_ip: IP address of destination
        dest_vpc_id: VPC ID hint for destination lookup
        port: Destination port number
        protocol: Protocol (tcp, udp, icmp)
        ec2_client: EC2 client for AWS API calls
        topology: Pre-loaded topology for offline/demo mode

    Returns:
        Dict with path analysis result including hop-by-hop verdict
    """
    protocol_enum = Protocol(protocol.lower())

    source = _endpoint_from_input(
        ec2_client,
        instance_id=source_instance_id,
        eni_id=source_eni_id,
        ip=source_ip,
        topology=topology,
    )
    if not source:
        return {
            "error": "Could not resolve source endpoint",
            "hint": "Provide instance_id, eni_id, or ip address",
        }

    dest = _endpoint_from_input(
        ec2_client,
        instance_id=dest_instance_id,
        eni_id=dest_eni_id,
        ip=dest_ip,
        vpc_id=dest_vpc_id,
        topology=topology,
    )
    if not dest:
        return {
            "error": "Could not resolve destination endpoint",
            "hint": "Provide instance_id, eni_id, or ip address",
        }

    if topology is None:
        return {
            "error": "No topology available",
            "hint": "Either connect to AWS or use demo mode",
        }

    analyzer = PathAnalyzer(topology)
    result = analyzer.analyze_path(source, dest, port, protocol_enum)
    return _format_result(result)


def explain_connectivity(
    source_ip: str,
    dest_ip: str,
    port: int = 443,
    protocol: str = "tcp",
    ec2_client: EC2Client | None = None,
    topology: NetworkTopology | None = None,
) -> dict[str, Any]:
    """
    Explain why source can or cannot reach destination.

    Simplified interface to describe_path using IP addresses.

    Args:
        source_ip: Source IP address
        dest_ip: Destination IP address
        port: Destination port
        protocol: Protocol (tcp, udp, icmp)

    Returns:
        Human-readable explanation of connectivity
    """
    result = describe_path(
        source_ip=source_ip,
        dest_ip=dest_ip,
        port=port,
        protocol=protocol,
        ec2_client=ec2_client,
        topology=topology,
    )

    if "error" in result:
        return result

    explanation_parts = [
        f"Connectivity analysis: {result['source']['ip']} → {result['destination']['ip']}:{port}/{protocol}",
        "",
        f"**Verdict: {result['overall_verdict']}**",
        "",
        result["summary"],
        "",
        "Path analysis:",
    ]

    for i, hop in enumerate(result["hops"], 1):
        icon = "✓" if hop["verdict"] == "ALLOW" else "✗" if hop["verdict"] == "DENY" else "?"
        explanation_parts.append(
            f"  {i}. [{icon}] {hop['hop_type']}: {hop['resource_id']} - {hop['details']}"
        )

    if result.get("additional_findings"):
        explanation_parts.append("")
        explanation_parts.append("Additional findings:")
        for finding in result["additional_findings"]:
            explanation_parts.append(f"  - {finding}")

    if result.get("inspection_bypassed"):
        explanation_parts.append("")
        explanation_parts.append(
            "**Inspection bypassed** — a more-specific TGW route skipped the firewall."
        )

    if result["blocking_hop"]:
        explanation_parts.extend(
            [
                "",
                "**Blocking issue:**",
                f"  Type: {result['blocking_hop']['hop_type']}",
                f"  Resource: {result['blocking_hop']['resource_id']}",
                f"  Rule: {result['blocking_hop']['blocking_rule']}",
            ]
        )

    return {
        "explanation": "\n".join(explanation_parts),
        "verdict": result["overall_verdict"],
        "raw_result": result,
    }


def run_reachability_analysis(
    source: str,
    destination: str,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    destination_port: int | None = None,
    protocol: str = "tcp",
    ec2_client: EC2Client | None = None,
    wait_for_completion: bool = True,
    cleanup: bool = True,
) -> dict[str, Any]:
    """
    Run VPC Reachability Analyzer to test connectivity.

    **Cost Note**: Each analysis incurs a charge (~$0.10 per path analyzed).
    See AWS pricing for current rates.

    Args:
        source: Source resource (instance ID, ENI ID, etc.)
        destination: Destination resource
        source_ip: Optional source IP filter
        destination_ip: Optional destination IP filter
        destination_port: Optional destination port
        protocol: Protocol to analyze
        wait_for_completion: Wait for analysis to complete
        cleanup: Delete the path after analysis

    Returns:
        Analysis results including reachability verdict and path details
    """
    if ec2_client is None:
        return {
            "error": "Reachability Analyzer requires AWS API access",
            "hint": "This tool cannot run in demo/offline mode",
            "cost_note": "Each analysis costs ~$0.10. Use describe_path for free offline analysis.",
        }

    try:
        path_id = ec2_client.create_reachability_path(
            source=source,
            destination=destination,
            source_ip=source_ip,
            destination_ip=destination_ip,
            destination_port=destination_port,
            protocol=protocol,
        )

        analysis_id = ec2_client.start_reachability_analysis(path_id)

        if wait_for_completion:
            max_wait = 120
            waited = 0
            while waited < max_wait:
                result = ec2_client.get_reachability_analysis(analysis_id)
                if result.status in ("succeeded", "failed"):
                    break
                time.sleep(5)
                waited += 5

            if cleanup:
                import contextlib

                with contextlib.suppress(Exception):
                    ec2_client.delete_reachability_path(path_id)

            return {
                "analysis_id": result.analysis_id,
                "path_id": result.path_id,
                "status": result.status,
                "reachable": result.reachable,
                "explanations": result.explanations,
                "forward_path": result.forward_path,
                "return_path": result.return_path,
                "cost_note": result.cost_note,
            }
        else:
            return {
                "analysis_id": analysis_id,
                "path_id": path_id,
                "status": "running",
                "message": "Analysis started. Query status with analysis_id.",
                "cost_note": ReachabilityAnalysisResult(
                    analysis_id="", path_id="", status="", reachable=None
                ).cost_note,
            }

    except Exception as e:
        return {
            "error": str(e),
            "hint": "Ensure source and destination are valid resource IDs",
        }
