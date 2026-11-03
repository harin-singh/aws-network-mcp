"""VPC Flow Logs query tools."""

from __future__ import annotations

from typing import Any

from aws_network_mcp.aws_client.logs_client import CloudWatchLogsClient


def query_flow_logs(
    log_group: str,
    src_addr: str | None = None,
    dst_addr: str | None = None,
    src_port: int | None = None,
    dst_port: int | None = None,
    protocol: int | None = None,
    action: str | None = None,
    start_time_minutes_ago: int = 15,
    limit: int = 100,
    logs_client: CloudWatchLogsClient | None = None,
) -> dict[str, Any]:
    """
    Query VPC Flow Logs for traffic matching a 5-tuple filter.

    Uses CloudWatch Logs Insights to search flow log data.

    Args:
        log_group: CloudWatch Logs group containing flow logs
        src_addr: Source IP address filter
        dst_addr: Destination IP address filter
        src_port: Source port filter
        dst_port: Destination port filter
        protocol: IP protocol number (6=TCP, 17=UDP, 1=ICMP)
        action: ACCEPT or REJECT filter
        start_time_minutes_ago: How far back to search (default 15 minutes)
        limit: Maximum results to return

    Returns:
        Matching flow log entries with summary statistics
    """
    if logs_client is None:
        return _demo_flow_logs(src_addr, dst_addr, dst_port, action)

    try:
        import time

        end_time_ms = int(time.time() * 1000)
        start_time_ms = end_time_ms - (start_time_minutes_ago * 60 * 1000)

        entries = logs_client.query_flow_logs(
            log_group=log_group,
            src_addr=src_addr,
            dst_addr=dst_addr,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            action=action,
            start_time_ms=start_time_ms,
            end_time_ms=end_time_ms,
            limit=limit,
        )

        accept_count = sum(1 for e in entries if e.action == "ACCEPT")
        reject_count = sum(1 for e in entries if e.action == "REJECT")

        return {
            "log_group": log_group,
            "query_params": {
                "src_addr": src_addr,
                "dst_addr": dst_addr,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "action": action,
                "time_range_minutes": start_time_minutes_ago,
            },
            "summary": {
                "total_entries": len(entries),
                "accept_count": accept_count,
                "reject_count": reject_count,
            },
            "entries": [
                {
                    "timestamp": e.timestamp,
                    "src_addr": e.src_addr,
                    "dst_addr": e.dst_addr,
                    "src_port": e.src_port,
                    "dst_port": e.dst_port,
                    "protocol": e.protocol,
                    "action": e.action,
                    "interface_id": e.interface_id,
                }
                for e in entries
            ],
        }

    except Exception as e:
        return {
            "error": str(e),
            "log_group": log_group,
            "hint": "Ensure the log group exists and you have logs:StartQuery permission",
        }


def _demo_flow_logs(
    src_addr: str | None,
    dst_addr: str | None,
    dst_port: int | None,
    action: str | None,
) -> dict[str, Any]:
    """Demo mode flow logs."""
    demo_entries = [
        {
            "timestamp": "2024-01-15T10:30:00Z",
            "src_addr": src_addr or "10.1.0.100",
            "dst_addr": dst_addr or "10.2.0.50",
            "src_port": 52431,
            "dst_port": dst_port or 443,
            "protocol": 6,
            "action": action or "ACCEPT",
            "interface_id": "eni-demo-001",
        },
        {
            "timestamp": "2024-01-15T10:30:01Z",
            "src_addr": src_addr or "10.1.0.100",
            "dst_addr": dst_addr or "10.2.0.50",
            "src_port": 52432,
            "dst_port": dst_port or 443,
            "protocol": 6,
            "action": action or "ACCEPT",
            "interface_id": "eni-demo-001",
        },
        {
            "timestamp": "2024-01-15T10:30:02Z",
            "src_addr": src_addr or "10.1.0.100",
            "dst_addr": "10.200.1.100",
            "src_port": 52433,
            "dst_port": 22,
            "protocol": 6,
            "action": "REJECT",
            "interface_id": "eni-demo-001",
        },
    ]

    if action:
        demo_entries = [e for e in demo_entries if e["action"] == action]

    accept_count = sum(1 for e in demo_entries if e["action"] == "ACCEPT")
    reject_count = sum(1 for e in demo_entries if e["action"] == "REJECT")

    return {
        "log_group": "demo-flow-logs",
        "query_params": {
            "src_addr": src_addr,
            "dst_addr": dst_addr,
            "dst_port": dst_port,
            "action": action,
        },
        "summary": {
            "total_entries": len(demo_entries),
            "accept_count": accept_count,
            "reject_count": reject_count,
        },
        "entries": demo_entries,
        "mode": "demo",
    }
