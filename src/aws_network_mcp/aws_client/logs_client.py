"""CloudWatch Logs client for VPC Flow Logs querying."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import boto3

from aws_network_mcp.models import FlowLogEntry

if TYPE_CHECKING:
    from mypy_boto3_logs.client import CloudWatchLogsClient as Boto3LogsClient


class CloudWatchLogsClient:
    """Read-only CloudWatch Logs client for VPC Flow Log analysis."""

    def __init__(self, region: str | None = None, session: boto3.Session | None = None):
        self._session = session or boto3.Session()
        self._region = region or self._session.region_name
        self._client: Boto3LogsClient = self._session.client("logs", region_name=self._region)

    def query_flow_logs(
        self,
        log_group: str,
        src_addr: str | None = None,
        dst_addr: str | None = None,
        src_port: int | None = None,
        dst_port: int | None = None,
        protocol: int | None = None,
        action: str | None = None,
        start_time_ms: int | None = None,
        end_time_ms: int | None = None,
        limit: int = 100,
    ) -> list[FlowLogEntry]:
        """
        Query VPC Flow Logs using CloudWatch Logs Insights.

        Args:
            log_group: CloudWatch Logs group name containing flow logs
            src_addr: Source IP address filter
            dst_addr: Destination IP address filter
            src_port: Source port filter
            dst_port: Destination port filter
            protocol: IP protocol number filter (6=TCP, 17=UDP, 1=ICMP)
            action: ACCEPT or REJECT filter
            start_time_ms: Query start time in milliseconds
            end_time_ms: Query end time in milliseconds
            limit: Maximum number of results

        Returns:
            List of FlowLogEntry objects matching the query
        """
        now_ms = int(time.time() * 1000)
        if end_time_ms is None:
            end_time_ms = now_ms
        if start_time_ms is None:
            start_time_ms = end_time_ms - (15 * 60 * 1000)

        query_parts = [
            "fields @timestamp, srcAddr, dstAddr, srcPort, dstPort, protocol, action, "
            "logStatus, interfaceId"
        ]

        filters = []
        if src_addr:
            filters.append(f"srcAddr = '{src_addr}'")
        if dst_addr:
            filters.append(f"dstAddr = '{dst_addr}'")
        if src_port is not None:
            filters.append(f"srcPort = {src_port}")
        if dst_port is not None:
            filters.append(f"dstPort = {dst_port}")
        if protocol is not None:
            filters.append(f"protocol = {protocol}")
        if action:
            filters.append(f"action = '{action}'")

        if filters:
            query_parts.append("| filter " + " and ".join(filters))

        query_parts.append("| sort @timestamp desc")
        query_parts.append(f"| limit {limit}")

        query_string = "\n".join(query_parts)

        start_response = self._client.start_query(
            logGroupName=log_group,
            startTime=start_time_ms // 1000,
            endTime=end_time_ms // 1000,
            queryString=query_string,
        )
        query_id = start_response["queryId"]

        while True:
            response = self._client.get_query_results(queryId=query_id)
            status = response.get("status", "Unknown")
            if status in ("Complete", "Failed", "Cancelled"):
                break
            time.sleep(0.5)

        if status != "Complete":
            return []

        results: list[FlowLogEntry] = []
        for row in response.get("results", []):
            fields = {f["field"]: f["value"] for f in row}

            action_val = fields.get("action", "ACCEPT")
            if action_val not in ("ACCEPT", "REJECT"):
                action_val = "ACCEPT"

            results.append(
                FlowLogEntry(
                    timestamp=fields.get("@timestamp", ""),
                    src_addr=fields.get("srcAddr", ""),
                    dst_addr=fields.get("dstAddr", ""),
                    src_port=int(fields.get("srcPort", 0)),
                    dst_port=int(fields.get("dstPort", 0)),
                    protocol=int(fields.get("protocol", 0)),
                    action=action_val,  # type: ignore[arg-type]
                    log_status=fields.get("logStatus", ""),
                    interface_id=fields.get("interfaceId"),
                )
            )

        return results
