#!/usr/bin/env python3
"""Prisma Cloud RQL Event & Audit Log Investigator.

Queries Prisma Cloud audit and activity logs across AWS CloudTrail, Azure Activity Logs,
and GCP Cloud Audit Logs using Event RQL (`event from cloud.audit_logs where ...`):
- Audits critical operations (IAM changes, database deletions, security group modifications)
- Supports relative lookback windows (minutes, hours, days)
- Handles pagination across event pages with exponential backoff
- Exports findings to CSV, JSON, or console table

Zero hardcoded API keys or proprietary filters.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from client import PrismaCloudClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("prisma-event-audit")

DEFAULT_CRITICAL_OPERATIONS = [
    "CreateSecurityGroup", "AuthorizeSecurityGroupIngress", "DeleteSecurityGroup",
    "AttachRolePolicy", "PutUserPolicy", "CreateAccessKey", "DeleteAccessKey",
    "CreateDBInstance", "DeleteDBInstance", "TerminateInstances",
]


def escape_rql_literal(val: str) -> str:
    """Escape single quotes and backslashes in RQL literal values."""
    return val.replace("\\", "\\\\").replace("'", "\\'")


def build_event_query(
    operations: Optional[List[str]] = None,
    account_groups: Optional[List[str]] = None,
    user_names: Optional[List[str]] = None,
    raw_query: Optional[str] = None,
) -> str:
    """Construct an RQL event query safely escaping literal values."""
    if raw_query:
        return raw_query

    conditions = []
    if operations:
        ops_list = ", ".join(f"'{escape_rql_literal(op)}'" for op in operations)
        conditions.append(f"operation IN ({ops_list})")

    if account_groups:
        groups_list = ", ".join(f"'{escape_rql_literal(g)}'" for g in account_groups)
        conditions.append(f"cloud.accountgroup IN ({groups_list})")

    if user_names:
        users_list = ", ".join(f"'{escape_rql_literal(u)}'" for u in user_names)
        conditions.append(f"user IN ({users_list})")

    base = "event from cloud.audit_logs"
    if conditions:
        base += " where " + " AND ".join(conditions)
    return base


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Query and audit cloud administrative events via Prisma Cloud RQL."
    )
    parser.add_argument("--query", help="Custom event RQL query string.")
    parser.add_argument("--operations", help="Comma-separated cloud operations (default: critical ops).")
    parser.add_argument("--account-groups", help="Comma-separated Prisma Cloud account groups.")
    parser.add_argument("--users", help="Comma-separated user identities to filter.")
    parser.add_argument("--hours", type=int, default=24, help="Lookback window in hours (default: 24).")
    parser.add_argument("--limit-per-page", type=int, default=100, help="Batch size per page (default: 100).")
    parser.add_argument("--max-events", type=int, help="Maximum events to retrieve.")
    parser.add_argument("--access-key", help="Prisma Cloud Access Key.")
    parser.add_argument("--secret-key", help="Prisma Cloud Secret Key.")
    parser.add_argument("--api-url", default="https://api.prismacloud.io", help="Prisma Cloud API URL.")
    parser.add_argument("--format", choices=["table", "csv", "json"], default="table", help="Output format.")
    parser.add_argument("--output-file", help="File path to write report to.")
    return parser.parse_args(args)


def main() -> int:
    opts = parse_args()
    ops = [o.strip() for o in opts.operations.split(",")] if opts.operations else DEFAULT_CRITICAL_OPERATIONS
    groups = [g.strip() for g in opts.account_groups.split(",")] if opts.account_groups else None
    users = [u.strip() for u in opts.users.split(",")] if opts.users else None

    query_str = build_event_query(
        operations=ops if not opts.query else None,
        account_groups=groups,
        user_names=users,
        raw_query=opts.query,
    )

    try:
        client = PrismaCloudClient(
            access_key=opts.access_key,
            secret_key=opts.secret_key,
            api_url=opts.api_url,
        )
    except ValueError as e:
        logger.error("Authentication setup error: %s", e)
        return 1

    logger.info("Executing Prisma Event Query (%d hours lookback): %s", opts.hours, query_str)
    events: List[Dict[str, Any]] = []

    try:
        for ev in client.search_events(
            query=query_str,
            limit=opts.limit_per_page,
            time_unit="minute",
            time_amount=opts.hours * 60,
        ):
            # Parse Prisma event attributes
            events.append({
                "timestamp": ev.get("timestamp") or ev.get("time", "Unknown"),
                "cloud_type": ev.get("cloudType", "Unknown"),
                "account_name": ev.get("accountName", "Unknown"),
                "account_id": ev.get("accountId", "Unknown"),
                "operation": ev.get("operation") or ev.get("eventName", "Unknown"),
                "user": ev.get("user") or ev.get("userName", "Unknown"),
                "source_ip": ev.get("sourceIPAddress") or ev.get("sourceIp", "Unknown"),
                "status": ev.get("status", "Success"),
            })

            if opts.max_events and len(events) >= opts.max_events:
                logger.info("Reached requested max event count (%d).", opts.max_events)
                break
    except Exception as e:
        logger.error("Error executing event search: %s", e)
        return 1

    logger.info("Retrieved %d audit events.", len(events))

    if opts.format == "json":
        text_out = json.dumps({"query": query_str, "total_events": len(events), "events": events}, indent=2)
    elif opts.format == "csv":
        fieldnames = ["timestamp", "cloud_type", "account_id", "account_name", "user", "operation", "source_ip", "status"]
        import io
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(events)
        text_out = buf.getvalue()
    else:
        lines = [
            "=" * 120,
            f" PRISMA CLOUD EVENT AUDIT REPORT ({len(events)} events | Last {opts.hours}h)",
            "=" * 120,
            f"{'Timestamp':<22} {'Cloud':<7} {'Account':<18} {'User':<20} {'Operation':<28} {'Source IP'}",
            "-" * 120,
        ]
        for ev in events[:100]:
            lines.append(
                f"{str(ev['timestamp'])[:20]:<22} {ev['cloud_type']:<7} {ev['account_name'][:16]:<18} "
                f"{ev['user'][:18]:<20} {ev['operation'][:26]:<28} {ev['source_ip']}"
            )
        if len(events) > 100:
            lines.append(f"... ({len(events) - 100} additional events truncated in table view; use --format csv or json)")
        lines.append("=" * 120)
        text_out = "\n".join(lines)

    if opts.output_file:
        p = Path(opts.output_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text_out, encoding="utf-8")
        logger.info("Report written to %s", opts.output_file)
    else:
        print(text_out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
