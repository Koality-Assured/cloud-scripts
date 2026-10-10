#!/usr/bin/env python3
"""Prisma Cloud Security Alert & Remediation Backlog Auditor.

Aggregates open security alerts across AWS, GCP, and Azure accounts:
- Classifies alert volume by Severity (Critical, High, Medium, Low)
- Groups violations by Cloud Provider
- Identifies the Top 10 offending security policies contributing to alert fatigue
- Summarizes remediation backlog for executive reporting

Exports report to CSV, JSON, or formatted console table.
"""

from __future__ import annotations

import argparse
import collections
import csv
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from client import PrismaCloudClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("prisma-alert-audit")


def audit_alerts(
    client: PrismaCloudClient,
    status: str = "open",
    max_alerts: Optional[int] = None,
) -> Dict[str, Any]:
    """Retrieve and aggregate security alerts from Prisma Cloud."""
    logger.info("Fetching %s alerts from Prisma Cloud...", status)
    alerts = client.list_alerts(status=status, max_alerts=max_alerts)

    severity_counts: collections.Counter[str] = collections.Counter()
    cloud_counts: collections.Counter[str] = collections.Counter()
    policy_counts: collections.Counter[str] = collections.Counter()

    processed_alerts = []
    for a in alerts:
        # Prisma alert structure
        policy = a.get("policy", {})
        policy_name = policy.get("name") or a.get("policyName", "Unknown Policy")
        severity = policy.get("severity") or a.get("severity", "medium").lower()

        res = a.get("resource", {})
        cloud_type = res.get("cloudType") or a.get("cloudType", "unknown").lower()
        account_name = res.get("accountName") or a.get("accountName", "unknown")

        severity_counts[severity] += 1
        cloud_counts[cloud_type] += 1
        policy_counts[policy_name] += 1

        processed_alerts.append({
            "alert_id": a.get("id", "unknown"),
            "severity": severity,
            "cloud_type": cloud_type,
            "account_name": account_name,
            "policy_name": policy_name,
        })

    top_policies = [
        {"policy_name": name, "alert_count": count}
        for name, count in policy_counts.most_common(10)
    ]

    return {
        "status_filter": status,
        "total_alerts": len(alerts),
        "by_severity": dict(severity_counts),
        "by_cloud": dict(cloud_counts),
        "top_offending_policies": top_policies,
        "sample_alerts": processed_alerts[:200],
    }


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit open security alerts and policy violations in Prisma Cloud."
    )
    parser.add_argument("--access-key", help="Prisma Cloud Access Key.")
    parser.add_argument("--secret-key", help="Prisma Cloud Secret Key.")
    parser.add_argument("--api-url", default="https://api.prismacloud.io", help="Prisma Cloud API URL.")
    parser.add_argument("--status", default="open", choices=["open", "resolved", "dismissed"], help="Alert status filter.")
    parser.add_argument("--max-alerts", type=int, help="Maximum total alerts to process.")
    parser.add_argument("--format", choices=["table", "csv", "json"], default="table", help="Output format.")
    parser.add_argument("--output-file", help="File path to write report to.")
    return parser.parse_args(args)


def main() -> int:
    opts = parse_args()
    try:
        client = PrismaCloudClient(
            access_key=opts.access_key,
            secret_key=opts.secret_key,
            api_url=opts.api_url,
        )
    except ValueError as e:
        logger.error("Authentication setup error: %s", e)
        return 1

    try:
        report = audit_alerts(client, status=opts.status, max_alerts=opts.max_alerts)
    except Exception as e:
        logger.error("Failed querying alerts: %s", e)
        return 1

    if opts.format == "json":
        text_out = json.dumps(report, indent=2)
    elif opts.format == "csv":
        fieldnames = ["policy_name", "alert_count"]
        import io
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(report["top_offending_policies"])
        text_out = buf.getvalue()
    else:
        lines = [
            "=" * 90,
            f" PRISMA CLOUD ALERT & REMEDIATION AUDIT (Total Open Alerts: {report['total_alerts']})",
            "=" * 90,
            "Severity Breakdown:",
        ]
        for sev in ["critical", "high", "medium", "low"]:
            count = report["by_severity"].get(sev, 0)
            lines.append(f"  {sev.upper():<10}: {count} alerts")

        lines.append("\nCloud Provider Breakdown:")
        for cloud, count in report["by_cloud"].items():
            lines.append(f"  {cloud.upper():<10}: {count} alerts")

        lines.append("\n" + "-" * 90)
        lines.append(f"{'Top Offending Policies (Causing Alert Fatigue)':<68} {'Alert Count'}")
        lines.append("-" * 90)
        for p in report["top_offending_policies"]:
            lines.append(f"{p['policy_name'][:66]:<68} {p['alert_count']}")
        lines.append("=" * 90)
        text_out = "\n".join(lines)

    if opts.output_file:
        p = Path(opts.output_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text_out, encoding="utf-8")
        logger.info("Alert report saved to %s", opts.output_file)
    else:
        print(text_out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
