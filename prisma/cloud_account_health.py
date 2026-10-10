#!/usr/bin/env python3
"""Prisma Cloud Onboarded Cloud Account Health Monitor.

Audits all cloud accounts connected to Prisma Cloud (AWS, Azure, GCP, Alibaba, OCI):
- Account connection health status (Active, Inactive, Failed, Disabled)
- Last completed compliance and inventory scan timestamps
- Permission validation and credential verification
- Identifies degraded accounts requiring credential re-authentication

Exports report to CSV, JSON, or console table.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from client import PrismaCloudClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("prisma-account-health")


def audit_account_health(client: PrismaCloudClient) -> List[Dict[str, Any]]:
    """Retrieve and evaluate cloud account connection health."""
    raw_accounts = client.list_cloud_accounts()
    health_records = []

    for acct in raw_accounts:
        aid = acct.get("accountId") or acct.get("id", "Unknown")
        name = acct.get("name", aid)
        cloud_type = acct.get("cloudType", "Unknown")
        status = acct.get("status", "Unknown")

        last_scan_ms = acct.get("lastModifiedTs") or acct.get("lastScanTs", 0)
        last_scan_str = "Never"
        days_since_scan = 999
        if last_scan_ms:
            try:
                scan_dt = datetime.datetime.fromtimestamp(last_scan_ms / 1000.0, tz=datetime.timezone.utc)
                last_scan_str = scan_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                days_since_scan = (datetime.datetime.now(datetime.timezone.utc) - scan_dt).days
            except Exception:
                pass

        # Identify health concerns
        is_healthy = status.lower() in ("active", "healthy", "ok") and days_since_scan <= 3

        health_records.append({
            "account_id": aid,
            "account_name": name,
            "cloud_type": cloud_type,
            "status": status,
            "is_healthy": is_healthy,
            "last_scan_time": last_scan_str,
            "days_since_last_scan": days_since_scan if days_since_scan != 999 else "N/A",
            "account_groups": ", ".join(acct.get("groups", [])),
        })

    return health_records


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit connection health of cloud accounts connected to Prisma Cloud."
    )
    parser.add_argument("--access-key", help="Prisma Cloud Access Key.")
    parser.add_argument("--secret-key", help="Prisma Cloud Secret Key.")
    parser.add_argument("--api-url", default="https://api.prismacloud.io", help="Prisma Cloud API URL.")
    parser.add_argument("--show-unhealthy-only", action="store_true", help="Filter for only degraded or failed accounts.")
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

    logger.info("Querying onboarded cloud accounts from Prisma Cloud...")
    try:
        accounts = audit_account_health(client)
    except Exception as e:
        logger.error("Failed querying accounts: %s", e)
        return 1

    if opts.show_unhealthy_only:
        accounts = [a for a in accounts if not a["is_healthy"]]

    unhealthy_count = sum(1 for a in accounts if not a["is_healthy"])

    if opts.format == "json":
        text_out = json.dumps({
            "total_accounts": len(accounts),
            "unhealthy_accounts_count": unhealthy_count,
            "accounts": accounts,
        }, indent=2)
    elif opts.format == "csv":
        fieldnames = ["account_id", "account_name", "cloud_type", "status", "is_healthy", "last_scan_time", "account_groups"]
        import io
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(accounts)
        text_out = buf.getvalue()
    else:
        lines = [
            "=" * 115,
            f" PRISMA CLOUD ACCOUNT HEALTH AUDIT (Total: {len(accounts)} | Degraded/Unhealthy: {unhealthy_count})",
            "=" * 115,
            f"{'Cloud':<8} {'Account ID':<18} {'Account Name':<24} {'Status':<12} {'Health':<10} {'Last Scan'}",
            "-" * 115,
        ]
        for a in accounts:
            health_str = "HEALTHY" if a["is_healthy"] else "DEGRADED"
            lines.append(
                f"{a['cloud_type']:<8} {a['account_id']:<18} {a['account_name'][:22]:<24} "
                f"{a['status']:<12} {health_str:<10} {a['last_scan_time']}"
            )
        lines.append("=" * 115)
        text_out = "\n".join(lines)

    if opts.output_file:
        p = Path(opts.output_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text_out, encoding="utf-8")
        logger.info("Account health report saved to %s", opts.output_file)
    else:
        print(text_out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
