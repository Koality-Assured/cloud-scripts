#!/usr/bin/env python3
"""Prisma Cloud RQL Config Search & Security Posture Inventory.

Executes Prisma Cloud Resource Query Language (RQL) configuration searches:
- Built-in library of curated security queries across AWS, GCP, and Azure
- Custom RQL query support via --query
- Seamless pagination across tens of thousands of resources
- Output to CSV, JSON, or formatted console table

Zero hardcoded API keys or proprietary account group references.
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
logger = logging.getLogger("prisma-config-inventory")

PRESET_QUERIES = {
    "all-cloud-resources": (
        "config from cloud.resource where cloud.type IN ('aws', 'gcp', 'azure')"
    ),
    "aws-all-resources": (
        "config from cloud.resource where cloud.type = 'aws'"
    ),
    "azure-all-resources": (
        "config from cloud.resource where cloud.type = 'azure'"
    ),
    "gcp-all-resources": (
        "config from cloud.resource where cloud.type = 'gcp'"
    ),
    "aws-public-s3": (
        "config from cloud.resource where cloud.type = 'aws' AND "
        "api.name = 'aws-s3api-get-bucket-acl' AND "
        "json.rule = acl.grants[?(@.grantee.uri contains 'AllUsers')] exists"
    ),
    "aws-open-ssh-rdp": (
        "config from cloud.resource where cloud.type = 'aws' AND "
        "api.name = 'aws-ec2-describe-security-groups' AND "
        "json.rule = ipPermissions[?(@.toPort == 22 || @.toPort == 3389)].ipRanges[*] contains 0.0.0.0/0"
    ),
    "azure-public-storage": (
        "config from cloud.resource where cloud.type = 'azure' AND "
        "api.name = 'azure-storage-account-list' AND "
        "json.rule = properties.allowBlobPublicAccess is true"
    ),
    "gcp-unencrypted-disks": (
        "config from cloud.resource where cloud.type = 'gcp' AND "
        "api.name = 'gcloud-compute-disks-list' AND "
        "json.rule = diskEncryptionKey does not exist"
    ),
}


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Execute Prisma Cloud RQL configuration searches."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--query", help="Custom RQL configuration query string.")
    group.add_argument(
        "--preset",
        choices=list(PRESET_QUERIES.keys()),
        help="Use a pre-defined security query preset.",
    )

    parser.add_argument("--access-key", help="Prisma Cloud Access Key (default: PRISMA_ACCESS_KEY env var).")
    parser.add_argument("--secret-key", help="Prisma Cloud Secret Key (default: PRISMA_SECRET_KEY env var).")
    parser.add_argument("--api-url", default="https://api.prismacloud.io", help="Prisma Cloud API URL.")
    parser.add_argument("--limit-per-page", type=int, default=1000, help="Batch limit per API page (default: 1000).")
    parser.add_argument("--max-items", type=int, help="Maximum total items to fetch.")
    parser.add_argument("--format", choices=["table", "csv", "json"], default="table", help="Output format.")
    parser.add_argument("--output-file", help="File path to write report to.")
    return parser.parse_args(args)


def main() -> int:
    opts = parse_args()
    query_str = opts.query if opts.query else PRESET_QUERIES[opts.preset]

    try:
        client = PrismaCloudClient(
            access_key=opts.access_key,
            secret_key=opts.secret_key,
            api_url=opts.api_url,
        )
    except ValueError as e:
        logger.error("Authentication setup error: %s", e)
        return 1

    logger.info("Executing RQL Config Search: %s", query_str)
    items: List[Dict[str, Any]] = []

    try:
        for resource in client.search_config(query=query_str, limit=opts.limit_per_page):
            # Extract common Prisma Cloud resource properties
            res_id = resource.get("id") or resource.get("name", "Unknown")
            cloud_type = resource.get("cloudType", "Unknown")
            account_id = resource.get("accountId", "Unknown")
            account_name = resource.get("accountName", account_id)
            region = resource.get("regionName") or resource.get("region", "Global")
            service = resource.get("service", "Unknown")
            res_type = resource.get("resourceType") or resource.get("apiName", "Unknown")

            items.append({
                "resource_id": res_id,
                "cloud_type": cloud_type,
                "account_id": account_id,
                "account_name": account_name,
                "region": region,
                "service": service,
                "resource_type": res_type,
            })

            if opts.max_items and len(items) >= opts.max_items:
                logger.info("Reached maximum requested item limit (%d).", opts.max_items)
                break
    except Exception as e:
        logger.error("Error executing RQL query: %s", e)
        return 1

    logger.info("Retrieved %d resources.", len(items))

    if opts.format == "json":
        text_out = json.dumps({"query": query_str, "total_resources": len(items), "items": items}, indent=2)
    elif opts.format == "csv":
        fieldnames = ["cloud_type", "account_id", "account_name", "region", "service", "resource_type", "resource_id"]
        import io
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(items)
        text_out = buf.getvalue()
    else:
        lines = [
            "=" * 115,
            f" PRISMA CLOUD CONFIG SEARCH REPORT (Found {len(items)} resources)",
            "=" * 115,
            f"{'Cloud':<8} {'Account':<20} {'Region':<14} {'Service':<14} {'Resource Type':<24} {'Resource ID'}",
            "-" * 115,
        ]
        for r in items[:100]:
            lines.append(
                f"{r['cloud_type']:<8} {r['account_name'][:18]:<20} {r['region'][:12]:<14} "
                f"{r['service'][:12]:<14} {r['resource_type'][:22]:<24} {r['resource_id']}"
            )
        if len(items) > 100:
            lines.append(f"... ({len(items) - 100} additional resources truncated in table view; use --format csv or json)")
        lines.append("=" * 115)
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
