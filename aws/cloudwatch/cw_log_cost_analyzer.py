#!/usr/bin/env python3
"""CloudWatch Logs Cost & Ingestion Analyzer.

Discovers CloudWatch log groups across AWS profiles and regions, queries incoming byte
metrics (CloudWatch Metric: IncomingBytes), active stored bytes, and current retention settings.
Estimates monthly ingestion cost, monthly storage cost, and the cost differential from
enforcing a targeted retention policy.

Exports findings to CSV, JSON, or formatted console tables.
"""

from __future__ import annotations

import argparse
import configparser
import csv
import datetime
import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cw-log-cost-analyzer")

STANDARD_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "ca-central-1", "eu-west-1", "eu-west-2", "eu-west-3",
    "eu-central-1", "ap-northeast-1", "ap-northeast-2",
    "ap-southeast-1", "ap-southeast-2", "ap-south-1", "sa-east-1"
]


def get_configured_profiles(pattern: Optional[str] = None) -> List[str]:
    """Discover AWS profile names from local AWS config file."""
    config_path = Path(os.path.expanduser("~/.aws/config"))
    if not config_path.exists():
        return ["default"]

    parser = configparser.ConfigParser()
    try:
        parser.read(config_path)
    except Exception as e:
        logger.warning("Could not read AWS config file: %s", e)
        return ["default"]

    profiles = []
    for section in parser.sections():
        if section.startswith("profile "):
            pname = section[len("profile "):].strip()
            if not pattern or re.search(pattern, pname, re.IGNORECASE):
                profiles.append(pname)
        elif section == "default" and (not pattern or re.search(pattern, "default", re.IGNORECASE)):
            profiles.append("default")

    return profiles or ["default"]


def analyze_log_group(
    cloudwatch: Any,
    log_group: Dict[str, Any],
    ingest_rate_per_gb: float = 0.50,
    store_rate_per_gb: float = 0.03,
    target_retention_days: int = 30,
) -> Dict[str, Any]:
    """Calculate ingestion volume, stored bytes, and cost projections for a single log group."""
    name = log_group.get("logGroupName", "")
    arn = log_group.get("arn", "")
    created = log_group.get("creationTime", 0)
    current_retention = log_group.get("retentionInDays", 0)
    stored_bytes = log_group.get("storedBytes", 0)
    stored_gb = stored_bytes / (1024 ** 3)

    # Query last 30 days incoming bytes
    end_time = datetime.datetime.now(datetime.timezone.utc)
    start_time = end_time - datetime.timedelta(days=30)

    incoming_bytes = 0.0
    try:
        stats = cloudwatch.get_metric_statistics(
            Namespace="AWS/Logs",
            MetricName="IncomingBytes",
            Dimensions=[{"Name": "LogGroupName", "Value": name}],
            StartTime=start_time,
            EndTime=end_time,
            Period=86400 * 30,  # 30 day aggregate
            Statistics=["Sum"],
            Unit="Bytes",
        )
        datapoints = stats.get("Datapoints", [])
        if datapoints:
            incoming_bytes = float(datapoints[0].get("Sum", 0.0))
    except ClientError as e:
        logger.debug("Failed metric lookup for %s: %s", name, e)

    monthly_ingest_gb = incoming_bytes / (1024 ** 3)
    monthly_ingest_cost = monthly_ingest_gb * ingest_rate_per_gb
    monthly_store_cost = stored_gb * store_rate_per_gb

    # If current retention is indefinite (0) or larger than target, estimate storage savings
    if current_retention == 0 or current_retention > target_retention_days:
        # Estimated steady-state stored size under target retention:
        # daily average * target_retention_days
        daily_ingest_gb = monthly_ingest_gb / 30.0 if monthly_ingest_gb > 0 else (stored_gb / 365.0)
        projected_stored_gb = min(stored_gb, daily_ingest_gb * target_retention_days)
        projected_store_cost = projected_stored_gb * store_rate_per_gb
        monthly_savings = max(0.0, monthly_store_cost - projected_store_cost)
    else:
        monthly_savings = 0.0

    return {
        "log_group_name": name,
        "arn": arn,
        "created_timestamp": created,
        "retention_days": current_retention if current_retention > 0 else "Never",
        "stored_gb": round(stored_gb, 4),
        "monthly_ingest_gb": round(monthly_ingest_gb, 4),
        "monthly_ingest_cost_usd": round(monthly_ingest_cost, 2),
        "monthly_storage_cost_usd": round(monthly_store_cost, 2),
        "projected_monthly_savings_usd": round(monthly_savings, 2),
    }


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze CloudWatch log group ingestion, storage size, and cost savings."
    )
    parser.add_argument("--profiles", help="Comma-separated AWS CLI profiles (default: auto-discover).")
    parser.add_argument("--profile-pattern", help="Regex pattern to filter AWS profiles (e.g., 'prod', 'Audit').")
    parser.add_argument("--regions", help="Comma-separated regions (default: standard regions).")
    parser.add_argument("--filter-pattern", help="Regex pattern to filter log group names (e.g., 'flowlogs|vpc|prisma').")
    parser.add_argument("--target-retention", type=int, default=30, help="Target retention days for savings projection (default: 30).")
    parser.add_argument("--ingest-rate", type=float, default=0.50, help="Ingest cost per GB (default: $0.50).")
    parser.add_argument("--storage-rate", type=float, default=0.03, help="Storage cost per GB-month (default: $0.03).")
    parser.add_argument("--format", choices=["table", "csv", "json"], default="table", help="Output format.")
    parser.add_argument("--output-file", help="File path to write report to (default: print to stdout).")
    return parser.parse_args(args)


def main() -> int:
    opts = parse_args()

    profiles = opts.profiles.split(",") if opts.profiles else get_configured_profiles(opts.profile_pattern)
    regions = opts.regions.split(",") if opts.regions else STANDARD_REGIONS

    name_regex = re.compile(opts.filter_pattern, re.IGNORECASE) if opts.filter_pattern else None

    all_results: List[Dict[str, Any]] = []

    for profile in profiles:
        logger.info("Processing AWS profile: %s", profile)
        for region in regions:
            try:
                session = boto3.Session(profile_name=profile, region_name=region)
                logs_client = session.client("logs", region_name=region)
                cw_client = session.client("cloudwatch", region_name=region)

                paginator = logs_client.get_paginator("describe_log_groups")
                for page in paginator.paginate():
                    for lg in page.get("logGroups", []):
                        lg_name = lg.get("logGroupName", "")
                        if name_regex and not name_regex.search(lg_name):
                            continue

                        data = analyze_log_group(
                            cloudwatch=cw_client,
                            log_group=lg,
                            ingest_rate_per_gb=opts.ingest_rate,
                            store_rate_per_gb=opts.storage_rate,
                            target_retention_days=opts.target_retention,
                        )
                        data["profile"] = profile
                        data["region"] = region
                        all_results.append(data)
            except ClientError as e:
                logger.debug("Failed querying %s / %s: %s", profile, region, e)
            except Exception as e:
                logger.debug("Unexpected error in %s / %s: %s", profile, region, e)

    # Sort results by monthly storage cost descending
    all_results.sort(key=lambda x: x["monthly_storage_cost_usd"], reverse=True)

    total_ingest_cost = sum(r["monthly_ingest_cost_usd"] for r in all_results)
    total_store_cost = sum(r["monthly_storage_cost_usd"] for r in all_results)
    total_potential_savings = sum(r["projected_monthly_savings_usd"] for r in all_results)

    if opts.format == "json":
        output_payload = {
            "summary": {
                "total_log_groups": len(all_results),
                "total_monthly_ingest_cost_usd": round(total_ingest_cost, 2),
                "total_monthly_storage_cost_usd": round(total_store_cost, 2),
                "total_projected_savings_usd": round(total_potential_savings, 2),
            },
            "log_groups": all_results,
        }
        text_out = json.dumps(output_payload, indent=2)
    elif opts.format == "csv":
        fieldnames = [
            "profile", "region", "log_group_name", "retention_days",
            "stored_gb", "monthly_ingest_gb", "monthly_ingest_cost_usd",
            "monthly_storage_cost_usd", "projected_monthly_savings_usd"
        ]
        import io
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_results)
        text_out = buf.getvalue()
    else:
        # Table format
        lines = [
            "=" * 115,
            f"{'Profile':<15} {'Region':<12} {'Retention':<10} {'Stored(GB)':<12} {'Ingest($/mo)':<14} {'Store($/mo)':<13} {'Savings($)':<12} {'Log Group Name'}",
            "-" * 115,
        ]
        for r in all_results:
            lines.append(
                f"{r['profile'][:14]:<15} {r['region']:<12} {str(r['retention_days']):<10} "
                f"{r['stored_gb']:<12.2f} ${r['monthly_ingest_cost_usd']:<13.2f} "
                f"${r['monthly_storage_cost_usd']:<12.2f} ${r['projected_monthly_savings_usd']:<11.2f} "
                f"{r['log_group_name']}"
            )
        lines.append("=" * 115)
        lines.append(
            f"TOTALS across {len(all_results)} log groups: Ingest: ${total_ingest_cost:.2f}/mo | "
            f"Storage: ${total_store_cost:.2f}/mo | Projected Savings: ${total_potential_savings:.2f}/mo"
        )
        lines.append("=" * 115)
        text_out = "\n".join(lines)

    if opts.output_file:
        out_path = Path(opts.output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text_out, encoding="utf-8")
        logger.info("Report written to %s", opts.output_file)
    else:
        print(text_out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
