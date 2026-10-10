#!/usr/bin/env python3
"""AWS Cost Explorer Service & Usage Breakdown.

Queries AWS Cost Explorer across AWS accounts and profiles for specified services,
usage types, or operations over a dynamic time range.

Exports granular unblended costs and usage amounts to CSV, JSON, or console tables.
Zero hardcoded account IDs, dates, or proprietary paths.
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
logger = logging.getLogger("cost-explorer-breakdown")


def get_default_time_period() -> tuple[str, str]:
    """Calculate the first and last day of the preceding month in YYYY-MM-DD format."""
    today = datetime.date.today()
    first_of_this_month = today.replace(day=1)
    last_of_prev_month = first_of_this_month - datetime.timedelta(days=1)
    first_of_prev_month = last_of_prev_month.replace(day=1)
    return str(first_of_prev_month), str(first_of_this_month)


def get_configured_profiles(pattern: Optional[str] = None) -> List[str]:
    """Discover AWS profiles from ~/.aws/config."""
    config_path = Path(os.path.expanduser("~/.aws/config"))
    if not config_path.exists():
        return ["default"]

    parser = configparser.ConfigParser()
    try:
        parser.read(config_path)
    except Exception as e:
        logger.warning("Could not read AWS config: %s", e)
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


def query_cost_and_usage(
    session: boto3.Session,
    start_date: str,
    end_date: str,
    services: Optional[List[str]] = None,
    group_by: str = "USAGE_TYPE",
) -> List[Dict[str, Any]]:
    """Query AWS Cost Explorer get_cost_and_usage."""
    ce = session.client("ce", region_name="us-east-1")

    filter_dict: Optional[Dict[str, Any]] = None
    if services:
        filter_dict = {
            "Dimensions": {
                "Key": "SERVICE",
                "Values": services,
            }
        }

    group_defs = [{"Type": "DIMENSION", "Key": group_by}]

    kwargs: Dict[str, Any] = {
        "TimePeriod": {"Start": start_date, "End": end_date},
        "Granularity": "MONTHLY",
        "GroupBy": group_defs,
        "Metrics": ["UnblendedCost", "UsageQuantity"],
    }
    if filter_dict:
        kwargs["Filter"] = filter_dict

    records: List[Dict[str, Any]] = []

    while True:
        resp = ce.get_cost_and_usage(**kwargs)
        for time_block in resp.get("ResultsByTime", []):
            period_start = time_block.get("TimePeriod", {}).get("Start")
            period_end = time_block.get("TimePeriod", {}).get("End")
            for group in time_block.get("Groups", []):
                key_value = group.get("Keys", ["Unknown"])[0]
                metrics = group.get("Metrics", {})
                cost_amt = float(metrics.get("UnblendedCost", {}).get("Amount", 0.0))
                usage_qty = float(metrics.get("UsageQuantity", {}).get("Amount", 0.0))

                records.append({
                    "period_start": period_start,
                    "period_end": period_end,
                    "dimension_key": group_by,
                    "dimension_value": key_value,
                    "cost_usd": round(cost_amt, 4),
                    "usage_quantity": round(usage_qty, 4),
                })

        next_token = resp.get("NextPageToken")
        if not next_token:
            break
        kwargs["NextPageToken"] = next_token

    return records


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    def_start, def_end = get_default_time_period()
    parser = argparse.ArgumentParser(
        description="Extract AWS Cost Explorer spend breakdown by usage type or operation."
    )
    parser.add_argument("--profiles", help="Comma-separated AWS profiles.")
    parser.add_argument("--profile-pattern", help="Regex to filter profile names.")
    parser.add_argument("--services", help="Comma-separated services to filter (e.g. 'Amazon CloudWatch,Amazon Simple Storage Service').")
    parser.add_argument("--start-date", default=def_start, help=f"Start date YYYY-MM-DD (default: {def_start}).")
    parser.add_argument("--end-date", default=def_end, help=f"End date YYYY-MM-DD (default: {def_end}).")
    parser.add_argument("--group-by", default="USAGE_TYPE", choices=["USAGE_TYPE", "OPERATION", "SERVICE", "INSTANCE_TYPE"], help="Dimension to group by (default: USAGE_TYPE).")
    parser.add_argument("--format", choices=["table", "csv", "json"], default="table", help="Output format.")
    parser.add_argument("--output-file", help="Path to write output file.")
    return parser.parse_args(args)


def main() -> int:
    opts = parse_args()
    profiles = opts.profiles.split(",") if opts.profiles else get_configured_profiles(opts.profile_pattern)
    services = [s.strip() for s in opts.services.split(",")] if opts.services else None

    all_data: List[Dict[str, Any]] = []

    for profile in profiles:
        logger.info("Querying Cost Explorer for profile: %s", profile)
        try:
            session = boto3.Session(profile_name=profile)
            # Fetch account ID
            sts = session.client("sts")
            account_id = sts.get_caller_identity().get("Account", "Unknown")

            rows = query_cost_and_usage(
                session=session,
                start_date=opts.start_date,
                end_date=opts.end_date,
                services=services,
                group_by=opts.group_by,
            )
            for r in rows:
                r["profile"] = profile
                r["account_id"] = account_id
                all_data.append(r)
        except ClientError as e:
            logger.error("Failed to query profile %s: %s", profile, e)
        except Exception as e:
            logger.error("Unexpected error for profile %s: %s", profile, e)

    # Sort descending by cost
    all_data.sort(key=lambda x: x["cost_usd"], reverse=True)
    total_cost = sum(x["cost_usd"] for x in all_data)

    if opts.format == "json":
        out_payload = {
            "time_period": {"start": opts.start_date, "end": opts.end_date},
            "total_cost_usd": round(total_cost, 2),
            "records": all_data,
        }
        text_out = json.dumps(out_payload, indent=2)
    elif opts.format == "csv":
        fieldnames = ["account_id", "profile", "period_start", "period_end", "dimension_key", "dimension_value", "cost_usd", "usage_quantity"]
        import io
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_data)
        text_out = buf.getvalue()
    else:
        lines = [
            "=" * 105,
            f" AWS COST EXPLORER BREAKDOWN ({opts.start_date} to {opts.end_date})",
            "=" * 105,
            f"{'Account ID':<16} {'Profile':<16} {opts.group_by:<48} {'Cost (USD)':<12} {'Usage Qty'}",
            "-" * 105,
        ]
        for r in all_data[:100]:  # Top 100 in table view
            lines.append(f"{r['account_id']:<16} {r['profile'][:15]:<16} {r['dimension_value'][:46]:<48} ${r['cost_usd']:<11.2f} {r['usage_quantity']}")
        if len(all_data) > 100:
            lines.append(f"... ({len(all_data) - 100} additional records truncated in table view; use --format csv or json for full report)")
        lines.append("=" * 105)
        lines.append(f"TOTAL SPEND: ${total_cost:.2f}")
        lines.append("=" * 105)
        text_out = "\n".join(lines)

    if opts.output_file:
        p = Path(opts.output_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text_out, encoding="utf-8")
        logger.info("Cost report saved to %s", opts.output_file)
    else:
        print(text_out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
