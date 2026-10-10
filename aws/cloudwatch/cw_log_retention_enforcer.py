#!/usr/bin/env python3
"""CloudWatch Log Group Retention Enforcer.

Audits and enforces retention policies on CloudWatch log groups across AWS profiles
and regions to stop unconstrained log storage billing growth.

Safe by default: runs in dry-run mode unless --apply is explicitly specified.
Supports filtering by regex pattern, minimum retention threshold, and batch multi-account runs.
"""

from __future__ import annotations

import argparse
import configparser
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cw-log-retention-enforcer")

VALID_RETENTION_DAYS = [
    1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653
]

STANDARD_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "ca-central-1", "eu-west-1", "eu-west-2", "eu-west-3",
    "eu-central-1", "ap-northeast-1", "ap-northeast-2",
    "ap-southeast-1", "ap-southeast-2", "ap-south-1", "sa-east-1"
]


def get_configured_profiles(pattern: Optional[str] = None) -> List[str]:
    """Discover AWS profiles from ~/.aws/config."""
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


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit and enforce retention policies on CloudWatch log groups."
    )
    parser.add_argument("--profiles", help="Comma-separated AWS CLI profiles (default: auto-discover).")
    parser.add_argument("--profile-pattern", help="Regex pattern to filter AWS profiles.")
    parser.add_argument("--regions", help="Comma-separated regions (default: standard regions).")
    parser.add_argument("--filter-pattern", help="Regex pattern matching target log groups (e.g. 'flowlogs|prisma').")
    parser.add_argument(
        "--retention-days",
        type=int,
        default=30,
        choices=VALID_RETENTION_DAYS,
        help="Target retention in days to apply (default: 30).",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply changes. Without this flag, the script runs in DRY-RUN mode.",
    )
    return parser.parse_args(args)


def main() -> int:
    opts = parse_args()
    profiles = opts.profiles.split(",") if opts.profiles else get_configured_profiles(opts.profile_pattern)
    regions = opts.regions.split(",") if opts.regions else STANDARD_REGIONS

    name_regex = re.compile(opts.filter_pattern, re.IGNORECASE) if opts.filter_pattern else None

    is_dry_run = not opts.apply
    if is_dry_run:
        logger.info("DRY-RUN MODE ACTIVE: No changes will be applied. Use --apply to execute.")

    candidates: List[Dict[str, Any]] = []

    for profile in profiles:
        for region in regions:
            try:
                session = boto3.Session(profile_name=profile, region_name=region)
                logs_client = session.client("logs", region_name=region)

                paginator = logs_client.get_paginator("describe_log_groups")
                for page in paginator.paginate():
                    for lg in page.get("logGroups", []):
                        lg_name = lg.get("logGroupName", "")
                        if name_regex and not name_regex.search(lg_name):
                            continue

                        current_retention = lg.get("retentionInDays", 0)  # 0 indicates 'Never Expire'
                        # Candidate if never expires or current retention > target
                        if current_retention == 0 or current_retention > opts.retention_days:
                            candidates.append({
                                "profile": profile,
                                "region": region,
                                "log_group_name": lg_name,
                                "current_retention": current_retention if current_retention > 0 else "Never",
                                "target_retention": opts.retention_days,
                                "stored_mb": round(lg.get("storedBytes", 0) / (1024 * 1024), 2),
                            })
            except ClientError as e:
                logger.debug("Access error for %s / %s: %s", profile, region, e)
            except Exception as e:
                logger.debug("Unexpected error for %s / %s: %s", profile, region, e)

    print("\n" + "=" * 90)
    print(f" CLOUDWATCH LOG RETENTION AUDIT (Found {len(candidates)} candidate log groups)")
    print("=" * 90)
    print(f"{'Profile':<15} {'Region':<12} {'Current':<10} {'Target':<10} {'Stored(MB)':<12} {'Log Group'}")
    print("-" * 90)
    for c in candidates:
        print(f"{c['profile'][:14]:<15} {c['region']:<12} {str(c['current_retention']):<10} {c['target_retention']:<10} {c['stored_mb']:<12.1f} {c['log_group_name']}")
    print("=" * 90)

    if not candidates:
        logger.info("No log groups require retention adjustment.")
        return 0

    if is_dry_run:
        print(f"\n[DRY RUN] {len(candidates)} log groups would be updated to {opts.retention_days} days retention.")
        print("To apply these changes, re-run with the --apply flag.")
        return 0

    # Apply phase
    logger.info("Applying %d-day retention to %d log groups...", opts.retention_days, len(candidates))
    applied_count = 0
    error_count = 0

    for c in candidates:
        try:
            session = boto3.Session(profile_name=c["profile"], region_name=c["region"])
            logs_client = session.client("logs", region_name=c["region"])
            logs_client.put_retention_policy(
                logGroupName=c["log_group_name"],
                retentionInDays=opts.retention_days,
            )
            applied_count += 1
            logger.info("Updated: [%s/%s] %s -> %d days", c["profile"], c["region"], c["log_group_name"], opts.retention_days)
        except ClientError as e:
            error_count += 1
            logger.error("Failed to update %s: %s", c["log_group_name"], e)

    print(f"\nCompleted: {applied_count} updated successfully, {error_count} failed.")
    return 0 if error_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
