#!/usr/bin/env python3
"""AWS S3 Multi-Account Inventory & Storage Metrics Collector.

Enumerates S3 buckets across AWS accounts and profiles, retrieving:
- Bucket region and Account ID
- Server-Side Encryption (SSE) configuration
- S3 Versioning state
- Public Access Block configuration
- CloudWatch storage metrics: Total Stored Size (MB/GB) and Object Counts

Exports consolidated security and FinOps inventory to CSV, JSON, or table.
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
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("s3-inventory")


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


def get_bucket_region(s3_client: Any, bucket_name: str) -> str:
    """Resolve bucket region safely."""
    try:
        resp = s3_client.get_bucket_location(Bucket=bucket_name)
        constraint = resp.get("LocationConstraint")
        if not constraint:
            return "us-east-1"
        if constraint == "EU":
            return "eu-west-1"
        return constraint
    except ClientError:
        return "us-east-1"


def get_bucket_security_posture(s3_client: Any, bucket_name: str) -> Dict[str, Any]:
    """Retrieve encryption, versioning, and public access block settings."""
    # 1. Encryption
    encryption = "None"
    try:
        enc_resp = s3_client.get_bucket_encryption(Bucket=bucket_name)
        rules = enc_resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if rules:
            encryption = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "Enabled")
    except ClientError:
        pass

    # 2. Versioning
    versioning = "Disabled"
    try:
        ver_resp = s3_client.get_bucket_versioning(Bucket=bucket_name)
        versioning = ver_resp.get("Status", "Disabled")
    except ClientError:
        pass

    # 3. Public Access Block
    public_blocked = False
    try:
        pab_resp = s3_client.get_public_access_block(Bucket=bucket_name)
        cfg = pab_resp.get("PublicAccessBlockConfiguration", {})
        public_blocked = all([
            cfg.get("BlockPublicAcls", False),
            cfg.get("IgnorePublicAcls", False),
            cfg.get("BlockPublicPolicy", False),
            cfg.get("RestrictPublicBuckets", False),
        ])
    except ClientError:
        pass

    return {
        "encryption": encryption,
        "versioning": versioning,
        "public_access_blocked": public_blocked,
    }


def get_cloudwatch_metrics(session: boto3.Session, bucket_name: str, region: str) -> Tuple[float, int]:
    """Retrieve latest average bucket size and object count from CloudWatch."""
    try:
        cw = session.client("cloudwatch", region_name=region)
        end_time = datetime.datetime.now(datetime.timezone.utc)
        start_time = end_time - datetime.timedelta(days=3)

        metric_resp = cw.get_metric_data(
            MetricDataQueries=[
                {
                    "Id": "bucketSize",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/S3",
                            "MetricName": "BucketSizeBytes",
                            "Dimensions": [
                                {"Name": "BucketName", "Value": bucket_name},
                                {"Name": "StorageType", "Value": "StandardStorage"},
                            ],
                        },
                        "Period": 86400,
                        "Stat": "Average",
                    },
                    "ReturnData": True,
                },
                {
                    "Id": "objectCount",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/S3",
                            "MetricName": "NumberOfObjects",
                            "Dimensions": [
                                {"Name": "BucketName", "Value": bucket_name},
                                {"Name": "StorageType", "Value": "AllStorageTypes"},
                            ],
                        },
                        "Period": 86400,
                        "Stat": "Average",
                    },
                    "ReturnData": True,
                },
            ],
            StartTime=start_time,
            EndTime=end_time,
        )

        size_bytes = 0.0
        num_objects = 0
        for r in metric_resp.get("MetricDataResults", []):
            vals = r.get("Values", [])
            if r["Id"] == "bucketSize" and vals:
                size_bytes = vals[0]
            elif r["Id"] == "objectCount" and vals:
                num_objects = int(vals[0])

        size_mb = size_bytes / (1024 * 1024)
        return round(size_mb, 2), num_objects
    except ClientError:
        return 0.0, 0


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Consolidate S3 bucket inventory, security posture, and storage metrics."
    )
    parser.add_argument("--profiles", help="Comma-separated AWS profiles.")
    parser.add_argument("--profile-pattern", help="Regex pattern to filter AWS profiles.")
    parser.add_argument("--skip-metrics", action="store_true", help="Skip CloudWatch metric lookups for faster execution.")
    parser.add_argument("--format", choices=["table", "csv", "json"], default="table", help="Output format.")
    parser.add_argument("--output-file", help="File path to write report to.")
    return parser.parse_args(args)


def main() -> int:
    opts = parse_args()
    profiles = opts.profiles.split(",") if opts.profiles else get_configured_profiles(opts.profile_pattern)

    inventory: List[Dict[str, Any]] = []

    for profile in profiles:
        logger.info("Scanning S3 buckets for profile: %s", profile)
        try:
            session = boto3.Session(profile_name=profile)
            sts = session.client("sts")
            account_id = sts.get_caller_identity().get("Account", "Unknown")
            s3_client = session.client("s3")

            buckets = s3_client.list_buckets().get("Buckets", [])
            for b in buckets:
                name = b.get("Name", "")
                region = get_bucket_region(s3_client, name)
                posture = get_bucket_security_posture(s3_client, name)

                if opts.skip_metrics:
                    size_mb, count = 0.0, 0
                else:
                    size_mb, count = get_cloudwatch_metrics(session, name, region)

                inventory.append({
                    "account_id": account_id,
                    "profile": profile,
                    "bucket_name": name,
                    "region": region,
                    "encryption": posture["encryption"],
                    "versioning": posture["versioning"],
                    "public_access_blocked": posture["public_access_blocked"],
                    "size_mb": size_mb,
                    "object_count": count,
                })
        except ClientError as e:
            logger.error("Failed querying S3 on profile %s: %s", profile, e)
        except Exception as e:
            logger.error("Unexpected error for profile %s: %s", profile, e)

    # Sort by size descending
    inventory.sort(key=lambda x: x["size_mb"], reverse=True)

    if opts.format == "json":
        text_out = json.dumps({"total_buckets": len(inventory), "buckets": inventory}, indent=2)
    elif opts.format == "csv":
        fieldnames = ["account_id", "profile", "bucket_name", "region", "encryption", "versioning", "public_access_blocked", "size_mb", "object_count"]
        import io
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(inventory)
        text_out = buf.getvalue()
    else:
        lines = [
            "=" * 115,
            f" S3 INVENTORY & STORAGE POSTURE (Found {len(inventory)} buckets)",
            "=" * 115,
            f"{'Account ID':<14} {'Region':<12} {'Encryption':<10} {'Versioning':<10} {'Public Block':<13} {'Size(MB)':<12} {'Objects':<10} {'Bucket Name'}",
            "-" * 115,
        ]
        for b in inventory:
            pub_str = "Yes" if b["public_access_blocked"] else "No"
            lines.append(
                f"{b['account_id']:<14} {b['region']:<12} {b['encryption']:<10} {b['versioning']:<10} "
                f"{pub_str:<13} {b['size_mb']:<12.1f} {b['object_count']:<10} {b['bucket_name']}"
            )
        lines.append("=" * 115)
        text_out = "\n".join(lines)

    if opts.output_file:
        p = Path(opts.output_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text_out, encoding="utf-8")
        logger.info("Inventory saved to %s", opts.output_file)
    else:
        print(text_out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
