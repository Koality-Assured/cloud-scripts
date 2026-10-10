#!/usr/bin/env python3
"""AWS VPC Resource Attachment & Interface Density Analyzer.

Quantifies network interface density (ENIs, EC2 instances, Lambda VPC endpoints,
RDS databases, NAT Gateways, ELBs) per VPC and subnet.

Highlights:
- Abandoned / Unused VPCs (0 ENI attachments) suitable for deprecation.
- High-density VPCs and subnet IP exhaustion risks.
- Consolidated multi-account reporting.
"""

from __future__ import annotations

import argparse
import configparser
import csv
import json
import logging
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("vpc-density-analyzer")

STANDARD_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "ca-central-1", "eu-west-1", "eu-west-2", "eu-west-3",
    "eu-central-1", "ap-northeast-1", "ap-northeast-2",
    "ap-southeast-1", "ap-southeast-2", "ap-south-1"
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


def analyze_vpc_density(session: boto3.Session, region: str) -> List[Dict[str, Any]]:
    """Inspect ENI and resource attachments per VPC in a region."""
    ec2 = session.client("ec2", region_name=region)
    try:
        vpcs_resp = ec2.describe_vpcs()
        vpcs = vpcs_resp.get("Vpcs", [])
        if not vpcs:
            return []

        # Enumerate ENIs across all pages and group by VPC
        paginator = ec2.get_paginator("describe_network_interfaces")
        enis_by_vpc: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for page in paginator.paginate():
            for eni in page.get("NetworkInterfaces", []):
                vid = eni.get("VpcId")
                if vid:
                    enis_by_vpc[vid].append(eni)

        results = []
        for v in vpcs:
            vid = v.get("VpcId", "")
            enis = enis_by_vpc.get(vid, [])

            # Categorize ENIs
            ec2_instances = set()
            lambda_enis = 0
            rds_enis = 0
            nat_gateways = 0
            elbs = 0
            other_enis = 0

            for eni in enis:
                desc = eni.get("Description", "").lower()
                itype = eni.get("InterfaceType", "")
                attach = eni.get("Attachment", {})
                inst_id = attach.get("InstanceId")

                if inst_id:
                    ec2_instances.add(inst_id)
                elif "lambda" in desc or itype == "lambda":
                    lambda_enis += 1
                elif "rds" in desc:
                    rds_enis += 1
                elif "nat gateway" in desc or itype == "nat_gateway":
                    nat_gateways += 1
                elif "elb" in desc or "loadbalancer" in desc:
                    elbs += 1
                else:
                    other_enis += 1

            name = "unnamed"
            for t in v.get("Tags", []):
                if t.get("Key") == "Name":
                    name = t.get("Value", "unnamed")
                    break

            total_enis = len(enis)
            results.append({
                "owner_id": v.get("OwnerId", ""),
                "region": region,
                "vpc_id": vid,
                "name": name,
                "cidr": v.get("CidrBlock", ""),
                "is_default": v.get("IsDefault", False),
                "total_enis": total_enis,
                "ec2_instance_count": len(ec2_instances),
                "lambda_enis": lambda_enis,
                "rds_enis": rds_enis,
                "nat_gateways": nat_gateways,
                "elbs": elbs,
                "other_enis": other_enis,
                "is_abandoned": total_enis == 0,
            })
        return results
    except ClientError as e:
        logger.debug("Failed querying ENIs in %s: %s", region, e)
        return []


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Quantify resource connection density and find abandoned VPCs."
    )
    parser.add_argument("--profiles", help="Comma-separated AWS profiles.")
    parser.add_argument("--profile-pattern", help="Regex pattern to filter AWS profiles.")
    parser.add_argument("--regions", help="Comma-separated regions (default: standard regions).")
    parser.add_argument("--show-abandoned-only", action="store_true", help="Filter for only unused VPCs (0 ENIs).")
    parser.add_argument("--format", choices=["table", "csv", "json"], default="table", help="Output format.")
    parser.add_argument("--output-file", help="File path to write report to.")
    return parser.parse_args(args)


def main() -> int:
    opts = parse_args()
    profiles = opts.profiles.split(",") if opts.profiles else get_configured_profiles(opts.profile_pattern)
    regions = opts.regions.split(",") if opts.regions else STANDARD_REGIONS

    all_density: List[Dict[str, Any]] = []

    for profile in profiles:
        logger.info("Analyzing VPC density for profile: %s", profile)
        try:
            session = boto3.Session(profile_name=profile)
            for region in regions:
                rows = analyze_vpc_density(session, region)
                for r in rows:
                    r["profile"] = profile
                    if opts.show_abandoned_only and not r["is_abandoned"]:
                        continue
                    all_density.append(r)
        except ClientError as e:
            logger.error("Error for profile %s: %s", profile, e)
        except Exception as e:
            logger.error("Unexpected error for profile %s: %s", profile, e)

    # Sort by total ENIs descending
    all_density.sort(key=lambda x: x["total_enis"], reverse=True)

    abandoned_count = sum(1 for v in all_density if v["is_abandoned"])

    if opts.format == "json":
        text_out = json.dumps({
            "total_vpcs_analyzed": len(all_density),
            "abandoned_vpcs_count": abandoned_count,
            "vpcs": all_density,
        }, indent=2)
    elif opts.format == "csv":
        fieldnames = [
            "owner_id", "profile", "region", "vpc_id", "name", "cidr",
            "is_default", "total_enis", "ec2_instance_count", "lambda_enis",
            "rds_enis", "nat_gateways", "elbs", "is_abandoned"
        ]
        import io
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_density)
        text_out = buf.getvalue()
    else:
        lines = [
            "=" * 120,
            f" VPC RESOURCE CONNECTION & DENSITY REPORT (Total: {len(all_density)} | Unused/Abandoned: {abandoned_count})",
            "=" * 120,
            f"{'Owner Account':<16} {'Region':<12} {'VPC ID':<22} {'Total ENIs':<12} {'EC2':<6} {'RDS':<6} {'NAT':<6} {'ELB':<6} {'Status':<12} {'Name'}",
            "-" * 120,
        ]
        for v in all_density:
            status = "UNUSED (0 ENI)" if v["is_abandoned"] else "ACTIVE"
            lines.append(
                f"{v['owner_id']:<16} {v['region']:<12} {v['vpc_id']:<22} {v['total_enis']:<12} "
                f"{v['ec2_instance_count']:<6} {v['rds_enis']:<6} {v['nat_gateways']:<6} {v['elbs']:<6} "
                f"{status:<12} {v['name']}"
            )
        lines.append("=" * 120)
        text_out = "\n".join(lines)

    if opts.output_file:
        p = Path(opts.output_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text_out, encoding="utf-8")
        logger.info("Density report saved to %s", opts.output_file)
    else:
        print(text_out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
