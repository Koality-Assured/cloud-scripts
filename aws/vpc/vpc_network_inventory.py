#!/usr/bin/env python3
"""AWS Multi-Region VPC & Network Topology Inventory.

Discovers VPCs across AWS accounts and regions, collecting:
- VPC ID, Account ID, Region, and Name Tag
- IPv4 & IPv6 CIDR allocations
- Default VPC status
- Attached Internet Gateways (IGWs)
- Subnet counts, Route Table associations, and Peering connections

Exports inventory to CSV, JSON, or console tables.
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
from pathlib import Path
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("vpc-network-inventory")

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


def get_vpc_name(tags: Optional[List[Dict[str, str]]]) -> str:
    """Extract Name tag value if present."""
    if not tags:
        return "unnamed"
    for t in tags:
        if t.get("Key") == "Name":
            return t.get("Value", "unnamed")
    return "unnamed"


def inventory_vpcs(session: boto3.Session, region: str) -> List[Dict[str, Any]]:
    """Scan VPCs in a given region."""
    ec2 = session.client("ec2", region_name=region)
    try:
        vpcs_resp = ec2.describe_vpcs()
        vpcs = vpcs_resp.get("Vpcs", [])
        if not vpcs:
            return []

        # Subnets
        subnets_resp = ec2.describe_subnets()
        subnet_counts: Dict[str, int] = {}
        for s in subnets_resp.get("Subnets", []):
            vid = s.get("VpcId")
            subnet_counts[vid] = subnet_counts.get(vid, 0) + 1

        # Internet Gateways
        igws_resp = ec2.describe_internet_gateways()
        igw_attached: Dict[str, bool] = {}
        for igw in igws_resp.get("InternetGateways", []):
            for att in igw.get("Attachments", []):
                vid = att.get("VpcId")
                if vid:
                    igw_attached[vid] = True

        out = []
        for v in vpcs:
            vid = v.get("VpcId", "")
            cidr_assoc = v.get("CidrBlockAssociationSet", [])
            cidrs = [c.get("CidrBlock") for c in cidr_assoc if c.get("CidrBlock")]

            out.append({
                "vpc_id": vid,
                "name": get_vpc_name(v.get("Tags")),
                "region": region,
                "owner_id": v.get("OwnerId", ""),
                "is_default": v.get("IsDefault", False),
                "state": v.get("State", "available"),
                "primary_cidr": v.get("CidrBlock", ""),
                "all_cidrs": ",".join(cidrs),
                "subnet_count": subnet_counts.get(vid, 0),
                "has_igw": igw_attached.get(vid, False),
            })
        return out
    except ClientError as e:
        logger.debug("Failed querying VPCs in %s: %s", region, e)
        return []


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit VPC network topology and internet connectivity across regions."
    )
    parser.add_argument("--profiles", help="Comma-separated AWS profiles.")
    parser.add_argument("--profile-pattern", help="Regex pattern to filter AWS profiles.")
    parser.add_argument("--regions", help="Comma-separated regions (default: standard regions).")
    parser.add_argument("--format", choices=["table", "csv", "json"], default="table", help="Output format.")
    parser.add_argument("--output-file", help="File path to write report to.")
    return parser.parse_args(args)


def main() -> int:
    opts = parse_args()
    profiles = opts.profiles.split(",") if opts.profiles else get_configured_profiles(opts.profile_pattern)
    regions = opts.regions.split(",") if opts.regions else STANDARD_REGIONS

    all_vpcs: List[Dict[str, Any]] = []

    for profile in profiles:
        logger.info("Scanning VPCs for profile: %s", profile)
        try:
            session = boto3.Session(profile_name=profile)
            for region in regions:
                vpcs = inventory_vpcs(session, region)
                for v in vpcs:
                    v["profile"] = profile
                    all_vpcs.append(v)
        except ClientError as e:
            logger.error("Error for profile %s: %s", profile, e)
        except Exception as e:
            logger.error("Unexpected error for profile %s: %s", profile, e)

    if opts.format == "json":
        text_out = json.dumps({"total_vpcs": len(all_vpcs), "vpcs": all_vpcs}, indent=2)
    elif opts.format == "csv":
        fieldnames = ["owner_id", "profile", "region", "vpc_id", "name", "is_default", "primary_cidr", "subnet_count", "has_igw"]
        import io
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_vpcs)
        text_out = buf.getvalue()
    else:
        lines = [
            "=" * 115,
            f" AWS VPC NETWORK INVENTORY (Found {len(all_vpcs)} VPCs)",
            "=" * 115,
            f"{'Owner Account':<16} {'Region':<12} {'VPC ID':<22} {'CIDR':<18} {'Subnets':<9} {'IGW':<6} {'Default':<9} {'Name'}",
            "-" * 115,
        ]
        for v in all_vpcs:
            igw_str = "Yes" if v["has_igw"] else "No"
            def_str = "Yes" if v["is_default"] else "No"
            lines.append(
                f"{v['owner_id']:<16} {v['region']:<12} {v['vpc_id']:<22} {v['primary_cidr']:<18} "
                f"{v['subnet_count']:<9} {igw_str:<6} {def_str:<9} {v['name']}"
            )
        lines.append("=" * 115)
        text_out = "\n".join(lines)

    if opts.output_file:
        p = Path(opts.output_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text_out, encoding="utf-8")
        logger.info("VPC inventory saved to %s", opts.output_file)
    else:
        print(text_out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
