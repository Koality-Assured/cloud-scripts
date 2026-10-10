#!/usr/bin/env python3
"""AWS SSO CLI Profile Generator.

Generates structured AWS CLI SSO configuration profiles (~/.aws/config) from:
1. AWS Organizations API (dynamically discovering all active accounts and names)
2. CSV or JSON account manifest file
3. Explicit list of Account IDs

Safely preserves existing non-SSO profiles, formats SSO token scopes, and supports
custom profile naming schemes and multiple IAM roles per account.
"""

from __future__ import annotations

import argparse
import configparser
import csv
import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("generate-sso-config")


def get_accounts_from_org(profile: Optional[str] = None, region: str = "us-east-1") -> List[Dict[str, str]]:
    """Query AWS Organizations list_accounts for all active accounts."""
    session = boto3.Session(profile_name=profile, region_name=region)
    org_client = session.client("organizations")
    accounts = []
    try:
        paginator = org_client.get_paginator("list_accounts")
        for page in paginator.paginate():
            for acct in page.get("Accounts", []):
                if acct.get("Status") == "ACTIVE":
                    accounts.append({
                        "id": str(acct.get("Id")),
                        "name": acct.get("Name", "unnamed").replace(" ", "-"),
                    })
    except ClientError as e:
        logger.error("Failed to list accounts from AWS Organizations: %s", e)
        raise
    return accounts


def load_accounts_from_file(file_path: str) -> List[Dict[str, str]]:
    """Load account IDs and names from CSV or JSON file."""
    p = Path(file_path)
    if not p.exists():
        raise FileNotFoundError(f"Accounts file not found: {file_path}")

    accounts = []
    if p.suffix.lower() == ".json":
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    accounts.append({"id": str(item.get("id")), "name": str(item.get("name", item.get("id")))})
                else:
                    accounts.append({"id": str(item), "name": str(item)})
    else:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Find ID and Name keys flexibly
                aid = row.get("id") or row.get("AccountId") or row.get("account_id") or list(row.values())[0]
                aname = row.get("name") or row.get("AccountName") or row.get("account_name") or aid
                accounts.append({"id": str(aid).strip(), "name": str(aname).strip()})
    return accounts


def build_sso_config(
    accounts: List[Dict[str, str]],
    sso_session_name: str,
    sso_start_url: str,
    sso_region: str,
    roles: List[str],
    profile_format: str = "{role}-{account_id}",
    existing_config_path: Optional[Path] = None,
) -> configparser.ConfigParser:
    """Build or update configparser instance with SSO profiles."""
    config = configparser.ConfigParser()
    if existing_config_path and existing_config_path.exists():
        try:
            config.read(existing_config_path)
        except Exception as e:
            logger.warning("Could not parse existing config, creating fresh: %s", e)

    # Configure SSO Session
    session_section = f"sso-session {sso_session_name}"
    config[session_section] = {
        "sso_start_url": sso_start_url,
        "sso_region": sso_region,
        "sso_registration_scopes": "sso:account:access",
    }

    # Generate Profile Sections
    for acct in accounts:
        aid = acct["id"]
        aname = acct.get("name", aid)
        for role in roles:
            profile_name = profile_format.format(role=role, account_id=aid, account_name=aname)
            section_key = f"profile {profile_name}"
            config[section_key] = {
                "sso_session": sso_session_name,
                "sso_account_id": aid,
                "sso_role_name": role,
                "region": sso_region,
                "output": "json",
            }

    return config


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate ~/.aws/config SSO profiles dynamically or from account list."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--from-org", action="store_true", help="Auto-discover accounts from AWS Organizations API.")
    group.add_argument("--accounts-file", help="Path to CSV or JSON file containing accounts.")
    group.add_argument("--account-ids", help="Comma-separated list of AWS Account IDs.")

    parser.add_argument("--sso-start-url", required=True, help="AWS IAM Identity Center (SSO) Start URL.")
    parser.add_argument("--sso-region", default="us-east-1", help="SSO Region (default: us-east-1).")
    parser.add_argument("--sso-session-name", default="my-sso", help="SSO session name identifier.")
    parser.add_argument("--roles", default="Viewer,Admin", help="Comma-separated role names (default: Viewer,Admin).")
    parser.add_argument(
        "--profile-format",
        default="{role}-{account_id}",
        help="Profile naming template (variables: {role}, {account_id}, {account_name}).",
    )
    parser.add_argument("--org-profile", help="AWS CLI profile with permission to call organizations:ListAccounts.")
    parser.add_argument("--write-to-aws-config", action="store_true", help="Directly update ~/.aws/config.")
    parser.add_argument("--output-file", help="Custom path to output generated config.")
    parser.add_argument("--dry-run", action="store_true", help="Print generated config without writing to disk.")
    return parser.parse_args(args)


def main() -> int:
    opts = parse_args()

    # 1. Collect accounts
    if opts.from_org:
        logger.info("Discovering accounts from AWS Organizations...")
        accounts = get_accounts_from_org(profile=opts.org_profile, region=opts.sso_region)
    elif opts.accounts_file:
        logger.info("Loading accounts from %s...", opts.accounts_file)
        accounts = load_accounts_from_file(opts.accounts_file)
    else:
        accounts = [{"id": aid.strip(), "name": aid.strip()} for aid in opts.account_ids.split(",") if aid.strip()]

    logger.info("Loaded %d accounts for SSO configuration.", len(accounts))
    roles = [r.strip() for r in opts.roles.split(",") if r.strip()]

    target_path: Optional[Path] = None
    if opts.write_to_aws_config:
        target_path = Path(os.path.expanduser("~/.aws/config"))
    elif opts.output_file:
        target_path = Path(opts.output_file)

    config = build_sso_config(
        accounts=accounts,
        sso_session_name=opts.sso_session_name,
        sso_start_url=opts.sso_start_url,
        sso_region=opts.sso_region,
        roles=roles,
        profile_format=opts.profile_format,
        existing_config_path=target_path if (target_path and target_path.exists()) else None,
    )

    import io
    buf = io.StringIO()
    config.write(buf)
    content = buf.getvalue()

    if opts.dry_run or not target_path:
        print("\n" + "=" * 70)
        print(" GENERATED AWS SSO CONFIGURATION PREVIEW")
        print("=" * 70)
        # Print first few sections and total count
        sections = config.sections()
        print(f"Total Sections Generated: {len(sections)} ({len(accounts)} accounts x {len(roles)} roles + 1 sso-session)")
        print("\nSample Preview:")
        for s in sections[:6]:
            print(f"[{s}]")
            for k, v in config[s].items():
                print(f"{k} = {v}")
            print()
        if len(sections) > 6:
            print(f"... and {len(sections) - 6} more sections.")
        print("=" * 70)
        if not target_path and not opts.dry_run:
            print("Specify --write-to-aws-config or --output-file to save.")
        return 0

    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(content, encoding="utf-8")
    logger.info("SSO configuration successfully written to %s (%d sections).", target_path, len(config.sections()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
