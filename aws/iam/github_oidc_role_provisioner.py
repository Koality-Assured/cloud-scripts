#!/usr/bin/env python3
"""AWS IAM GitHub Actions OIDC Role Provisioner.

Sets up GitHub Actions OpenID Connect (OIDC) authentication in AWS IAM.
Eliminates long-lived AWS access keys in CI/CD by creating or updating an IAM role
trusting GitHub's OIDC identity provider (`token.actions.githubusercontent.com`)
with repository, branch, or environment subject conditions.

Supports dry-run preview, policy attachments (managed or inline JSON), and custom session duration.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("github-oidc-provisioner")

GITHUB_OIDC_URL = "https://token.actions.githubusercontent.com"
GITHUB_AUDIENCE = "sts.amazonaws.com"
# GitHub Actions thumbprints (historical thumbprint list)
GITHUB_THUMBPRINTS = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c58a3a8518e8759bf075b76b750d4f8d264fcd9",
]


def ensure_oidc_provider(iam_client: Any, session: Optional[boto3.Session] = None, dry_run: bool = False) -> str:
    """Ensure GitHub Actions OIDC provider exists, creating it if needed."""
    try:
        providers = iam_client.list_open_id_connect_providers().get("OpenIDConnectProviderList", [])
        for p in providers:
            arn = p.get("Arn", "")
            if GITHUB_OIDC_URL.replace("https://", "") in arn:
                logger.info("Found existing GitHub OIDC provider: %s", arn)
                return arn
    except ClientError as e:
        logger.error("Failed to list OIDC providers: %s", e)
        raise

    if dry_run:
        account_id = "123456789012"
        if session:
            try:
                account_id = session.client("sts").get_caller_identity().get("Account", account_id)
            except Exception:
                pass
        logger.info("[DRY RUN] Would create OpenID Connect Provider for %s", GITHUB_OIDC_URL)
        return f"arn:aws:iam::{account_id}:oidc-provider/{GITHUB_OIDC_URL.replace('https://', '')}"

    logger.info("Creating new OpenID Connect Provider for %s...", GITHUB_OIDC_URL)
    resp = iam_client.create_open_id_connect_provider(
        Url=GITHUB_OIDC_URL,
        ClientIDList=[GITHUB_AUDIENCE],
        ThumbprintList=GITHUB_THUMBPRINTS,
    )
    arn = resp["OpenIDConnectProviderArn"]
    logger.info("Created OIDC provider: %s", arn)
    return arn


def build_trust_policy(
    oidc_arn: str,
    repo: str,
    branch: Optional[str] = None,
    environment: Optional[str] = None,
) -> Dict[str, Any]:
    """Construct least-privilege assume role trust policy for GitHub Actions."""
    if environment:
        sub_condition = f"repo:{repo}:environment:{environment}"
    elif branch:
        sub_condition = f"repo:{repo}:ref:refs/heads/{branch}"
    else:
        sub_condition = f"repo:{repo}:*"

    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": oidc_arn
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        f"{GITHUB_OIDC_URL.replace('https://', '')}:aud": GITHUB_AUDIENCE
                    },
                    "StringLike": {
                        f"{GITHUB_OIDC_URL.replace('https://', '')}:sub": sub_condition
                    },
                },
            }
        ],
    }


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Provision AWS IAM Role for GitHub Actions OIDC federation."
    )
    parser.add_argument("--role-name", required=True, help="IAM Role Name to create/update.")
    parser.add_argument("--repo", required=True, help="GitHub repository in 'owner/repo' format (supports wildcards e.g. 'org/*').")
    parser.add_argument("--branch", help="Optional specific branch to restrict (e.g. 'main').")
    parser.add_argument("--environment", help="Optional GitHub Environment name to restrict (e.g. 'production').")
    parser.add_argument("--policy-arn", help="Managed policy ARN to attach (e.g. 'arn:aws:iam::aws:policy/AdministratorAccess').")
    parser.add_argument("--policy-file", help="Path to custom JSON IAM policy document to attach inline.")
    parser.add_argument("--session-duration", type=int, default=3600, help="Max session duration in seconds (default: 3600).")
    parser.add_argument("--profile", help="AWS CLI profile name.")
    parser.add_argument("--region", default="us-east-1", help="AWS Region (default: us-east-1).")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply changes. Without this flag, the script runs in DRY-RUN mode.",
    )
    return parser.parse_args(args)


def main() -> int:
    opts = parse_args()
    session = boto3.Session(profile_name=opts.profile, region_name=opts.region)
    iam = session.client("iam")

    is_dry_run = not opts.apply
    if is_dry_run:
        logger.info("DRY-RUN MODE ACTIVE: No changes will be applied. Use --apply to execute.")

    logger.info("Initializing OIDC role provisioning for repo: %s", opts.repo)

    oidc_arn = ensure_oidc_provider(iam, session=session, dry_run=is_dry_run)
    trust_policy = build_trust_policy(
        oidc_arn=oidc_arn,
        repo=opts.repo,
        branch=opts.branch,
        environment=opts.environment,
    )
    trust_policy_str = json.dumps(trust_policy, indent=2)

    print("\n--- Trust Policy ---")
    print(trust_policy_str)

    if is_dry_run:
        print(f"\n[DRY RUN] Role '{opts.role_name}' would be created/updated with the above trust policy.")
        print("To apply these changes, re-run with the --apply flag.")
        return 0

    # Create or update IAM role
    try:
        role_resp = iam.get_role(RoleName=opts.role_name)
        role_arn = role_resp["Role"]["Arn"]
        logger.info("Role '%s' exists. Updating assume role trust policy...", opts.role_name)
        iam.update_assume_role_policy(
            RoleName=opts.role_name,
            PolicyDocument=trust_policy_str,
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            logger.info("Creating new IAM role '%s'...", opts.role_name)
            create_resp = iam.create_role(
                RoleName=opts.role_name,
                AssumeRolePolicyDocument=trust_policy_str,
                Description=f"GitHub Actions runner role for {opts.repo}",
                MaxSessionDuration=opts.session_duration,
            )
            role_arn = create_resp["Role"]["Arn"]
        else:
            logger.error("Failed querying role: %s", e)
            return 1

    # Attach Managed Policy
    if opts.policy_arn:
        logger.info("Attaching managed policy: %s", opts.policy_arn)
        iam.attach_role_policy(
            RoleName=opts.role_name,
            PolicyArn=opts.policy_arn,
        )

    # Attach Inline Policy from File
    if opts.policy_file:
        p_path = Path(opts.policy_file)
        if not p_path.exists():
            logger.error("Policy file not found: %s", opts.policy_file)
            return 1
        inline_policy_doc = p_path.read_text(encoding="utf-8")
        policy_name = f"{opts.role_name}-inline-policy"
        logger.info("Attaching inline policy '%s' from %s", policy_name, opts.policy_file)
        iam.put_role_policy(
            RoleName=opts.role_name,
            PolicyName=policy_name,
            PolicyDocument=inline_policy_doc,
        )

    print("\n" + "=" * 65)
    print(" GITHUB ACTIONS OIDC ROLE PROVISIONED")
    print("=" * 65)
    print(f"Role Name:     {opts.role_name}")
    print(f"Role ARN:      {role_arn}")
    print(f"Repository:    {opts.repo}")
    print("\nGitHub Actions Workflow Snippet:")
    print("---------------------------------")
    print("jobs:")
    print("  deploy:")
    print("    runs-on: ubuntu-latest")
    print("    permissions:")
    print("      id-token: write")
    print("      contents: read")
    print("    steps:")
    print("      - uses: actions/checkout@v4")
    print("      - uses: aws-actions/configure-aws-credentials@v4")
    print("        with:")
    print(f"          role-to-assume: {role_arn}")
    print(f"          aws-region: {opts.region}")
    print("=" * 65)

    return 0


if __name__ == "__main__":
    sys.exit(main())
