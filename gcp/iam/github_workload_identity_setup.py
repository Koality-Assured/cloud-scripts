#!/usr/bin/env python3
"""GCP Workload Identity Federation Setup for GitHub Actions.

Configures keyless Google Cloud authentication for GitHub Actions CI/CD workflows:
1. Workload Identity Pool (`projects/{project}/locations/global/workloadIdentityPools/{pool_id}`)
2. Workload Identity Provider (OIDC issuer: `https://token.actions.githubusercontent.com`)
   with attribute mappings (`google.subject=assertion.sub`, `attribute.repository=assertion.repository`)
3. Service Account IAM Binding granting `roles/iam.workloadIdentityUser` restricted to the target GitHub repository

Generates the ready-to-use GitHub Actions workflow YAML snippet.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any, Dict, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("gcp-workload-identity")

GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"


def generate_configuration_plan(
    project_id: str,
    project_number: str,
    pool_id: str,
    provider_id: str,
    service_account_email: str,
    github_repo: str,
    attribute_condition: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate configuration plan and resource identifiers for Workload Identity Federation."""
    pool_name = f"projects/{project_number}/locations/global/workloadIdentityPools/{pool_id}"
    provider_name = f"{pool_name}/providers/{provider_id}"
    principal_set = f"principalSet://iam.googleapis.com/{pool_name}/attribute.repository/{github_repo}"

    # gcloud CLI commands to establish the federation
    gcloud_commands = [
        # 1. Create Workload Identity Pool
        f"gcloud iam workload-identity-pools create \"{pool_id}\" "
        f"--project=\"{project_id}\" "
        f"--location=\"global\" "
        f"--display-name=\"GitHub Actions Pool\"",

        # 2. Create Workload Identity Provider
        f"gcloud iam workload-identity-pools providers create-oidc \"{provider_id}\" "
        f"--project=\"{project_id}\" "
        f"--location=\"global\" "
        f"--workload-identity-pool=\"{pool_id}\" "
        f"--display-name=\"GitHub Provider\" "
        f"--issuer-uri=\"{GITHUB_OIDC_ISSUER}\" "
        f"--attribute-mapping=\"google.subject=assertion.sub,attribute.actor=assertion.actor,attribute.repository=assertion.repository,attribute.ref=assertion.ref\""
        + (f" --attribute-condition=\"{attribute_condition}\"" if attribute_condition else ""),

        # 3. Bind Service Account to Workload Identity User
        f"gcloud iam service-accounts add-iam-policy-binding \"{service_account_email}\" "
        f"--project=\"{project_id}\" "
        f"--role=\"roles/iam.workloadIdentityUser\" "
        f"--member=\"{principal_set}\"",
    ]

    # GitHub Actions workflow snippet
    actions_snippet = f"""jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      - id: auth
        uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: '{provider_name}'
          service_account: '{service_account_email}'

      - name: Verify GCP Access
        run: gcloud compute instances list
"""

    return {
        "project_id": project_id,
        "project_number": project_number,
        "pool_name": pool_name,
        "provider_name": provider_name,
        "principal_set": principal_set,
        "gcloud_commands": gcloud_commands,
        "actions_snippet": actions_snippet,
    }


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Plan and setup GCP Workload Identity Federation for GitHub Actions."
    )
    parser.add_argument("--project-id", required=True, help="GCP Project ID.")
    parser.add_argument("--project-number", required=True, help="GCP Project Number (numeric ID).")
    parser.add_argument("--service-account", required=True, help="Target Service Account Email to impersonate.")
    parser.add_argument("--repo", required=True, help="GitHub repository in 'owner/repo' format.")
    parser.add_argument("--pool-id", default="github-actions-pool", help="Workload Identity Pool ID.")
    parser.add_argument("--provider-id", default="github-provider", help="Workload Identity Provider ID.")
    parser.add_argument("--branch", help="Optional branch restriction (e.g. 'main').")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format.")
    return parser.parse_args(args)


def main() -> int:
    opts = parse_args()

    condition = None
    if opts.branch:
        condition = f"assertion.repository == '{opts.repo}' && assertion.ref == 'refs/heads/{opts.branch}'"

    plan = generate_configuration_plan(
        project_id=opts.project_id,
        project_number=opts.project_number,
        pool_id=opts.pool_id,
        provider_id=opts.provider_id,
        service_account_email=opts.service_account,
        github_repo=opts.repo,
        attribute_condition=condition,
    )

    if opts.format == "json":
        print(json.dumps(plan, indent=2))
        return 0

    print("\n" + "=" * 75)
    print(" GCP WORKLOAD IDENTITY FEDERATION FOR GITHUB ACTIONS")
    print("=" * 75)
    print(f"Project ID:         {plan['project_id']} (Number: {plan['project_number']})")
    print(f"Repository:         {opts.repo}")
    print(f"Service Account:    {opts.service_account}")
    print(f"Provider Identifier:\n  {plan['provider_name']}")
    print(f"IAM Principal Set:\n  {plan['principal_set']}")
    print("\n" + "-" * 75)
    print("Execution Setup Commands (Run via gcloud or terraform):")
    print("-" * 75)
    for i, cmd in enumerate(plan["gcloud_commands"], start=1):
        print(f"\n# Step {i}:\n{cmd}")

    print("\n" + "-" * 75)
    print("GitHub Actions CI/CD Workflow Snippet (.github/workflows/deploy.yml):")
    print("-" * 75)
    print(plan["actions_snippet"])
    print("=" * 75)
    return 0


if __name__ == "__main__":
    sys.exit(main())
