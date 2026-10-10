#!/usr/bin/env python3
"""Azure Entra ID (Azure AD) Federated Credential Setup for GitHub Actions.

Configures keyless OIDC authentication for GitHub Actions CI/CD workflows on Microsoft Azure:
1. Microsoft Entra ID App Registration & Enterprise Application (Service Principal)
2. Federated Identity Credential targeting `https://token.actions.githubusercontent.com`
   with subject claim scoped to `repo:{org}/{repo}:ref:refs/heads/{branch}` or `repo:{org}/{repo}:*`
3. Azure RBAC Role Assignment (e.g. Contributor or Reader) at Subscription or Resource Group scope

Generates the ready-to-use GitHub Actions workflow YAML snippet using `azure/login@v2`.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any, Dict, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("azure-federated-credentials")

GITHUB_ISSUER = "https://token.actions.githubusercontent.com"


def generate_azure_federation_plan(
    app_name: str,
    github_repo: str,
    tenant_id: str,
    subscription_id: str,
    branch: Optional[str] = None,
    environment: Optional[str] = None,
    role_name: str = "Contributor",
    resource_group: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate configuration blueprint and Azure CLI setup commands."""
    if environment:
        subject = f"repo:{github_repo}:environment:{environment}"
        credential_name = f"github-{environment}"
    elif branch:
        subject = f"repo:{github_repo}:ref:refs/heads/{branch}"
        credential_name = f"github-{branch}"
    else:
        subject = f"repo:{github_repo}:*"
        credential_name = "github-all"

    # Define scope
    if resource_group:
        scope = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
    else:
        scope = f"/subscriptions/{subscription_id}"

    az_commands = [
        # 1. Create Entra ID App Registration
        f'APP_ID=$(az ad app create --display-name "{app_name}" --query appId -o tsv)',

        # 2. Create Service Principal
        'az ad sp create --id $APP_ID',

        # 3. Create Federated Identity Credential
        (
            'az ad app federated-credential create --id $APP_ID --parameters \''
            + json.dumps({
                "name": credential_name,
                "issuer": GITHUB_ISSUER,
                "subject": subject,
                "description": f"GitHub Actions OIDC runner for {github_repo}",
                "audiences": ["api://AzureADTokenExchange"],
            })
            + "'"
        ),

        # 4. Assign RBAC Role
        f'az role assignment create --role "{role_name}" --assignee $APP_ID --scope "{scope}"',
    ]

    actions_snippet = f"""jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4

      - name: 'Az CLI login via OIDC'
        uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }} # Application (client) ID
          tenant-id: {tenant_id}
          subscription-id: {subscription_id}

      - name: 'Run Azure CLI script'
        run: az group list -o table
"""

    return {
        "app_name": app_name,
        "github_repo": github_repo,
        "subject_claim": subject,
        "tenant_id": tenant_id,
        "subscription_id": subscription_id,
        "scope": scope,
        "role_name": role_name,
        "azure_cli_commands": az_commands,
        "actions_snippet": actions_snippet,
    }


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Plan and setup Azure Entra ID Federated Credentials for GitHub Actions."
    )
    parser.add_argument("--app-name", required=True, help="Display name for Entra ID App Registration.")
    parser.add_argument("--repo", required=True, help="GitHub repository in 'owner/repo' format.")
    parser.add_argument("--tenant-id", required=True, help="Azure Entra ID Tenant ID.")
    parser.add_argument("--subscription-id", required=True, help="Azure Subscription ID.")
    parser.add_argument("--branch", help="Optional branch restriction (e.g. 'main').")
    parser.add_argument("--environment", help="Optional GitHub Environment name.")
    parser.add_argument("--role", default="Contributor", help="Azure RBAC Role name (default: Contributor).")
    parser.add_argument("--resource-group", help="Optional Resource Group to scope permissions (default: subscription).")
    parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format.")
    return parser.parse_args(args)


def main() -> int:
    opts = parse_args()
    plan = generate_azure_federation_plan(
        app_name=opts.app_name,
        github_repo=opts.repo,
        tenant_id=opts.tenant_id,
        subscription_id=opts.subscription_id,
        branch=opts.branch,
        environment=opts.environment,
        role_name=opts.role,
        resource_group=opts.resource_group,
    )

    if opts.format == "json":
        print(json.dumps(plan, indent=2))
        return 0

    print("\n" + "=" * 75)
    print(" AZURE ENTRA ID FEDERATED CREDENTIALS FOR GITHUB ACTIONS")
    print("=" * 75)
    print(f"Application Name:   {plan['app_name']}")
    print(f"GitHub Repository:  {plan['github_repo']}")
    print(f"Subject Claim:      {plan['subject_claim']}")
    print(f"RBAC Role Scope:    {plan['scope']} ({plan['role_name']})")
    print("\n" + "-" * 75)
    print("Azure CLI Setup Commands:")
    print("-" * 75)
    for cmd in plan["azure_cli_commands"]:
        print(cmd)

    print("\n" + "-" * 75)
    print("GitHub Actions CI/CD Workflow Snippet (.github/workflows/deploy.yml):")
    print("-" * 75)
    print(plan["actions_snippet"])
    print("=" * 75)
    return 0


if __name__ == "__main__":
    sys.exit(main())
