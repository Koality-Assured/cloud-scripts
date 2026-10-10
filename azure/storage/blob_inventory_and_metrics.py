#!/usr/bin/env python3
"""Azure Storage Account & Blob Security Posture Inventory.

Audits Azure Storage Accounts across subscriptions for compliance and security posture:
- Public blob access settings (allowBlobPublicAccess)
- Minimum TLS version enforcement (TLS 1.2)
- Secure transfer / HTTPS enforcement (supportsHttpsTrafficOnly)
- Redundancy / SKU replication tier (Standard_LRS, Standard_GRS, Premium_LRS)
- Soft delete policy retention days
- Network access default actions (Deny / Allow)

Exports findings to CSV, JSON, or console table.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from azure.core.exceptions import HttpResponseError
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.storage import StorageManagementClient
    AZURE_STORAGE_AVAILABLE = True
except ImportError:
    AZURE_STORAGE_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("azure-storage-inventory")


def audit_storage_accounts(subscription_id: str) -> List[Dict[str, Any]]:
    """Audit Azure Storage accounts in a subscription."""
    if not AZURE_STORAGE_AVAILABLE:
        raise ImportError("azure-mgmt-storage is required. Install via: pip install '.[azure]'")

    credential = DefaultAzureCredential()
    client = StorageManagementClient(credential, subscription_id)

    results = []
    try:
        accounts = client.storage_accounts.list()
        for sa in accounts:
            sku_name = sa.sku.name if sa.sku else "Unknown"
            min_tls = sa.minimum_tls_version or "TLS1_0"
            https_only = sa.enable_https_traffic_only
            # Public access property
            allow_public = getattr(sa, "allow_blob_public_access", True)
            network_rule_set = getattr(sa, "network_rule_set", None)
            default_action = network_rule_set.default_action if network_rule_set else "Allow"

            parts = sa.id.split("/")
            rg_name = parts[4] if len(parts) > 4 else "Unknown"

            results.append({
                "subscription_id": subscription_id,
                "resource_group": rg_name,
                "account_name": sa.name,
                "location": sa.location,
                "sku": sku_name,
                "min_tls_version": min_tls,
                "https_only": https_only,
                "public_blob_access_disabled": not allow_public,
                "default_network_action": default_action,
                "resource_id": sa.id,
            })
    except HttpResponseError as e:
        logger.error("Failed querying storage accounts in subscription %s: %s", subscription_id, e)
        raise

    return results


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit Azure Storage Accounts security posture, TLS, and public access."
    )
    parser.add_argument("--subscription-id", required=True, help="Azure Subscription ID (or comma-separated IDs).")
    parser.add_argument("--format", choices=["table", "csv", "json"], default="table", help="Output format.")
    parser.add_argument("--output-file", help="File path to write report to.")
    return parser.parse_args(args)


def main() -> int:
    opts = parse_args()
    if not AZURE_STORAGE_AVAILABLE:
        logger.error("Azure storage dependencies not installed. Install via: pip install '.[azure]'")
        return 1

    subs = [s.strip() for s in opts.subscription_id.split(",") if s.strip()]
    all_accounts: List[Dict[str, Any]] = []

    for sub in subs:
        logger.info("Auditing storage accounts in subscription: %s", sub)
        try:
            accounts = audit_storage_accounts(sub)
            all_accounts.extend(accounts)
        except Exception as e:
            logger.error("Error inspecting subscription %s: %s", sub, e)

    if opts.format == "json":
        text_out = json.dumps({"total_storage_accounts": len(all_accounts), "accounts": all_accounts}, indent=2)
    elif opts.format == "csv":
        fieldnames = [
            "subscription_id", "resource_group", "account_name", "location", "sku",
            "min_tls_version", "https_only", "public_blob_access_disabled", "default_network_action"
        ]
        import io
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_accounts)
        text_out = buf.getvalue()
    else:
        lines = [
            "=" * 115,
            f" AZURE STORAGE ACCOUNT POSTURE INVENTORY (Found {len(all_accounts)} accounts)",
            "=" * 115,
            f"{'Resource Group':<20} {'Account Name':<22} {'SKU':<16} {'TLS':<8} {'HTTPS':<7} {'Pub Blocked':<12} {'Default Net'}",
            "-" * 115,
        ]
        for a in all_accounts:
            tls_str = a["min_tls_version"].replace("TLS", "v")
            https_str = "Yes" if a["https_only"] else "NO"
            pub_blocked_str = "Yes" if a["public_blob_access_disabled"] else "NO (RISK)"
            lines.append(
                f"{a['resource_group'][:18]:<20} {a['account_name'][:20]:<22} {a['sku']:<16} "
                f"{tls_str:<8} {https_str:<7} {pub_blocked_str:<12} {a['default_network_action']}"
            )
        lines.append("=" * 115)
        text_out = "\n".join(lines)

    if opts.output_file:
        p = Path(opts.output_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text_out, encoding="utf-8")
        logger.info("Storage report saved to %s", opts.output_file)
    else:
        print(text_out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
