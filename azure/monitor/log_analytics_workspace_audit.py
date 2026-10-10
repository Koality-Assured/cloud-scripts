#!/usr/bin/env python3
"""Azure Log Analytics Workspace Retention & Cost Auditor.

Audits Azure Log Analytics Workspaces across subscriptions, evaluating:
- Data retention periods (retentionInDays)
- Daily volume ingestion caps (dailyQuotaGb)
- Workspace pricing tier / SKU
- Public network access and security settings
- Opportunities for storage cost reduction

Supports dry-run preview and policy updates.
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
    from azure.mgmt.loganalytics import LogAnalyticsManagementClient
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("azure-loganalytics-audit")


def audit_workspaces(subscription_id: str, target_retention_days: int = 30) -> List[Dict[str, Any]]:
    """Audit Log Analytics Workspaces in an Azure subscription."""
    if not AZURE_AVAILABLE:
        raise ImportError("azure-mgmt-loganalytics and azure-identity are required. Install via: pip install '.[azure]'")

    credential = DefaultAzureCredential()
    client = LogAnalyticsManagementClient(credential, subscription_id)

    results = []
    try:
        workspaces = client.workspaces.list()
        for w in workspaces:
            sku_name = w.sku.name if w.sku else "Unknown"
            current_retention = w.retention_in_days or 30
            daily_quota = w.workspace_capping.daily_quota_gb if w.workspace_capping else -1

            # Extract resource group from Azure resource ID
            parts = w.id.split("/")
            rg_name = parts[4] if len(parts) > 4 else "Unknown"

            needs_update = current_retention > target_retention_days

            results.append({
                "subscription_id": subscription_id,
                "resource_group": rg_name,
                "workspace_name": w.name,
                "location": w.location,
                "sku": sku_name,
                "current_retention_days": current_retention,
                "target_retention_days": target_retention_days,
                "daily_quota_gb": daily_quota if daily_quota != -1 else "Unlimited",
                "public_network_access": getattr(w, "public_network_access_for_ingestion", "Enabled"),
                "needs_update": needs_update,
                "resource_id": w.id,
            })
    except HttpResponseError as e:
        logger.error("Failed querying workspaces in subscription %s: %s", subscription_id, e)
        raise

    return results


def update_workspace_retention(
    subscription_id: str,
    resource_group: str,
    workspace_name: str,
    retention_days: int,
) -> bool:
    """Update workspace retention policy."""
    if not AZURE_AVAILABLE:
        return False
    credential = DefaultAzureCredential()
    client = LogAnalyticsManagementClient(credential, subscription_id)
    try:
        patch_payload = {"retention_in_days": retention_days}
        client.workspaces.update(resource_group, workspace_name, patch_payload)
        logger.info("Updated %s retention to %d days", workspace_name, retention_days)
        return True
    except HttpResponseError as e:
        logger.error("Failed updating %s: %s", workspace_name, e)
        return False


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit and optimize Azure Log Analytics Workspace retention and daily caps."
    )
    parser.add_argument("--subscription-id", required=True, help="Azure Subscription ID (or comma-separated IDs).")
    parser.add_argument("--target-retention", type=int, default=30, help="Target retention in days (default: 30).")
    parser.add_argument("--apply", action="store_true", help="Apply retention changes (default: DRY-RUN).")
    parser.add_argument("--format", choices=["table", "csv", "json"], default="table", help="Output format.")
    parser.add_argument("--output-file", help="File path to write report to.")
    return parser.parse_args(args)


def main() -> int:
    opts = parse_args()
    if not AZURE_AVAILABLE:
        logger.error("Azure dependencies not installed. Install with: pip install '.[azure]'")
        return 1

    subscriptions = [s.strip() for s in opts.subscription_id.split(",") if s.strip()]
    all_workspaces: List[Dict[str, Any]] = []

    for sub in subscriptions:
        logger.info("Auditing Log Analytics in subscription: %s", sub)
        try:
            ws_list = audit_workspaces(sub, target_retention_days=opts.target_retention)
            all_workspaces.extend(ws_list)
        except Exception as e:
            logger.error("Error inspecting subscription %s: %s", sub, e)

    candidate_count = sum(1 for w in all_workspaces if w["needs_update"])

    if opts.format == "json":
        text_out = json.dumps({
            "total_workspaces": len(all_workspaces),
            "candidates_for_optimization": candidate_count,
            "workspaces": all_workspaces,
        }, indent=2)
    elif opts.format == "csv":
        fieldnames = [
            "subscription_id", "resource_group", "workspace_name", "location",
            "sku", "current_retention_days", "target_retention_days", "daily_quota_gb", "needs_update"
        ]
        import io
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_workspaces)
        text_out = buf.getvalue()
    else:
        lines = [
            "=" * 115,
            f" AZURE LOG ANALYTICS WORKSPACE AUDIT (Total: {len(all_workspaces)} | Optimization Candidates: {candidate_count})",
            "=" * 115,
            f"{'Subscription':<16} {'Resource Group':<20} {'Workspace Name':<24} {'SKU':<14} {'Current':<9} {'Target':<8} {'Status'}",
            "-" * 115,
        ]
        for w in all_workspaces:
            status = "NEEDS_OPTIMIZATION" if w["needs_update"] else "OK"
            lines.append(
                f"{w['subscription_id'][:14]:<16} {w['resource_group'][:18]:<20} "
                f"{w['workspace_name'][:22]:<24} {w['sku']:<14} {w['current_retention_days']:<9} "
                f"{w['target_retention_days']:<8} {status}"
            )
        lines.append("=" * 115)
        text_out = "\n".join(lines)

    if opts.output_file:
        p = Path(opts.output_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text_out, encoding="utf-8")
        logger.info("Report saved to %s", opts.output_file)
    else:
        print(text_out)

    if candidate_count > 0:
        if not opts.apply:
            print(f"\n[DRY RUN] {candidate_count} workspaces can be optimized to {opts.target_retention} days retention.")
            print("To apply changes, re-run with --apply.")
        else:
            logger.info("Applying retention updates to %d workspaces...", candidate_count)
            success = 0
            for w in all_workspaces:
                if w["needs_update"]:
                    if update_workspace_retention(w["subscription_id"], w["resource_group"], w["workspace_name"], opts.target_retention):
                        success += 1
            print(f"\nApplied updates to {success}/{candidate_count} workspaces.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
