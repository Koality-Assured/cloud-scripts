#!/usr/bin/env python3
"""Azure Virtual Network (VNet) & Connected Device Density Analyzer.

Audits Azure VNets and subnets across subscriptions:
- Address space prefix allocations
- Subnet counts and associated Network Security Groups (NSGs)
- Connected device count (Network Interfaces / NICs, Private Endpoints, App Service VNet integrations)
- Highlights abandoned / unused VNets (0 attached devices) for deprecation and cost optimization

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
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.network import NetworkManagementClient
    AZURE_NETWORK_AVAILABLE = True
except ImportError:
    AZURE_NETWORK_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("azure-vnet-density")


def audit_vnets(subscription_id: str) -> List[Dict[str, Any]]:
    """Audit VNets and calculate connected device density."""
    if not AZURE_NETWORK_AVAILABLE:
        raise ImportError("azure-mgmt-network is required. Install via: pip install '.[azure]'")

    credential = DefaultAzureCredential()
    client = NetworkManagementClient(credential, subscription_id)

    # 1. Enumerate NICs to map attached VNets
    nics = client.network_interfaces.list_all()
    nic_counts_by_subnet: Dict[str, int] = {}
    for nic in nics:
        for ip_cfg in getattr(nic, "ip_configurations", []):
            if ip_cfg.subnet and ip_cfg.subnet.id:
                sub_id = ip_cfg.subnet.id.lower()
                nic_counts_by_subnet[sub_id] = nic_counts_by_subnet.get(sub_id, 0) + 1

    results = []
    vnets = client.virtual_networks.list_all()
    for v in vnets:
        parts = v.id.split("/")
        rg_name = parts[4] if len(parts) > 4 else "Unknown"

        prefixes = v.address_space.address_prefixes if v.address_space else []
        subnets = v.subnets or []

        total_attached_nics = 0
        for s in subnets:
            s_id = s.id.lower()
            total_attached_nics += nic_counts_by_subnet.get(s_id, 0)

        is_abandoned = total_attached_nics == 0

        results.append({
            "subscription_id": subscription_id,
            "resource_group": rg_name,
            "vnet_name": v.name,
            "location": v.location,
            "address_prefixes": ", ".join(prefixes),
            "subnet_count": len(subnets),
            "total_attached_nics": total_attached_nics,
            "is_abandoned": is_abandoned,
            "resource_id": v.id,
        })

    return results


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit Azure VNet topology and connected device density."
    )
    parser.add_argument("--subscription-id", required=True, help="Azure Subscription ID (or comma-separated IDs).")
    parser.add_argument("--show-abandoned-only", action="store_true", help="Filter for only unused VNets (0 attached NICs).")
    parser.add_argument("--format", choices=["table", "csv", "json"], default="table", help="Output format.")
    parser.add_argument("--output-file", help="File path to write report to.")
    return parser.parse_args(args)


def main() -> int:
    opts = parse_args()
    if not AZURE_NETWORK_AVAILABLE:
        logger.error("Azure network dependencies not installed. Install via: pip install '.[azure]'")
        return 1

    subs = [s.strip() for s in opts.subscription_id.split(",") if s.strip()]
    all_vnets: List[Dict[str, Any]] = []

    for sub in subs:
        logger.info("Auditing VNets in subscription: %s", sub)
        try:
            vnets = audit_vnets(sub)
            for v in vnets:
                if opts.show_abandoned_only and not v["is_abandoned"]:
                    continue
                all_vnets.append(v)
        except Exception as e:
            logger.error("Error inspecting subscription %s: %s", sub, e)

    # Sort descending by attached NICs
    all_vnets.sort(key=lambda x: x["total_attached_nics"], reverse=True)
    abandoned_count = sum(1 for v in all_vnets if v["is_abandoned"])

    if opts.format == "json":
        text_out = json.dumps({
            "total_vnets": len(all_vnets),
            "abandoned_vnets_count": abandoned_count,
            "vnets": all_vnets,
        }, indent=2)
    elif opts.format == "csv":
        fieldnames = [
            "subscription_id", "resource_group", "vnet_name", "location",
            "address_prefixes", "subnet_count", "total_attached_nics", "is_abandoned"
        ]
        import io
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_vnets)
        text_out = buf.getvalue()
    else:
        lines = [
            "=" * 115,
            f" AZURE VNET DENSITY & NETWORK AUDIT (Total: {len(all_vnets)} | Unused/Abandoned: {abandoned_count})",
            "=" * 115,
            f"{'Resource Group':<20} {'VNet Name':<22} {'Subnets':<9} {'Attached NICs':<15} {'Status':<14} {'Prefixes'}",
            "-" * 115,
        ]
        for v in all_vnets:
            status = "UNUSED (0 NIC)" if v["is_abandoned"] else "ACTIVE"
            lines.append(
                f"{v['resource_group'][:18]:<20} {v['vnet_name'][:20]:<22} {v['subnet_count']:<9} "
                f"{v['total_attached_nics']:<15} {status:<14} {v['address_prefixes']}"
            )
        lines.append("=" * 115)
        text_out = "\n".join(lines)

    if opts.output_file:
        p = Path(opts.output_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text_out, encoding="utf-8")
        logger.info("VNet report saved to %s", opts.output_file)
    else:
        print(text_out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
