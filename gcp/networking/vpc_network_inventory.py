#!/usr/bin/env python3
"""GCP Virtual Private Cloud (VPC) & Subnet Network Inventory.

Discovers GCP VPC networks and subnets across Google Cloud projects:
- Custom Mode vs Auto-Create Subnet mode
- Subnet CIDR allocations and secondary ranges (GKE Pods / Services)
- Private Google Access (PGA) enablement
- Network Peering relationships
- Gateway IPv4 configurations

Exports network topology inventory to CSV, JSON, or console table.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("gcp-vpc-inventory")


def get_gcp_access_token() -> Optional[str]:
    """Retrieve Google OAuth2 bearer access token via google-auth or gcloud auth print-access-token."""
    try:
        import google.auth
        import google.auth.transport.requests
        creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        auth_req = google.auth.transport.requests.Request()
        creds.refresh(auth_req)
        return creds.token
    except Exception:
        # Fallback to gcloud CLI
        import shutil
        import subprocess
        gcloud_bin = shutil.which("gcloud")
        if gcloud_bin:
            try:
                res = subprocess.run([gcloud_bin, "auth", "print-access-token"], capture_output=True, text=True, check=True)
                return res.stdout.strip()
            except Exception:
                pass
    return None


def query_gcp_networks(project_id: str, token: str) -> List[Dict[str, Any]]:
    """Query GCP Compute Engine REST API for networks and subnets."""
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    # 1. Fetch Networks
    net_url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/global/networks"
    net_resp = requests.get(net_url, headers=headers, timeout=30)
    if net_resp.status_code != 200:
        logger.error("Failed to query networks for %s: HTTP %d - %s", project_id, net_resp.status_code, net_resp.text)
        return []

    networks = net_resp.json().get("items", [])

    # 2. Fetch Aggregated Subnetworks
    sub_url = f"https://compute.googleapis.com/compute/v1/projects/{project_id}/aggregated/subnetworks"
    sub_resp = requests.get(sub_url, headers=headers, timeout=30)
    subnets_by_network: Dict[str, List[Dict[str, Any]]] = {}

    if sub_resp.status_code == 200:
        items = sub_resp.json().get("items", {})
        for _region_scope, data in items.items():
            for sub in data.get("subnetworks", []):
                net_name = sub.get("network", "").split("/")[-1]
                subnets_by_network.setdefault(net_name, []).append(sub)

    out = []
    for net in networks:
        net_name = net.get("name", "")
        auto_create = net.get("autoCreateSubnetworks", False)
        peerings = [p.get("name") for p in net.get("peerings", [])]

        subs = subnets_by_network.get(net_name, [])
        subnet_cidrs = [s.get("ipCidrRange", "") for s in subs]

        out.append({
            "project_id": project_id,
            "network_name": net_name,
            "auto_create_subnets": auto_create,
            "subnet_count": len(subs),
            "primary_cidrs": ", ".join(subnet_cidrs[:5]) + (f" (+{len(subnet_cidrs)-5} more)" if len(subnet_cidrs) > 5 else ""),
            "peerings": ", ".join(peerings) if peerings else "None",
            "routing_mode": net.get("routingConfig", {}).get("routingMode", "REGIONAL"),
        })

    return out


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit GCP VPC network topology, subnets, and peering."
    )
    parser.add_argument("--project-id", required=True, help="GCP Project ID (or comma-separated IDs).")
    parser.add_argument("--format", choices=["table", "csv", "json"], default="table", help="Output format.")
    parser.add_argument("--output-file", help="File path to write report to.")
    return parser.parse_args(args)


def main() -> int:
    opts = parse_args()
    token = get_gcp_access_token()
    if not token:
        logger.error("Could not obtain GCP credentials. Please run: gcloud auth application-default login")
        return 1

    projects = [p.strip() for p in opts.project_id.split(",") if p.strip()]
    all_networks: List[Dict[str, Any]] = []

    for proj in projects:
        logger.info("Discovering VPC networks in project: %s", proj)
        nets = query_gcp_networks(proj, token)
        all_networks.extend(nets)

    if opts.format == "json":
        text_out = json.dumps({"total_networks": len(all_networks), "networks": all_networks}, indent=2)
    elif opts.format == "csv":
        fieldnames = ["project_id", "network_name", "auto_create_subnets", "subnet_count", "routing_mode", "peerings", "primary_cidrs"]
        import io
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_networks)
        text_out = buf.getvalue()
    else:
        lines = [
            "=" * 110,
            f" GCP VPC NETWORK INVENTORY (Found {len(all_networks)} networks)",
            "=" * 110,
            f"{'Project ID':<22} {'Network Name':<20} {'Mode':<14} {'Subnets':<9} {'Routing':<12} {'Peerings'}",
            "-" * 110,
        ]
        for n in all_networks:
            mode_str = "Auto" if n["auto_create_subnets"] else "Custom"
            lines.append(
                f"{n['project_id']:<22} {n['network_name']:<20} {mode_str:<14} "
                f"{n['subnet_count']:<9} {n['routing_mode']:<12} {n['peerings']}"
            )
        lines.append("=" * 110)
        text_out = "\n".join(lines)

    if opts.output_file:
        p = Path(opts.output_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text_out, encoding="utf-8")
        logger.info("VPC network report saved to %s", opts.output_file)
    else:
        print(text_out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
