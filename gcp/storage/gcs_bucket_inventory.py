#!/usr/bin/env python3
"""Google Cloud Storage (GCS) Multi-Bucket Security & Posture Inventory.

Audits GCS storage buckets across Google Cloud projects, collecting:
- Location (region / dual-region / multi-region)
- Default storage class (STANDARD, NEARLINE, COLDLINE, ARCHIVE)
- Uniform Bucket-Level Access (UBLA) compliance
- Public Access Prevention (enforced / unmanaged)
- Object Versioning state
- Lifecycle rule counts
- Customer-Managed Encryption Key (CMEK) configuration

Exports inventory to CSV, JSON, or console table.
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
    from google.api_core.exceptions import GoogleAPIError
    from google.cloud import storage
    GCP_STORAGE_AVAILABLE = True
except ImportError:
    GCP_STORAGE_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("gcs-inventory")


def audit_project_gcs_buckets(project_id: str) -> List[Dict[str, Any]]:
    """Audit GCS buckets for security and storage configuration."""
    if not GCP_STORAGE_AVAILABLE:
        raise ImportError("google-cloud-storage is required. Install via: pip install '.[gcp]'")

    client = storage.Client(project=project_id)
    results = []

    try:
        buckets = list(client.list_buckets())
        for b in buckets:
            # UBLA check
            iam_config = getattr(b, "iam_configuration", None)
            ubla_enabled = False
            pap = "unspecified"
            if iam_config:
                ubla_enabled = getattr(iam_config, "uniform_bucket_level_access_enabled", False)
                pap = getattr(iam_config, "public_access_prevention", "unspecified")

            lifecycle_rules = list(getattr(b, "lifecycle_rules", []))
            cmek_key = getattr(b, "default_kms_key_name", None) or "Google-Managed"

            results.append({
                "project_id": project_id,
                "bucket_name": b.name,
                "location": b.location,
                "location_type": getattr(b, "location_type", "region"),
                "storage_class": b.storage_class,
                "ubla_enabled": ubla_enabled,
                "public_access_prevention": pap,
                "versioning_enabled": bool(b.versioning_enabled),
                "lifecycle_rule_count": len(lifecycle_rules),
                "encryption": cmek_key,
            })
    except GoogleAPIError as e:
        logger.error("Failed querying GCS buckets in project %s: %s", project_id, e)
        raise

    return results


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit GCS bucket security posture, UBLA, and storage classes."
    )
    parser.add_argument("--project-id", required=True, help="GCP Project ID (or comma-separated IDs).")
    parser.add_argument("--format", choices=["table", "csv", "json"], default="table", help="Output format.")
    parser.add_argument("--output-file", help="File path to write report to.")
    return parser.parse_args(args)


def main() -> int:
    opts = parse_args()
    if not GCP_STORAGE_AVAILABLE:
        logger.error("google-cloud-storage not installed. Install via: pip install '.[gcp]'")
        return 1

    projects = [p.strip() for p in opts.project_id.split(",") if p.strip()]
    all_buckets: List[Dict[str, Any]] = []

    for proj in projects:
        logger.info("Scanning GCS buckets in project: %s", proj)
        try:
            buckets = audit_project_gcs_buckets(proj)
            all_buckets.extend(buckets)
        except Exception as e:
            logger.error("Error inspecting project %s: %s", proj, e)

    if opts.format == "json":
        text_out = json.dumps({"total_buckets": len(all_buckets), "buckets": all_buckets}, indent=2)
    elif opts.format == "csv":
        fieldnames = [
            "project_id", "bucket_name", "location", "storage_class",
            "ubla_enabled", "public_access_prevention", "versioning_enabled",
            "lifecycle_rule_count", "encryption"
        ]
        import io
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_buckets)
        text_out = buf.getvalue()
    else:
        lines = [
            "=" * 115,
            f" GCS STORAGE & SECURITY POSTURE (Found {len(all_buckets)} buckets)",
            "=" * 115,
            f"{'Project ID':<18} {'Location':<12} {'Storage Class':<14} {'UBLA':<8} {'Public Prev':<14} {'Version':<9} {'Bucket Name'}",
            "-" * 115,
        ]
        for b in all_buckets:
            ubla_str = "Yes" if b["ubla_enabled"] else "NO (RISK)"
            ver_str = "Yes" if b["versioning_enabled"] else "No"
            lines.append(
                f"{b['project_id']:<18} {b['location']:<12} {b['storage_class']:<14} "
                f"{ubla_str:<8} {b['public_access_prevention']:<14} {ver_str:<9} {b['bucket_name']}"
            )
        lines.append("=" * 115)
        text_out = "\n".join(lines)

    if opts.output_file:
        p = Path(opts.output_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text_out, encoding="utf-8")
        logger.info("GCS report saved to %s", opts.output_file)
    else:
        print(text_out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
