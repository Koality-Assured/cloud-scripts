#!/usr/bin/env python3
"""GCP Cloud Logging Storage Bucket Retention & Cost Analyzer.

Inspects Google Cloud Logging storage buckets (`_Default`, `_Required`, and user-defined buckets)
across GCP projects, evaluating:
- Data retention periods (days)
- Locked retention policy status
- Storage location (regional / multi-regional)
- Opportunities for cost optimization by lowering retention on non-compliance buckets

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
    from google.api_core.exceptions import GoogleAPIError
    from google.cloud import logging_v2
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("gcp-log-retention-analyzer")


def audit_project_log_buckets(
    project_id: str,
    target_retention_days: int = 30,
) -> List[Dict[str, Any]]:
    """Audit Cloud Logging buckets in a GCP project."""
    if not GCP_AVAILABLE:
        raise ImportError(
            "google-cloud-logging is required. Install via: pip install '.[gcp]'"
        )

    client = logging_v2.ConfigServiceV2Client()
    parent = f"projects/{project_id}/locations/-"

    results = []
    try:
        buckets = client.list_buckets(parent=parent)
        for b in buckets:
            # Bucket name format: projects/{project}/locations/{location}/buckets/{bucket_id}
            parts = b.name.split("/")
            location = parts[3] if len(parts) > 3 else "unknown"
            bucket_id = parts[5] if len(parts) > 5 else parts[-1]

            current_retention = b.retention_days
            is_locked = b.locked

            # _Required bucket has fixed 400-day retention and cannot be modified
            is_changeable = bucket_id != "_Required" and not is_locked

            needs_update = is_changeable and current_retention > target_retention_days

            results.append({
                "project_id": project_id,
                "bucket_id": bucket_id,
                "location": location,
                "full_name": b.name,
                "current_retention_days": current_retention,
                "target_retention_days": target_retention_days,
                "is_locked": is_locked,
                "is_changeable": is_changeable,
                "needs_update": needs_update,
                "description": b.description or "",
            })
    except GoogleAPIError as e:
        logger.error("Failed to query log buckets for project %s: %s", project_id, e)
        raise

    return results


def apply_retention(bucket_full_name: str, retention_days: int) -> bool:
    """Update Cloud Logging bucket retention days."""
    if not GCP_AVAILABLE:
        return False
    client = logging_v2.ConfigServiceV2Client()
    try:
        bucket = client.get_bucket(name=bucket_full_name)
        bucket.retention_days = retention_days
        client.update_bucket(bucket=bucket, update_mask={"paths": ["retention_days"]})
        logger.info("Updated %s retention to %d days", bucket_full_name, retention_days)
        return True
    except GoogleAPIError as e:
        logger.error("Failed updating %s: %s", bucket_full_name, e)
        return False


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit and optimize GCP Cloud Logging bucket retention periods."
    )
    parser.add_argument("--project-id", required=True, help="GCP Project ID (or comma-separated IDs).")
    parser.add_argument("--target-retention", type=int, default=30, help="Target retention in days (default: 30).")
    parser.add_argument("--apply", action="store_true", help="Apply retention changes (default: DRY-RUN).")
    parser.add_argument("--format", choices=["table", "csv", "json"], default="table", help="Output format.")
    parser.add_argument("--output-file", help="File path to write report to.")
    return parser.parse_args(args)


def main() -> int:
    opts = parse_args()
    if not GCP_AVAILABLE:
        logger.error("GCP dependencies not installed. Install with: pip install '.[gcp]'")
        return 1

    projects = [p.strip() for p in opts.project_id.split(",") if p.strip()]
    all_buckets: List[Dict[str, Any]] = []

    for proj in projects:
        logger.info("Auditing Cloud Logging buckets for GCP project: %s", proj)
        try:
            buckets = audit_project_log_buckets(proj, target_retention_days=opts.target_retention)
            all_buckets.extend(buckets)
        except Exception as e:
            logger.error("Error inspecting project %s: %s", proj, e)

    candidate_count = sum(1 for b in all_buckets if b["needs_update"])

    if opts.format == "json":
        text_out = json.dumps({
            "total_buckets": len(all_buckets),
            "candidates_for_optimization": candidate_count,
            "buckets": all_buckets,
        }, indent=2)
    elif opts.format == "csv":
        fieldnames = ["project_id", "bucket_id", "location", "current_retention_days", "target_retention_days", "is_locked", "needs_update"]
        import io
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_buckets)
        text_out = buf.getvalue()
    else:
        lines = [
            "=" * 95,
            f" GCP CLOUD LOGGING BUCKET RETENTION AUDIT (Total: {len(all_buckets)} | Candidates: {candidate_count})",
            "=" * 95,
            f"{'Project ID':<22} {'Bucket ID':<18} {'Location':<12} {'Current Days':<14} {'Target':<8} {'Locked':<8} {'Status'}",
            "-" * 95,
        ]
        for b in all_buckets:
            locked_str = "Yes" if b["is_locked"] else "No"
            status = "NEEDS_OPTIMIZATION" if b["needs_update"] else "OK"
            if not b["is_changeable"]:
                status = "PROTECTED"
            lines.append(
                f"{b['project_id']:<22} {b['bucket_id']:<18} {b['location']:<12} "
                f"{b['current_retention_days']:<14} {b['target_retention_days']:<8} "
                f"{locked_str:<8} {status}"
            )
        lines.append("=" * 95)
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
            print(f"\n[DRY RUN] {candidate_count} log buckets can be optimized to {opts.target_retention} days retention.")
            print("To apply changes, re-run with --apply.")
        else:
            logger.info("Applying retention updates to %d buckets...", candidate_count)
            success = 0
            for b in all_buckets:
                if b["needs_update"]:
                    if apply_retention(b["full_name"], opts.target_retention):
                        success += 1
            print(f"\nApplied updates to {success}/{candidate_count} log buckets.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
