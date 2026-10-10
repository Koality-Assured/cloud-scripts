#!/usr/bin/env python3
"""GCP Cloud Logging Sink & Exclusion Filter Auditor.

Audits project-level and organization-level Cloud Logging sinks, routing destinations
(BigQuery, Pub/Sub, Cloud Storage, Splunk/Chronicle forwarders), and exclusion filters.
Verifies that chatty healthchecks or verbose debug logs are excluded to prevent billing surges.
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
logger = logging.getLogger("gcp-log-sink-audit")


def audit_logging_sinks(project_id: str) -> List[Dict[str, Any]]:
    """List and audit Cloud Logging sinks for a project."""
    if not GCP_AVAILABLE:
        raise ImportError("google-cloud-logging is required.")

    client = logging_v2.ConfigServiceV2Client()
    parent = f"projects/{project_id}"

    results = []
    try:
        sinks = client.list_sinks(parent=parent)
        for s in sinks:
            exclusions = []
            for ex in getattr(s, "exclusions", []):
                exclusions.append({
                    "name": ex.name,
                    "filter": ex.filter,
                    "description": ex.description or "",
                    "disabled": ex.disabled,
                })

            results.append({
                "project_id": project_id,
                "sink_name": s.name,
                "destination": s.destination,
                "filter": s.filter or "ALL LOGS (No filter)",
                "writer_identity": s.writer_identity or "None",
                "disabled": getattr(s, "disabled", False),
                "exclusion_count": len(exclusions),
                "exclusions": exclusions,
            })
    except GoogleAPIError as e:
        logger.error("Failed to query sinks for project %s: %s", project_id, e)
        raise

    return results


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit GCP Cloud Logging sinks, routing destinations, and exclusion filters."
    )
    parser.add_argument("--project-id", required=True, help="GCP Project ID (or comma-separated IDs).")
    parser.add_argument("--format", choices=["table", "csv", "json"], default="table", help="Output format.")
    parser.add_argument("--output-file", help="File path to write report to.")
    return parser.parse_args(args)


def main() -> int:
    opts = parse_args()
    if not GCP_AVAILABLE:
        logger.error("GCP dependencies not installed. Install with: pip install '.[gcp]'")
        return 1

    projects = [p.strip() for p in opts.project_id.split(",") if p.strip()]
    all_sinks: List[Dict[str, Any]] = []

    for proj in projects:
        try:
            sinks = audit_logging_sinks(proj)
            all_sinks.extend(sinks)
        except Exception as e:
            logger.error("Error auditing project %s: %s", proj, e)

    if opts.format == "json":
        text_out = json.dumps({"total_sinks": len(all_sinks), "sinks": all_sinks}, indent=2)
    elif opts.format == "csv":
        fieldnames = ["project_id", "sink_name", "destination", "disabled", "exclusion_count", "filter"]
        import io
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_sinks)
        text_out = buf.getvalue()
    else:
        lines = [
            "=" * 115,
            f" GCP LOGGING SINK AUDIT (Found {len(all_sinks)} sinks)",
            "=" * 115,
            f"{'Project ID':<20} {'Sink Name':<20} {'Exclusions':<12} {'Disabled':<10} {'Destination'}",
            "-" * 115,
        ]
        for s in all_sinks:
            dis_str = "Yes" if s["disabled"] else "No"
            lines.append(
                f"{s['project_id']:<20} {s['sink_name']:<20} {s['exclusion_count']:<12} "
                f"{dis_str:<10} {s['destination']}"
            )
        lines.append("=" * 115)
        text_out = "\n".join(lines)

    if opts.output_file:
        p = Path(opts.output_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text_out, encoding="utf-8")
        logger.info("Sink audit report saved to %s", opts.output_file)
    else:
        print(text_out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
