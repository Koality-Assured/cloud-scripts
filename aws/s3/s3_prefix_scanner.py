#!/usr/bin/env python3
"""S3 Bucket Object Prefix & Key Hierarchy Scanner.

Scans S3 buckets to inspect prefix structures, directory depths, object distributions,
file extensions, and storage footprints.

Generalizes asset hierarchy queries, project directory audits, and orphaned key discovery.
Zero hardcoded profiles or buckets.
"""

from __future__ import annotations

import argparse
import collections
import csv
import json
import logging
import re
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("s3-prefix-scanner")


def scan_bucket_prefixes(
    s3_client: Any,
    bucket_name: str,
    prefix_filter: str = "",
    pattern: Optional[str] = None,
    depth: int = 1,
    max_keys: Optional[int] = None,
) -> Dict[str, Any]:
    """Scan bucket objects and group by hierarchical prefix segment at specified depth."""
    regex = re.compile(pattern, re.IGNORECASE) if pattern else None

    prefix_counts: collections.Counter[str] = collections.Counter()
    prefix_sizes: collections.Counter[str] = collections.Counter()
    extension_counts: collections.Counter[str] = collections.Counter()

    paginator = s3_client.get_paginator("list_objects_v2")
    kwargs: Dict[str, Any] = {"Bucket": bucket_name}
    if prefix_filter:
        kwargs["Prefix"] = prefix_filter

    total_scanned = 0

    for page in paginator.paginate(**kwargs):
        for obj in page.get("Contents", []):
            total_scanned += 1
            key = obj.get("Key", "")
            size = obj.get("Size", 0)

            if regex and not regex.search(key):
                continue

            parts = [p for p in key.split("/") if p]
            # Determine prefix segment at requested depth
            if len(parts) >= depth:
                segment = "/".join(parts[:depth]) + "/"
            elif parts:
                segment = "/".join(parts)
            else:
                segment = "root"

            prefix_counts[segment] += 1
            prefix_sizes[segment] += size

            # Extract extension
            ext = Path(key).suffix.lower() or "no_extension"
            extension_counts[ext] += 1

            if max_keys and total_scanned >= max_keys:
                break
        if max_keys and total_scanned >= max_keys:
            break

    # Build summary
    segments_summary = []
    for seg, count in prefix_counts.most_common():
        size_bytes = prefix_sizes[seg]
        segments_summary.append({
            "prefix": seg,
            "object_count": count,
            "total_size_mb": round(size_bytes / (1024 * 1024), 2),
            "avg_object_size_kb": round((size_bytes / count) / 1024, 2) if count > 0 else 0,
        })

    return {
        "bucket_name": bucket_name,
        "total_objects_scanned": total_scanned,
        "depth_level": depth,
        "prefixes": segments_summary,
        "extensions": dict(extension_counts.most_common(20)),
    }


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan S3 bucket object prefixes, directory hierarchies, and file types."
    )
    parser.add_argument("--bucket", required=True, help="Target S3 bucket name.")
    parser.add_argument("--prefix", default="", help="Optional root prefix to start scanning.")
    parser.add_argument("--pattern", help="Optional regex filter for object keys.")
    parser.add_argument("--depth", type=int, default=1, help="Hierarchy directory depth to aggregate (default: 1).")
    parser.add_argument("--max-keys", type=int, help="Optional max keys to inspect (for large buckets).")
    parser.add_argument("--profile", help="AWS CLI profile name.")
    parser.add_argument("--region", default="us-east-1", help="AWS Region (default: us-east-1).")
    parser.add_argument("--format", choices=["table", "csv", "json"], default="table", help="Output format.")
    parser.add_argument("--output-file", help="File path to write report to.")
    return parser.parse_args(args)


def main() -> int:
    opts = parse_args()
    session = boto3.Session(profile_name=opts.profile, region_name=opts.region)
    s3_client = session.client("s3")

    logger.info("Scanning bucket: %s (depth=%d, prefix='%s')", opts.bucket, opts.depth, opts.prefix)
    try:
        report = scan_bucket_prefixes(
            s3_client=s3_client,
            bucket_name=opts.bucket,
            prefix_filter=opts.prefix,
            pattern=opts.pattern,
            depth=opts.depth,
            max_keys=opts.max_keys,
        )
    except ClientError as e:
        logger.error("Failed scanning bucket '%s': %s", opts.bucket, e)
        return 1

    if opts.format == "json":
        text_out = json.dumps(report, indent=2)
    elif opts.format == "csv":
        fieldnames = ["prefix", "object_count", "total_size_mb", "avg_object_size_kb"]
        import io
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(report["prefixes"])
        text_out = buf.getvalue()
    else:
        lines = [
            "=" * 85,
            f" S3 PREFIX HIERARCHY REPORT: {opts.bucket}",
            "=" * 85,
            f"Total Objects Scanned: {report['total_objects_scanned']} | Hierarchy Depth: {opts.depth}",
            "-" * 85,
            f"{'Prefix / Directory':<45} {'Objects':<12} {'Size (MB)':<14} {'Avg Size (KB)'}",
            "-" * 85,
        ]
        for p in report["prefixes"][:50]:
            lines.append(f"{p['prefix'][:43]:<45} {p['object_count']:<12} {p['total_size_mb']:<14.2f} {p['avg_object_size_kb']}")
        if len(report["prefixes"]) > 50:
            lines.append(f"... ({len(report['prefixes']) - 50} additional prefixes truncated)")
        lines.append("-" * 85)
        lines.append("Top File Extensions:")
        for ext, count in list(report["extensions"].items())[:10]:
            lines.append(f"  {ext:<15}: {count} files")
        lines.append("=" * 85)
        text_out = "\n".join(lines)

    if opts.output_file:
        p = Path(opts.output_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text_out, encoding="utf-8")
        logger.info("Scan report saved to %s", opts.output_file)
    else:
        print(text_out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
