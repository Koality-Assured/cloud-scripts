#!/usr/bin/env python3
"""S3 Event-Driven Ephemeral Worker Trigger Pipeline.

Serverless pipeline component designed to consume S3 ObjectCreated / EventBridge events.
Validates object key prefixes/extensions and dynamically launches an on-demand ephemeral
worker instance from an EC2 Launch Template (with parameterized UserData) or Step Function
execution to process heavy payloads (e.g. binary analysis, file encryption, media encoding).

Generalizes build-protection, asset processing, and security automation workflows.
"""

from __future__ import annotations

import base64
import fnmatch
import json
import logging
import os
import re
import shlex
from typing import Any, Dict, Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("s3-worker-pipeline")
logger.setLevel(logging.INFO)

SAFE_KEY_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\./]+$")
SAFE_BUCKET_PATTERN = re.compile(r"^[a-z0-9][a-z0-9\.\-]{1,61}[a-z0-9]$")


def matches_filter(key: str, prefix_pattern: str, glob_pattern: str) -> bool:
    """Check if object key matches required prefix and glob extension."""
    if prefix_pattern and not key.startswith(prefix_pattern):
        return False
    if glob_pattern and not fnmatch.fnmatch(key, glob_pattern):
        return False
    return True


def launch_worker_instance(
    launch_template_id: str,
    bucket: str,
    key: str,
    instance_type_override: Optional[str] = None,
    user_data_template: Optional[str] = None,
    region: Optional[str] = None,
) -> Dict[str, Any]:
    """Launch an ephemeral EC2 worker instance to process the S3 object."""
    # Sanitize and strictly validate inputs against shell metacharacters
    if not SAFE_BUCKET_PATTERN.match(bucket):
        raise ValueError(f"Unsafe bucket name rejected: {bucket}")
    if not SAFE_KEY_PATTERN.match(key):
        raise ValueError(f"Unsafe characters in S3 key rejected: {key}")

    ec2 = boto3.client("ec2", region_name=region)

    launch_spec: Dict[str, Any] = {
        "LaunchTemplate": {"LaunchTemplateId": launch_template_id},
        "MinCount": 1,
        "MaxCount": 1,
        "InstanceInitiatedShutdownBehavior": "terminate",  # Ephemeral self-termination
    }

    if instance_type_override:
        launch_spec["InstanceType"] = instance_type_override

    # Parameterize UserData script safely with quoted arguments
    if user_data_template:
        safe_bucket = shlex.quote(bucket)
        safe_key = shlex.quote(key)
        formatted_script = user_data_template.format(bucket=safe_bucket, key=safe_key)
        encoded_user_data = base64.b64encode(formatted_script.encode("utf-8")).decode("utf-8")
        launch_spec["UserData"] = encoded_user_data

    # Tag instance with job context
    launch_spec["TagSpecifications"] = [
        {
            "ResourceType": "instance",
            "Tags": [
                {"Key": "ManagedBy", "Value": "s3-worker-pipeline"},
                {"Key": "SourceBucket", "Value": bucket},
                {"Key": "SourceKey", "Value": key[:250]},
            ],
        }
    ]

    resp = ec2.run_instances(**launch_spec)
    instances = resp.get("Instances", [])
    instance_id = instances[0]["InstanceId"] if instances else "unknown"
    logger.info("Launched worker instance %s for s3://%s/%s", instance_id, bucket, key)
    return {"instance_id": instance_id, "status": "launched"}


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Entry point for S3 or EventBridge events."""
    logger.info("Received event: %s", json.dumps(event))

    launch_template_id = os.environ.get("LAUNCH_TEMPLATE_ID")
    prefix_pattern = os.environ.get("PREFIX_PATTERN", "incoming/")
    glob_pattern = os.environ.get("GLOB_PATTERN", "*")
    region = os.environ.get("AWS_REGION", "us-east-1")

    # Detect S3 event structure: EventBridge format vs Direct S3 Notification format
    records_to_process = []

    if "detail" in event and "bucket" in event["detail"]:
        # EventBridge S3 notification
        records_to_process.append({
            "bucket": event["detail"]["bucket"]["name"],
            "key": event["detail"]["object"]["key"],
        })
    elif "Records" in event:
        # Standard S3 Lambda trigger
        for rec in event["Records"]:
            s3_data = rec.get("s3", {})
            b_name = s3_data.get("bucket", {}).get("name")
            k_name = s3_data.get("object", {}).get("key")
            if b_name and k_name:
                records_to_process.append({"bucket": b_name, "key": k_name})

    if not records_to_process:
        logger.warning("No S3 records identified in event payload.")
        return {"statusCode": 200, "message": "No S3 objects found in event"}

    max_workers = int(os.environ.get("MAX_WORKERS_PER_BATCH", "10"))
    if len(records_to_process) > max_workers:
        logger.warning(
            "Event batch size (%d) exceeds MAX_WORKERS_PER_BATCH (%d). Capping execution.",
            len(records_to_process), max_workers
        )
        records_to_process = records_to_process[:max_workers]

    results = []
    for item in records_to_process:
        bucket = item["bucket"]
        key = item["key"]

        if not matches_filter(key, prefix_pattern, glob_pattern):
            logger.info("Skipping s3://%s/%s (does not match filter '%s' / '%s')", bucket, key, prefix_pattern, glob_pattern)
            continue

        if not launch_template_id:
            logger.error("LAUNCH_TEMPLATE_ID environment variable is missing.")
            return {"statusCode": 500, "error": "Missing LAUNCH_TEMPLATE_ID configuration"}

        try:
            worker_res = launch_worker_instance(
                launch_template_id=launch_template_id,
                bucket=bucket,
                key=key,
                region=region,
            )
            results.append({"bucket": bucket, "key": key, "worker": worker_res})
        except ClientError as e:
            logger.error("Failed to launch worker for s3://%s/%s: %s", bucket, key, e)
            return {"statusCode": 500, "error": str(e)}

    return {
        "statusCode": 200,
        "processed_count": len(results),
        "results": results,
    }


if __name__ == "__main__":
    # Test filter logic
    print("Filter test (incoming/file.bin, incoming/, *.bin):", matches_filter("incoming/file.bin", "incoming/", "*.bin"))
    print("Filter test (unprotected/test.exe, incoming/, *.bin):", matches_filter("unprotected/test.exe", "incoming/", "*.bin"))
