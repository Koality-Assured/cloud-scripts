#!/usr/bin/env python3
"""CloudTrail SQS Ingestion & Queue Health Monitor.

Inspects SQS queues used for CloudTrail, event ingestion, and dead-letter queues (DLQ),
checking queue depth, in-flight message counts, and delayed messages. Optionally checks
CloudTrail delivery health and latest delivery errors.

Zero hardcoded credentials or proprietary names. Supports AWS SSO profiles, STS assume role,
environment variables, and standard IAM credentials.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from typing import Any, Dict, Optional

import boto3
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cloudtrail-queue-health")


def get_boto3_session(
    profile: Optional[str] = None,
    region: Optional[str] = None,
    role_arn: Optional[str] = None,
    role_session_name: str = "CloudTrailHealthSession",
) -> boto3.Session:
    """Create a boto3 session supporting profiles and STS role assumption."""
    base_session = boto3.Session(profile_name=profile, region_name=region)
    if not role_arn:
        return base_session

    sts = base_session.client("sts")
    logger.info("Assuming role: %s", role_arn)
    assumed = sts.assume_role(RoleArn=role_arn, RoleSessionName=role_session_name)
    creds = assumed["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region or base_session.region_name,
    )


def check_sqs_queue_health(session: boto3.Session, queue_url: str) -> Dict[str, Any]:
    """Retrieve queue depth attributes and dead-letter queue metrics."""
    sqs = session.client("sqs")
    try:
        attrs = sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=[
                "ApproximateNumberOfMessages",
                "ApproximateNumberOfMessagesNotVisible",
                "ApproximateNumberOfMessagesDelayed",
                "RedrivePolicy",
                "CreatedTimestamp",
                "LastModifiedTimestamp",
            ],
        ).get("Attributes", {})
    except ClientError as e:
        logger.error("Failed to query SQS queue attributes: %s", e)
        raise

    health: Dict[str, Any] = {
        "queue_url": queue_url,
        "visible_messages": int(attrs.get("ApproximateNumberOfMessages", 0)),
        "in_flight_messages": int(attrs.get("ApproximateNumberOfMessagesNotVisible", 0)),
        "delayed_messages": int(attrs.get("ApproximateNumberOfMessagesDelayed", 0)),
        "has_dlq": False,
        "dlq_url": None,
        "dlq_messages": 0,
    }

    redrive = attrs.get("RedrivePolicy")
    if redrive:
        try:
            redrive_cfg = json.loads(redrive)
            dlq_arn = redrive_cfg.get("deadLetterTargetArn")
            health["has_dlq"] = True
            health["dlq_arn"] = dlq_arn

            # Derive DLQ URL from DLQ ARN if possible
            if dlq_arn:
                dlq_name = dlq_arn.split(":")[-1]
                dlq_resp = sqs.get_queue_url(QueueName=dlq_name)
                dlq_url = dlq_resp.get("QueueUrl")
                health["dlq_url"] = dlq_url
                dlq_attrs = sqs.get_queue_attributes(
                    QueueUrl=dlq_url,
                    AttributeNames=["ApproximateNumberOfMessages"],
                ).get("Attributes", {})
                health["dlq_messages"] = int(dlq_attrs.get("ApproximateNumberOfMessages", 0))
        except Exception as dlq_err:
            logger.warning("Could not resolve DLQ details: %s", dlq_err)

    return health


def check_cloudtrail_status(
    session: boto3.Session, trail_name: str
) -> Dict[str, Any]:
    """Query CloudTrail logging status and recent delivery errors."""
    ct = session.client("cloudtrail")
    try:
        status = ct.get_trail_status(Name=trail_name)
        return {
            "trail_name": trail_name,
            "is_logging": status.get("IsLogging", False),
            "latest_delivery_time": str(status.get("LatestDeliveryTime", "Never")),
            "latest_delivery_error": status.get("LatestDeliveryError", "None"),
            "latest_notification_error": status.get("LatestNotificationError", "None"),
            "start_logging_time": str(status.get("StartLoggingTime", "Never")),
        }
    except ClientError as e:
        logger.error("Failed to query CloudTrail status for '%s': %s", trail_name, e)
        return {"trail_name": trail_name, "error": str(e)}


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit CloudTrail SQS ingestion queue depth, DLQ backlog, and trail health."
    )
    parser.add_argument("--queue-url", required=True, help="Target SQS queue URL to inspect.")
    parser.add_argument("--trail-name", help="Optional CloudTrail trail name to audit.")
    parser.add_argument("--profile", help="AWS CLI profile name.")
    parser.add_argument("--region", default="us-east-1", help="AWS Region (default: us-east-1).")
    parser.add_argument("--role-arn", help="Optional IAM Role ARN to assume.")
    parser.add_argument(
        "--threshold",
        type=int,
        default=1000,
        help="Alerting threshold for queue depth (default: 1000).",
    )
    parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text).",
    )
    return parser.parse_args(args)


def main() -> int:
    opts = parse_args()
    session = get_boto3_session(
        profile=opts.profile,
        region=opts.region,
        role_arn=opts.role_arn,
    )

    result: Dict[str, Any] = {"sqs": check_sqs_queue_health(session, opts.queue_url)}

    if opts.trail_name:
        result["cloudtrail"] = check_cloudtrail_status(session, opts.trail_name)

    # Determine status
    sqs_data = result["sqs"]
    is_alert = (
        sqs_data["visible_messages"] > opts.threshold
        or sqs_data.get("dlq_messages", 0) > 0
    )

    if opts.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print("\n" + "=" * 60)
        print(" CLOUDTRAIL / SQS INGESTION HEALTH REPORT")
        print("=" * 60)
        print(f"Queue URL:          {sqs_data['queue_url']}")
        print(f"Visible Messages:   {sqs_data['visible_messages']} (Threshold: {opts.threshold})")
        print(f"In-Flight Messages: {sqs_data['in_flight_messages']}")
        print(f"Delayed Messages:   {sqs_data['delayed_messages']}")
        print(f"DLQ Configured:     {sqs_data['has_dlq']}")
        if sqs_data["has_dlq"]:
            print(f"DLQ Messages:       {sqs_data['dlq_messages']}")
            print(f"DLQ URL:            {sqs_data.get('dlq_url', 'N/A')}")

        if "cloudtrail" in result:
            ct = result["cloudtrail"]
            print("-" * 60)
            print(f"Trail Name:         {ct.get('trail_name')}")
            print(f"Logging Active:     {ct.get('is_logging')}")
            print(f"Latest Delivery:    {ct.get('latest_delivery_time')}")
            print(f"Delivery Error:     {ct.get('latest_delivery_error')}")
        print("=" * 60)

        if is_alert:
            print("[ALERT] Queue messages exceed threshold or messages exist in DLQ!")
        else:
            print("[OK] All queue levels healthy.")

    return 1 if is_alert else 0


if __name__ == "__main__":
    sys.exit(main())
