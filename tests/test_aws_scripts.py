import sys
from pathlib import Path
from unittest.mock import MagicMock

# Add repository root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "aws"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "aws" / "cloudtrail"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "aws" / "cloudwatch"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "aws" / "cost_explorer"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "aws" / "iam"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "aws" / "s3"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "aws" / "sso_config"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "aws" / "vpc"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "aws" / "serverless"))

import canary_healthcheck_handler
import cloudtrail_queue_health
import cost_breakdown
import cw_log_cost_analyzer
import cw_log_retention_enforcer
import eventbridge_s3_worker_pipeline
import generate_sso_config
import github_oidc_role_provisioner
import s3_prefix_scanner


def test_cloudtrail_queue_health_parsing():
    args = cloudtrail_queue_health.parse_args([
        "--queue-url", "https://sqs.us-east-1.amazonaws.com/123456789012/test-queue",
        "--threshold", "500",
        "--format", "json"
    ])
    assert args.queue_url == "https://sqs.us-east-1.amazonaws.com/123456789012/test-queue"
    assert args.threshold == 500
    assert args.format == "json"


def test_cw_log_cost_analyzer_math():
    mock_cw = MagicMock()
    mock_cw.get_metric_statistics.return_value = {
        "Datapoints": [{"Sum": 10737418240}]  # 10 GB
    }
    log_group = {
        "logGroupName": "/aws/vpc/flowlogs",
        "arn": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/vpc/flowlogs:*",
        "creationTime": 1700000000000,
        "retentionInDays": 0,  # Never expire
        "storedBytes": 107374182400,  # 100 GB
    }
    result = cw_log_cost_analyzer.analyze_log_group(
        cloudwatch=mock_cw,
        log_group=log_group,
        ingest_rate_per_gb=0.50,
        store_rate_per_gb=0.03,
        target_retention_days=30,
    )
    assert result["stored_gb"] == 100.0
    assert result["monthly_ingest_gb"] == 10.0
    assert result["monthly_ingest_cost_usd"] == 5.0
    assert result["monthly_storage_cost_usd"] == 3.0
    assert result["projected_monthly_savings_usd"] > 0


def test_cw_log_retention_enforcer_args():
    args = cw_log_retention_enforcer.parse_args([
        "--retention-days", "30",
        "--filter-pattern", "flowlogs",
    ])
    assert args.retention_days == 30
    assert args.filter_pattern == "flowlogs"
    assert args.apply is False


def test_cost_breakdown_default_time():
    start, end = cost_breakdown.get_default_time_period()
    assert len(start) == 10  # YYYY-MM-DD
    assert len(end) == 10


def test_github_oidc_role_trust_policy():
    oidc_arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    policy = github_oidc_role_provisioner.build_trust_policy(
        oidc_arn=oidc_arn,
        repo="Koality-Assured/cloud-scripts",
        branch="main"
    )
    stmt = policy["Statement"][0]
    cond = stmt["Condition"]
    assert cond["StringEquals"]["token.actions.githubusercontent.com:sub"] == "repo:Koality-Assured/cloud-scripts:ref:refs/heads/main"

    policy_tag = github_oidc_role_provisioner.build_trust_policy(
        oidc_arn=oidc_arn,
        repo="Koality-Assured/cloud-scripts",
        tag="v1.0.0"
    )
    assert policy_tag["Statement"][0]["Condition"]["StringEquals"]["token.actions.githubusercontent.com:sub"] == "repo:Koality-Assured/cloud-scripts:ref:refs/tags/v1.0.0"

    policy_any = github_oidc_role_provisioner.build_trust_policy(
        oidc_arn=oidc_arn,
        repo="Koality-Assured/cloud-scripts",
        allow_any_ref=True
    )
    assert policy_any["Statement"][0]["Condition"]["StringLike"]["token.actions.githubusercontent.com:sub"] == "repo:Koality-Assured/cloud-scripts:*"

    import pytest
    with pytest.raises(ValueError):
        github_oidc_role_provisioner.build_trust_policy(oidc_arn, "invalid_repo", branch="main")

    with pytest.raises(ValueError):
        github_oidc_role_provisioner.build_trust_policy(oidc_arn, "Koality-Assured/cloud-scripts")


def test_s3_prefix_scanner_aggregation():
    mock_s3 = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [
        {
            "Contents": [
                {"Key": "builds/v1.0/app.zip", "Size": 1048576},
                {"Key": "builds/v1.0/notes.txt", "Size": 1024},
                {"Key": "builds/v2.0/app.zip", "Size": 2097152},
                {"Key": "assets/logo.png", "Size": 512},
            ]
        }
    ]
    mock_s3.get_paginator.return_value = mock_paginator

    report = s3_prefix_scanner.scan_bucket_prefixes(
        s3_client=mock_s3,
        bucket_name="test-bucket",
        depth=1,
    )
    assert report["total_objects_scanned"] == 4
    prefixes = {p["prefix"]: p["object_count"] for p in report["prefixes"]}
    assert prefixes.get("builds/") == 3
    assert prefixes.get("assets/") == 1


def test_generate_sso_config():
    accounts = [{"id": "111122223333", "name": "prod-acct"}]
    cfg = generate_sso_config.build_sso_config(
        accounts=accounts,
        sso_session_name="test-session",
        sso_start_url="https://identity.example.com/start#/",
        sso_region="us-east-1",
        roles=["Viewer", "Admin"],
        profile_format="{role}-{account_name}",
    )
    assert cfg.has_section("sso-session test-session")
    assert cfg.has_section("profile Viewer-prod-acct")
    assert cfg.has_section("profile Admin-prod-acct")


def test_canary_healthcheck_handler():
    class Context:
        aws_request_id = "test-123"
        function_name = "health-test"
        function_version = "1"

    resp = canary_healthcheck_handler.lambda_handler({}, Context())
    assert resp["statusCode"] == 200
    assert "application/json" in resp["headers"]["Content-Type"]


def test_eventbridge_s3_worker_pipeline_filter():
    assert eventbridge_s3_worker_pipeline.matches_filter("incoming/data.csv", "incoming/", "*.csv") is True
    assert eventbridge_s3_worker_pipeline.matches_filter("other/data.csv", "incoming/", "*.csv") is False
    assert eventbridge_s3_worker_pipeline.matches_filter("incoming/data.txt", "incoming/", "*.csv") is False
