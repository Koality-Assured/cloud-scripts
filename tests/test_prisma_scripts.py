import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "prisma"))

import alert_remediation_audit
import client
import rql_config_inventory
import rql_event_audit


def test_prisma_client_init():
    cli = client.PrismaCloudClient(
        access_key="test-access",
        secret_key="test-secret",
        api_url="https://api2.prismacloud.io",
    )
    assert cli.access_key == "test-access"
    assert cli.api_url == "https://api2.prismacloud.io"
    assert "x-redlock-auth" not in cli._session.headers


def test_rql_config_preset_queries():
    assert "aws-public-s3" in rql_config_inventory.PRESET_QUERIES
    assert "all-cloud-resources" in rql_config_inventory.PRESET_QUERIES
    query = rql_config_inventory.PRESET_QUERIES["aws-public-s3"]
    assert "api.name = 'aws-s3api-get-bucket-acl'" in query


def test_rql_event_query_builder():
    q = rql_event_audit.build_event_query(
        operations=["CreateSecurityGroup", "DeleteDBInstance"],
        account_groups=["Production"],
        user_names=["admin@example.com"],
    )
    assert "event from cloud.audit_logs where" in q
    assert "operation IN ('CreateSecurityGroup', 'DeleteDBInstance')" in q
    assert "cloud.accountgroup IN ('Production')" in q
    assert "user IN ('admin@example.com')" in q


def test_alert_remediation_audit_aggregation():
    mock_client = MagicMock()
    mock_client.list_alerts.return_value = [
        {
            "id": "alert-1",
            "policy": {"name": "S3 Bucket Public", "severity": "high"},
            "resource": {"cloudType": "aws", "accountName": "prod-aws"},
        },
        {
            "id": "alert-2",
            "policy": {"name": "S3 Bucket Public", "severity": "high"},
            "resource": {"cloudType": "aws", "accountName": "prod-aws"},
        },
        {
            "id": "alert-3",
            "policy": {"name": "GCS Bucket Public", "severity": "critical"},
            "resource": {"cloudType": "gcp", "accountName": "prod-gcp"},
        },
    ]

    report = alert_remediation_audit.audit_alerts(mock_client, status="open")
    assert report["total_alerts"] == 3
    assert report["by_severity"]["high"] == 2
    assert report["by_severity"]["critical"] == 1
    assert report["by_cloud"]["aws"] == 2
    assert report["by_cloud"]["gcp"] == 1
    assert report["top_offending_policies"][0]["policy_name"] == "S3 Bucket Public"
    assert report["top_offending_policies"][0]["alert_count"] == 2
