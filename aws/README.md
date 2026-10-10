# AWS Security, FinOps, & Cloud Engineering Suite

Production-grade, generalized Python tools for managing, auditing, and optimizing AWS cloud infrastructure.

## Directory Structure

- [`cloudtrail/`](./cloudtrail/): SQS queue depth, ingestion latency, and CloudTrail delivery health checks.
- [`cloudwatch/`](./cloudwatch/): CloudWatch log group ingestion cost analysis and retention policy enforcement.
- [`cost_explorer/`](./cost_explorer/): Granular spend breakdown by service, operation, and usage type over time.
- [`iam/`](./iam/): GitHub Actions OIDC identity federation and least-privilege role provisioning.
- [`s3/`](./s3/): S3 multi-account posture inventory, storage metrics, and object prefix hierarchy analysis.
- [`sso_config/`](./sso_config/): Dynamic AWS CLI SSO profile generation from AWS Organizations or CSV manifests.
- [`vpc/`](./vpc/): VPC network topology inventory and network interface (ENI) resource connection density analysis.
- [`serverless/`](./serverless/): Canary healthcheck handler and S3 event-driven ephemeral worker pipelines.

## Prerequisites
```bash
pip install boto3 botocore
```
Authentication follows standard AWS credential chains (AWS CLI SSO profiles, IAM roles, or environment variables).
