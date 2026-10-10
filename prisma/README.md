# Prisma Cloud Enterprise Security Tooling

Production-grade Python tools for Palo Alto Networks Prisma Cloud (formerly RedLock) across AWS, GCP, and Azure.

## Modules

### 1. `client.py`
Enterprise-grade API client:
- Automated JWT authentication (`/login`) with proactive token extension (`/auth_token/extend`).
- Exponential backoff with jitter on HTTP 429 (Rate Limit) and 5xx errors.
- Multi-stack domain resolution (`api.prismacloud.io`, `api2`, `api3`, `api.eu`, `api.gov`).
- Environment variable credential resolution (`PRISMA_ACCESS_KEY`, `PRISMA_SECRET_KEY`, `PRISMA_API_URL`).

### 2. `rql_config_inventory.py`
Runs RQL configuration queries across cloud resources:
- Built-in library of security presets: `aws-public-s3`, `aws-open-ssh-rdp`, `azure-public-storage`, `gcp-unencrypted-disks`, `all-cloud-resources`.
- Accepts custom queries via `--query`.
- Exports findings to CSV, JSON, or formatted console table.

```bash
# Run pre-configured security check for public S3 buckets
python rql_config_inventory.py --preset aws-public-s3 --format table

# Run custom RQL query
python rql_config_inventory.py \
  --query "config from cloud.resource where cloud.type = 'gcp' AND api.name = 'gcloud-compute-instances-list'" \
  --format csv \
  --output-file output/gcp_instances.csv
```

### 3. `rql_event_audit.py`
Investigates audit and administrative activity logs across cloud providers:
- Queries critical operations (`CreateSecurityGroup`, `DeleteDBInstance`, `AttachRolePolicy`, `DeleteAccessKey`).
- Configurable lookback windows (`--hours 24`).

```bash
python rql_event_audit.py --hours 48 --format table
```

### 4. `cloud_account_health.py`
Audits the connection health and scan status of all onboarded cloud accounts:
- Flags degraded accounts with broken permissions or stale scans.

```bash
python cloud_account_health.py --show-unhealthy-only --format table
```

### 5. `alert_remediation_audit.py`
Aggregates open security alerts by severity and cloud provider:
- Highlights the top 10 offending policies driving alert fatigue.

```bash
python alert_remediation_audit.py --format table
```
