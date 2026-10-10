# AWS CloudWatch Cost & Retention Tooling

Tools for auditing CloudWatch Log group storage, ingestion costs, and enforcing retention policies.

## Scripts

### 1. `cw_log_cost_analyzer.py`
Audits CloudWatch log groups across AWS profiles and regions.
- Computes incoming ingestion volume (via `AWS/Logs IncomingBytes` metric) and active stored bytes.
- Calculates monthly ingestion cost ($0.50/GB) and storage cost ($0.03/GB-month).
- Estimates potential monthly dollar savings achieved by applying a targeted retention window (e.g. 30 days) versus indefinite storage.
- Formats results as pretty console tables, CSV, or structured JSON.

```bash
# Analyze all configured AWS profiles in standard regions
python cw_log_cost_analyzer.py --format table

# Filter for flow logs and Prisma logs across specific profiles and export CSV
python cw_log_cost_analyzer.py \
  --profile-pattern "prod" \
  --filter-pattern "flowlogs|prisma|vpc" \
  --target-retention 30 \
  --format csv \
  --output-file output/cw_cost_report.csv
```

### 2. `cw_log_retention_enforcer.py`
Discovers and updates CloudWatch log groups whose retention is set to "Never Expire" or exceeds a target threshold.
- Safe by default: runs in **dry-run** mode unless `--apply` is specified.
- Supports filtering by regex patterns and targeting specific AWS regions.

```bash
# Preview log groups that would be updated to 30 days retention
python cw_log_retention_enforcer.py --filter-pattern "flowlogs|prisma" --retention-days 30

# Apply the 30-day retention policy to matching log groups
python cw_log_retention_enforcer.py --filter-pattern "flowlogs|prisma" --retention-days 30 --apply
```
