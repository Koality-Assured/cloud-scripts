# AWS Cost Explorer Tooling

Granular cost analysis and FinOps reporting across AWS profiles and accounts.

## Usage

```bash
# Analyze spend by Usage Type for the prior month
python cost_breakdown.py --format table

# Analyze CloudWatch and S3 spend grouped by OPERATION for a specific date range
python cost_breakdown.py \
  --services "Amazon CloudWatch,Amazon Simple Storage Service" \
  --group-by OPERATION \
  --start-date 2026-09-01 \
  --end-date 2026-10-01 \
  --format csv \
  --output-file output/cloudwatch_s3_ops_cost.csv

# Query spend grouped by AWS Service across all production profiles
python cost_breakdown.py \
  --profile-pattern "prod" \
  --group-by SERVICE \
  --format json \
  --output-file output/monthly_service_spend.json
```
