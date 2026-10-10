# AWS S3 Storage & Inventory Tooling

Tools for auditing S3 security posture, storage metrics, and object prefix hierarchies.

## Scripts

### 1. `s3_storage_inventory.py`
Enumerates S3 buckets across multiple AWS accounts and profiles:
- Discovers bucket region and owning AWS account ID.
- Audits Server-Side Encryption (SSE-S3 / SSE-KMS), Versioning status, and S3 Block Public Access posture.
- Retrieves storage size and object counts from CloudWatch metrics.
- Exports to console table, CSV, or JSON.

```bash
# Audit all S3 buckets across configured profiles
python s3_storage_inventory.py --format table

# Fast scan skipping CloudWatch metric lookups, exported to CSV
python s3_storage_inventory.py \
  --profile-pattern "prod" \
  --skip-metrics \
  --format csv \
  --output-file output/s3_posture.csv
```

### 2. `s3_prefix_scanner.py`
Scans object key hierarchies inside an S3 bucket:
- Aggregates object counts and byte volumes at specified directory depths (e.g. depth 1, 2, 3).
- Identifies top file extensions and storage-heavy prefixes.
- Supports regex filtering and sample limits.

```bash
# Group objects by top-level prefix
python s3_prefix_scanner.py --bucket "my-enterprise-data-lake" --depth 1

# Inspect subdirectories under 'builds/' matching release archives
python s3_prefix_scanner.py \
  --bucket "artifacts-bucket" \
  --prefix "builds/" \
  --depth 2 \
  --pattern "\.(zip|tar\.gz|iso)$" \
  --format json
```
