# Google Cloud Storage (GCS) Tooling

Auditing tools for GCS bucket configuration, compliance, and security posture.

## `gcs_bucket_inventory.py`
Audits GCS storage buckets across Google Cloud projects:
- Verifies **Uniform Bucket-Level Access (UBLA)** enforcement (prevents dangerous ACL overrides).
- Verifies **Public Access Prevention** status.
- Inspects storage classes (Standard, Nearline, Coldline, Archive) and lifecycle policy counts.
- Identifies Customer-Managed Encryption Keys (CMEK).

### Usage
```bash
python gcs_bucket_inventory.py --project-id "my-gcp-project-prod" --format table

# Scan multiple projects and export CSV
python gcs_bucket_inventory.py \
  --project-id "prod-project,stage-project,data-project" \
  --format csv \
  --output-file output/gcs_security_report.csv
```
