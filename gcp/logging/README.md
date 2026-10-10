# GCP Cloud Logging Optimization & Auditing Tooling

Tools for analyzing Google Cloud Logging storage bucket retention, sink routing, and exclusion filters.

## Scripts

### 1. `log_bucket_retention_analyzer.py`
Audits Cloud Logging buckets (`_Default`, custom log buckets) across GCP projects:
- Detects buckets with default 30-day retention versus oversized retention periods.
- Prevents tampering with locked compliance buckets and protected `_Required` buckets.
- Supports `--dry-run` and `--apply` to enforce retention targets.

```bash
# Preview retention optimization opportunities across projects
python log_bucket_retention_analyzer.py --project-id "my-gcp-project-prod" --target-retention 30

# Apply 30-day retention to non-compliant buckets
python log_bucket_retention_analyzer.py --project-id "my-gcp-project-prod" --target-retention 30 --apply
```

### 2. `log_sink_audit.py`
Audits log routing sinks across GCP projects:
- Lists destinations (BigQuery datasets, Cloud Storage buckets, Pub/Sub topics).
- Audits exclusion filters to ensure high-volume noisy logs (e.g. load balancer health checks) are suppressed.

```bash
python log_sink_audit.py --project-id "my-gcp-project-prod" --format table
```
