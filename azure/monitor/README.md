# Azure Monitor & Log Analytics Tooling

Tools for auditing Azure Monitor Log Analytics Workspaces, data retention, ingestion quotas, and billing controls.

## `log_analytics_workspace_audit.py`
Audits Log Analytics Workspaces across Azure subscriptions:
- Inspects data retention settings (`retentionInDays`) and identifies non-compliant workspaces.
- Verifies daily ingestion caps (`dailyQuotaGb`) to prevent runaway log billing.
- Supports `--dry-run` and `--apply` with `--target-retention` to adjust retention.

### Usage
```bash
# Preview workspace retention settings across a subscription
python log_analytics_workspace_audit.py \
  --subscription-id "00000000-0000-0000-0000-000000000000" \
  --target-retention 30

# Apply 30-day retention to all workspaces
python log_analytics_workspace_audit.py \
  --subscription-id "00000000-0000-0000-0000-000000000000" \
  --target-retention 30 \
  --apply
```
