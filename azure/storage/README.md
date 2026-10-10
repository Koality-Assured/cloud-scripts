# Azure Storage Tooling

Security, FinOps, and compliance tooling for Azure Storage Accounts and Blob Storage.

## `blob_inventory_and_metrics.py`
Audits Azure Storage Accounts across subscriptions:
- Verifies that public blob access is disabled (`allowBlobPublicAccess=false`).
- Checks TLS 1.2 minimum version enforcement.
- Ensures HTTPS-only secure transfer is active.
- Audits default network rules (Deny vs Allow) and SKU replication tiers.

### Usage
```bash
python blob_inventory_and_metrics.py \
  --subscription-id "00000000-0000-0000-0000-000000000000" \
  --format table

# Export to CSV
python blob_inventory_and_metrics.py \
  --subscription-id "00000000-0000-0000-0000-000000000000" \
  --format csv \
  --output-file output/azure_storage_posture.csv
```
