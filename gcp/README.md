# GCP Security, FinOps, & Engineering Suite

Production-grade Python tools for Google Cloud Platform (GCP).

## Modules
- [`logging/`](./logging/): Cloud Logging storage bucket retention optimization and sink exclusion auditing.
- [`iam/`](./iam/): Workload Identity Federation configuration for keyless GitHub Actions CI/CD workflows.
- [`storage/`](./storage/): Google Cloud Storage (GCS) Uniform Bucket-Level Access (UBLA), public prevention, and lifecycle audits.
- [`networking/`](./networking/): GCP VPC network topology, subnets, and peering inventory.

## Prerequisites
```bash
pip install -e ".[gcp]"
gcloud auth application-default login
```
