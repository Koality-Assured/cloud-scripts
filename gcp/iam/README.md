# GCP IAM & Workload Identity Tooling

Keyless authentication and identity federation tooling for Google Cloud Platform.

## `github_workload_identity_setup.py`
Establishes Workload Identity Federation for GitHub Actions OIDC on Google Cloud Platform, eliminating the need to store long-lived JSON service account keys in repository secrets.

### Features
- Configures Workload Identity Pool and OIDC Provider targeting `https://token.actions.githubusercontent.com`.
- Sets up attribute mappings for `google.subject`, `attribute.repository`, `attribute.actor`, and `attribute.ref`.
- Generates least-privilege `roles/iam.workloadIdentityUser` policy bindings.
- Outputs the ready-to-use GitHub Actions workflow YAML snippet using `google-github-actions/auth@v2`.

### Usage
```bash
python github_workload_identity_setup.py \
  --project-id "my-gcp-project" \
  --project-number "123456789012" \
  --service-account "deployer@my-gcp-project.iam.gserviceaccount.com" \
  --repo "Koality-Assured/cloud-scripts" \
  --branch "main"
```
