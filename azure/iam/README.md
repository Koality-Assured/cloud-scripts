# Azure IAM & Workload Identity Tooling

Identity federation and keyless authentication tooling for Microsoft Azure.

## `github_federated_credential_setup.py`
Establishes Microsoft Entra ID (Azure AD) Federated Identity Credentials for GitHub Actions OIDC:
- Generates Entra ID Application and Service Principal.
- Configures Federated Identity Credential targeting `https://token.actions.githubusercontent.com`.
- Binds Azure RBAC roles (`Contributor`, `Reader`, etc.) at Subscription or Resource Group scope.
- Outputs the ready-to-use GitHub Actions workflow YAML snippet using `azure/login@v2`.

### Usage
```bash
python github_federated_credential_setup.py \
  --app-name "github-actions-deployer" \
  --repo "Koality-Assured/cloud-scripts" \
  --tenant-id "00000000-0000-0000-0000-000000000000" \
  --subscription-id "11111111-1111-1111-1111-111111111111" \
  --branch "main" \
  --role "Contributor" \
  --resource-group "rg-production"
```
