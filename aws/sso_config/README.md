# AWS SSO Config Profile Generator

Automates the generation and updating of `~/.aws/config` profiles for AWS IAM Identity Center (SSO).

## Features
- **Auto-Discovery via Organizations**: Queries `organizations:ListAccounts` to discover all accounts and friendly account names automatically.
- **Account Manifest Support**: Ingests accounts from CSV or JSON files.
- **Config Merge Safety**: Preserves existing non-SSO sections in `~/.aws/config`.
- **Custom Profile Naming**: Format profiles using variables like `{role}-{account_id}` or `{account_name}-{role}`.

## Usage

```bash
# Auto-generate from AWS Organizations and preview (dry-run)
python generate_sso_config.py \
  --from-org \
  --org-profile "OrgMaster" \
  --sso-start-url "https://identity.example.com/start#/" \
  --sso-session-name "enterprise-sso" \
  --roles "Viewer,Admin,SecurityAudit" \
  --dry-run

# Write directly to ~/.aws/config from a CSV account manifest
python generate_sso_config.py \
  --accounts-file "accounts.csv" \
  --sso-start-url "https://identity.example.com/start#/" \
  --sso-session-name "enterprise-sso" \
  --roles "ReadOnly,AdministratorAccess" \
  --profile-format "{account_name}-{role}" \
  --write-to-aws-config
```
