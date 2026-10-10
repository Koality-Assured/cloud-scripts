# AWS IAM Tooling

Security and identity automation for AWS IAM.

## `github_oidc_role_provisioner.py`
Provisions OpenID Connect (OIDC) authentication for GitHub Actions workflows, replacing long-lived static AWS access keys.

### Features
- Verifies and configures AWS OIDC identity provider for `token.actions.githubusercontent.com`.
- Creates or updates IAM role with scoped `sub` condition matching your GitHub organization, repository, branch, or environment.
- Attaches managed policies or custom inline policy documents.
- Safe by default: runs in **dry-run** preview mode unless `--apply` is explicitly passed.
- Outputs the ready-to-paste GitHub Actions YAML workflow snippet.

### Usage
```bash
# Preview role configuration and trust policy (DRY-RUN by default)
python github_oidc_role_provisioner.py \
  --role-name "ci-cd-runner" \
  --repo "my-org/my-app" \
  --environment "production" \
  --policy-file "policies/least_privilege.json"

# Apply role provisioning with AdministratorAccess
python github_oidc_role_provisioner.py \
  --role-name "github-actions-iac-deployer" \
  --repo "Koality-Assured/cloud-scripts" \
  --branch "main" \
  --policy-arn "arn:aws:iam::aws:policy/AdministratorAccess" \
  --apply
```
