# Azure Security, FinOps, & Cloud Engineering Suite

Production-grade Python tools for Microsoft Azure.

## Modules
- [`monitor/`](./monitor/): Azure Log Analytics Workspace retention optimization and daily cap auditing.
- [`iam/`](./iam/): Microsoft Entra ID (Azure AD) Federated Identity Credentials for keyless GitHub Actions OIDC.
- [`storage/`](./storage/): Azure Storage Account security posture, TLS 1.2, and public blob access auditing.
- [`networking/`](./networking/): Azure VNet network topology and connected device density analysis.

## Prerequisites
```bash
pip install -e ".[azure]"
az login
```
