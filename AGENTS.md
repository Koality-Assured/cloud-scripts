# Repository AGENTS

Canonical rules for AI agents operating within `Koality-Assured/cloud-scripts`.

## Scope & Purpose
This repository provides production-grade, generalized, secure multi-cloud automation, inventory, cost optimization, and security posture tooling across AWS, GCP, Microsoft Azure, and Prisma Cloud.

## Non-Negotiable Directives

### 1. Sanitization & Public Hygiene (CRITICAL)
- **Zero Secrets / Internal Identifiers**: NEVER commit or hardcode private credentials, API keys, internal account IDs, proprietary internal system names, internal DNS names, or employee names.
- **Environment & CLI First**: All credentials must be accepted via standard cloud credential chains (AWS profiles/SSO/IAM roles, GCP ADC, Azure DefaultAzureCredential) or environment variables (`PRISMA_ACCESS_KEY`, `PRISMA_SECRET_KEY`, etc.).
- **Cross-Platform Paths**: Avoid hardcoding platform-specific paths (e.g. hardcoded local directories or paths without expanding user home). Always use `pathlib.Path` or `os.path.expanduser`.
- **Dry-Run by Default for Mutating Ops**: Any script modifying cloud state (e.g. updating retention policies, provisioning IAM roles, deleting resources) MUST provide a `--dry-run` flag and require explicit confirmation for production execution.

### 2. Code Quality & Standards
- Python >= 3.9 compatibility with type hints and docstrings.
- Standardized CLI ergonomics: use `argparse` with clear help text, support for `--output` formats (`table`, `json`, `csv`).
- Comprehensive error handling: handle rate limits (HTTP 429), API pagination (`NextToken`, `pageToken`), missing permissions, and region unavailability gracefully.

### 3. Testing & Verification
- Unit tests in `tests/` covering argument parsing, mock SDK responses, pagination logic, and data transformation.
- Pre-merge validation: run `ruff check .` and `pytest tests/`.
