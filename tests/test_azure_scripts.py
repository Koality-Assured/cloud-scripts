import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "azure"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "azure" / "monitor"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "azure" / "iam"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "azure" / "storage"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "azure" / "networking"))

import github_federated_credential_setup


def test_azure_federated_credential_plan():
    plan = github_federated_credential_setup.generate_azure_federation_plan(
        app_name="ci-deployer",
        github_repo="Koality-Assured/cloud-scripts",
        tenant_id="00000000-0000-0000-0000-000000000000",
        subscription_id="11111111-1111-1111-1111-111111111111",
        branch="main",
        role_name="Contributor",
        resource_group="rg-prod",
    )
    assert plan["app_name"] == "ci-deployer"
    assert plan["subject_claim"] == "repo:Koality-Assured/cloud-scripts:ref:refs/heads/main"
    assert "/resourceGroups/rg-prod" in plan["scope"]
    assert len(plan["azure_cli_commands"]) == 4
    assert "azure/login@v2" in plan["actions_snippet"]
