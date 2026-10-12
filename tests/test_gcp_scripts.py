import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "gcp"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "gcp" / "logging"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "gcp" / "iam"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "gcp" / "storage"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "gcp" / "networking"))

import github_workload_identity_setup


def test_gcp_workload_identity_plan():
    plan = github_workload_identity_setup.generate_configuration_plan(
        project_id="test-project",
        project_number="123456789012",
        pool_id="gh-pool",
        provider_id="gh-provider",
        service_account_email="deployer@test-project.iam.gserviceaccount.com",
        github_repo="Koality-Assured/cloud-scripts",
        attribute_condition="assertion.repository == 'Koality-Assured/cloud-scripts'",
    )
    assert plan["project_id"] == "test-project"
    assert "gh-pool" in plan["pool_name"]
    assert "attribute.repository/Koality-Assured/cloud-scripts" in plan["principal_set"]
    assert len(plan["gcloud_commands"]) == 3
    assert "google-github-actions/auth@v2" in plan["actions_snippet"]

def test_build_attribute_condition():
    assert github_workload_identity_setup.build_attribute_condition("repo", branch="main") == "assertion.repository == 'repo' && assertion.ref == 'refs/heads/main'"
    assert github_workload_identity_setup.build_attribute_condition("repo", environment="prod") == "assertion.repository == 'repo' && assertion.environment == 'prod'"
    assert github_workload_identity_setup.build_attribute_condition("repo", allow_any_ref=True) == "assertion.repository == 'repo'"

    import pytest
    with pytest.raises(ValueError):
        github_workload_identity_setup.build_attribute_condition("repo")
