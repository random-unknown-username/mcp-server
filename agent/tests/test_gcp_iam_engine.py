"""Tests for the GCP IAM privilege escalation engine."""

import json

from security_agent.config import AgentConfig, GcpConfig
from security_agent.gcp_iam_engine import (
    GcpIamEngine,
    IamBinding,
    PrivescPath,
    GcpIamTestResult,
    _check_metadata_response,
    _extract_granted_permissions,
    _find_dangerous_bindings,
    _inject_query_param,
    _is_user_or_sa,
    _parse_iam_bindings,
    _response_has_token,
)
from security_agent.models import HttpRequest, HttpResponse, VulnerabilityType


# ---------------------------------------------------------------------------
# _check_metadata_response
# ---------------------------------------------------------------------------


def test_check_metadata_token_response():
    resp = HttpResponse(
        status_code=200,
        body='{"access_token": "ya29.abc", "token_type": "Bearer", "expires_in": 3600}',
        headers={"Metadata-Flavor": "Google"},
    )
    hits = _check_metadata_response(resp, "/computeMetadata/v1/instance/service-accounts/default/token")
    assert any("access_token" in h for h in hits)
    assert any("Bearer" in h for h in hits)


def test_check_metadata_scopes_response():
    resp = HttpResponse(
        status_code=200,
        body="https://www.googleapis.com/auth/cloud-platform\nhttps://www.googleapis.com/auth/compute",
        headers={},
    )
    hits = _check_metadata_response(resp, "/computeMetadata/v1/instance/service-accounts/default/scopes")
    assert any("scopes" in h.lower() for h in hits)


def test_check_metadata_sa_list_response():
    resp = HttpResponse(
        status_code=200,
        body="default/\nmy-sa@my-project.iam.gserviceaccount.com/",
        headers={},
    )
    hits = _check_metadata_response(resp, "/computeMetadata/v1/instance/service-accounts/")
    assert any("service account email" in h.lower() for h in hits)


def test_check_metadata_project_id_response():
    resp = HttpResponse(
        status_code=200,
        body="my-project-123",
        headers={},
    )
    hits = _check_metadata_response(resp, "/computeMetadata/v1/project/project-id")
    assert any("project ID" in h for h in hits)


def test_check_metadata_kube_env_response():
    resp = HttpResponse(
        status_code=200,
        body="KUBERNETES_MASTER_NAME: k8s-master\nKUBELET_CERT: abc123",
        headers={},
    )
    hits = _check_metadata_response(resp, "/computeMetadata/v1/instance/attributes/kube-env")
    assert any("Kubernetes" in h for h in hits)


def test_check_metadata_no_match():
    resp = HttpResponse(
        status_code=404,
        body="Not Found",
        headers={},
    )
    hits = _check_metadata_response(resp, "/computeMetadata/v1/instance/service-accounts/default/token")
    assert len(hits) == 0


def test_check_metadata_flavor_header():
    resp = HttpResponse(
        status_code=200,
        body="some data",
        headers={"Metadata-Flavor": "Google"},
    )
    hits = _check_metadata_response(resp, "/computeMetadata/v1/instance/zone")
    assert any("Metadata-Flavor" in h for h in hits)


# ---------------------------------------------------------------------------
# _parse_iam_bindings
# ---------------------------------------------------------------------------


def test_parse_iam_bindings_valid():
    body = json.dumps({
        "bindings": [
            {"role": "roles/owner", "members": ["user:admin@example.com"]},
            {"role": "roles/viewer", "members": ["group:devs@example.com"]},
        ]
    })
    bindings = _parse_iam_bindings(body)
    assert len(bindings) == 2
    assert bindings[0].role == "roles/owner"
    assert "user:admin@example.com" in bindings[0].members


def test_parse_iam_bindings_empty():
    bindings = _parse_iam_bindings("{}")
    assert len(bindings) == 0


def test_parse_iam_bindings_invalid_json():
    bindings = _parse_iam_bindings("not json")
    assert len(bindings) == 0


# ---------------------------------------------------------------------------
# _find_dangerous_bindings
# ---------------------------------------------------------------------------


def test_find_dangerous_owner_binding():
    bindings = [
        IamBinding(role="roles/owner", members=["user:admin@example.com"]),
    ]
    dangerous = _find_dangerous_bindings(bindings)
    assert len(dangerous) == 1
    assert "owner" in dangerous[0][1].lower() or "owner" in dangerous[0][0].role


def test_find_dangerous_token_creator():
    bindings = [
        IamBinding(
            role="roles/iam.serviceAccountTokenCreator",
            members=["serviceAccount:attacker@proj.iam.gserviceaccount.com"],
        ),
    ]
    dangerous = _find_dangerous_bindings(bindings)
    assert len(dangerous) == 1
    assert "impersonate" in dangerous[0][1].lower()


def test_find_dangerous_allUsers():
    bindings = [
        IamBinding(role="roles/editor", members=["allUsers"]),
    ]
    dangerous = _find_dangerous_bindings(bindings)
    assert len(dangerous) == 1


def test_find_dangerous_safe_binding():
    bindings = [
        IamBinding(role="roles/viewer", members=["user:viewer@example.com"]),
    ]
    dangerous = _find_dangerous_bindings(bindings)
    assert len(dangerous) == 0


def test_find_dangerous_skips_google_managed():
    # Members not matching user:/serviceAccount:/group:/allUsers/allAuthenticatedUsers
    bindings = [
        IamBinding(
            role="roles/owner",
            members=["deleted:user:old@example.com?uid=123"],
        ),
    ]
    dangerous = _find_dangerous_bindings(bindings)
    # "deleted:" prefix shouldn't match _is_user_or_sa
    assert len(dangerous) == 0


# ---------------------------------------------------------------------------
# _is_user_or_sa
# ---------------------------------------------------------------------------


def test_is_user_or_sa_user():
    assert _is_user_or_sa("user:alice@example.com") is True


def test_is_user_or_sa_service_account():
    assert _is_user_or_sa("serviceAccount:sa@proj.iam.gserviceaccount.com") is True


def test_is_user_or_sa_group():
    assert _is_user_or_sa("group:team@example.com") is True


def test_is_user_or_sa_all_users():
    assert _is_user_or_sa("allUsers") is True


def test_is_user_or_sa_all_authenticated():
    assert _is_user_or_sa("allAuthenticatedUsers") is True


def test_is_user_or_sa_domain():
    assert _is_user_or_sa("domain:example.com") is False


def test_is_user_or_sa_deleted():
    assert _is_user_or_sa("deleted:user:old@example.com") is False


# ---------------------------------------------------------------------------
# _response_has_token
# ---------------------------------------------------------------------------


def test_response_has_token_true():
    resp = HttpResponse(
        status_code=200,
        body='{"access_token": "ya29.something", "expires_in": 3600}',
    )
    assert _response_has_token(resp) is True


def test_response_has_token_false():
    resp = HttpResponse(status_code=200, body='{"error": "unauthorized"}')
    assert _response_has_token(resp) is False


def test_response_has_token_empty():
    resp = HttpResponse(status_code=200, body="")
    assert _response_has_token(resp) is False


# ---------------------------------------------------------------------------
# _extract_granted_permissions
# ---------------------------------------------------------------------------


def test_extract_granted_permissions():
    body = json.dumps({
        "permissions": [
            "iam.serviceAccountKeys.create",
            "iam.serviceAccounts.actAs",
        ]
    })
    perms = _extract_granted_permissions(body)
    assert "iam.serviceAccountKeys.create" in perms
    assert "iam.serviceAccounts.actAs" in perms


def test_extract_granted_permissions_empty():
    perms = _extract_granted_permissions("{}")
    assert perms == []


def test_extract_granted_permissions_invalid():
    perms = _extract_granted_permissions("not json")
    assert perms == []


# ---------------------------------------------------------------------------
# _inject_query_param
# ---------------------------------------------------------------------------


def test_inject_query_param_new():
    req = HttpRequest(method="GET", url="https://example.com/api")
    mutated = _inject_query_param(req, "url", "http://evil.com")
    assert "url=http" in mutated.url
    assert "evil.com" in mutated.url


def test_inject_query_param_existing():
    req = HttpRequest(method="GET", url="https://example.com/api?url=safe")
    mutated = _inject_query_param(req, "url", "http://evil.com")
    assert "evil.com" in mutated.url


# ---------------------------------------------------------------------------
# Data model tests
# ---------------------------------------------------------------------------


def test_iam_binding_dataclass():
    b = IamBinding(role="roles/editor", members=["user:a@b.com"])
    assert b.role == "roles/editor"
    assert len(b.members) == 1


def test_privesc_path_dataclass():
    p = PrivescPath(
        source_identity="sa-a@proj.iam.gserviceaccount.com",
        target_identity="sa-b@proj.iam.gserviceaccount.com",
        method="impersonation",
        permissions_used=["iam.serviceAccounts.getAccessToken"],
        description="Direct impersonation via getAccessToken",
    )
    assert p.method == "impersonation"
    assert len(p.permissions_used) == 1


def test_gcp_iam_test_result_defaults():
    r = GcpIamTestResult()
    assert r.metadata_exposed is False
    assert len(r.metadata_findings) == 0
    assert len(r.impersonation_findings) == 0


# ---------------------------------------------------------------------------
# GcpConfig integration
# ---------------------------------------------------------------------------


def test_gcp_config_defaults():
    config = GcpConfig()
    assert config.enabled is False
    assert config.project_id == ""
    assert config.target_service_account == ""
    assert config.impersonation_chain == []


def test_gcp_config_in_agent_config():
    data = {
        "gcp": {
            "enabled": True,
            "project_id": "my-project",
            "target_service_account": "sa@my-project.iam.gserviceaccount.com",
        },
        "enable_gcp_tests": True,
    }
    config = AgentConfig.from_dict(data)
    assert config.gcp.enabled is True
    assert config.gcp.project_id == "my-project"
    assert config.enable_gcp_tests is True


def test_gcp_config_to_dict():
    config = AgentConfig()
    config.gcp.project_id = "test-proj"
    config.gcp.enabled = True
    d = config.to_dict()
    assert d["gcp"]["project_id"] == "test-proj"
    assert d["gcp"]["enabled"] is True


def test_gcp_env_override(monkeypatch):
    monkeypatch.setenv("GCP_PROJECT", "env-project")
    monkeypatch.setenv("GCP_SERVICE_ACCOUNT", "sa@env-project.iam.gserviceaccount.com")
    config = AgentConfig()
    config.apply_env_overrides()
    assert config.gcp.project_id == "env-project"
    assert config.gcp.target_service_account == "sa@env-project.iam.gserviceaccount.com"
    assert config.gcp.enabled is True
    assert config.enable_gcp_tests is True


# ---------------------------------------------------------------------------
# VulnerabilityType integration
# ---------------------------------------------------------------------------


def test_gcp_vulnerability_types_exist():
    assert VulnerabilityType.GCP_IAM_BYPASS.value == "gcp_iam_bypass"
    assert VulnerabilityType.GCP_PRIVILEGE_ESCALATION.value == "gcp_privilege_escalation"


# ---------------------------------------------------------------------------
# Vuln knowledge GCP patterns
# ---------------------------------------------------------------------------


def test_gcp_iam_weakness_patterns():
    from security_agent.vuln_knowledge import get_weakness_by_cwe
    privesc = get_weakness_by_cwe("CWE-269")
    assert privesc is not None
    assert "privilege" in privesc.name.lower() or "iam" in privesc.name.lower()
    assert privesc.category == "cloud_iam"

    access = get_weakness_by_cwe("CWE-284")
    assert access is not None
    assert "access" in access.name.lower()


def test_gcp_metadata_paths_available():
    from security_agent.vuln_knowledge import GCP_METADATA_PATHS
    assert len(GCP_METADATA_PATHS) > 0
    assert any("token" in p for p in GCP_METADATA_PATHS)
    assert any("scopes" in p for p in GCP_METADATA_PATHS)
    assert any("project-id" in p for p in GCP_METADATA_PATHS)


def test_gcp_privesc_permissions_available():
    from security_agent.vuln_knowledge import GCP_PRIVESC_PERMISSIONS
    assert "iam.serviceAccounts.actAs" in GCP_PRIVESC_PERMISSIONS
    assert "iam.serviceAccounts.getAccessToken" in GCP_PRIVESC_PERMISSIONS
    assert "iam.serviceAccountKeys.create" in GCP_PRIVESC_PERMISSIONS


def test_suggest_attack_vectors_gcp_params():
    from security_agent.vuln_knowledge import suggest_attack_vectors
    suggestions = suggest_attack_vectors(
        "https://example.com/api/gcp",
        ["project_id", "service_account"],
        requires_auth=True,
    )
    cwe_ids = [s["cwe"] for s in suggestions]
    assert "CWE-269" in cwe_ids
    assert "CWE-284" in cwe_ids


def test_ssrf_payloads_include_gcp_metadata():
    from security_agent.vuln_knowledge import SSRF_PAYLOADS
    gcp_payloads = [p for p in SSRF_PAYLOADS if "metadata.google.internal" in p]
    assert len(gcp_payloads) >= 4  # token, project-id, SAs, scopes
