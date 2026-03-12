"""Tests for data models."""

from security_agent.models import (
    Endpoint,
    Finding,
    HttpRequest,
    HttpResponse,
    Severity,
    TaskStatus,
    TestTask,
    VulnerabilityType,
)


def test_http_request_to_dict():
    req = HttpRequest(
        method="POST",
        url="https://example.com/api/users",
        headers={"Authorization": "Bearer token123"},
        body='{"name": "test"}',
        cookies={"session": "abc"},
    )
    d = req.to_dict()
    assert d["method"] == "POST"
    assert d["url"] == "https://example.com/api/users"
    assert d["headers"]["Authorization"] == "Bearer token123"
    assert d["body"] == '{"name": "test"}'
    assert d["cookies"]["session"] == "abc"


def test_http_response_to_dict():
    resp = HttpResponse(status_code=200, headers={"Content-Type": "application/json"}, body='{"ok": true}')
    d = resp.to_dict()
    assert d["status_code"] == 200
    assert d["body"] == '{"ok": true}'


def test_endpoint_to_dict():
    ep = Endpoint(url="https://example.com/api/users/1", method="GET", parameters=["id"], requires_auth=True)
    d = ep.to_dict()
    assert d["url"] == "https://example.com/api/users/1"
    assert d["requires_auth"] is True


def test_finding_to_dict():
    finding = Finding(
        vulnerability_type=VulnerabilityType.IDOR,
        severity=Severity.HIGH,
        endpoint="https://example.com/api/users/1",
        description="Test finding",
        verified=True,
        reproduction_steps=["Step 1", "Step 2"],
    )
    d = finding.to_dict()
    assert d["vulnerability_type"] == "idor"
    assert d["severity"] == "high"
    assert d["verified"] is True
    assert len(d["reproduction_steps"]) == 2


def test_finding_has_unique_id():
    f1 = Finding()
    f2 = Finding()
    assert f1.id != f2.id


def test_task_defaults():
    task = TestTask()
    assert task.status == TaskStatus.PENDING
    assert task.result is None


def test_vulnerability_type_values():
    assert VulnerabilityType.IDOR.value == "idor"
    assert VulnerabilityType.RACE_CONDITION.value == "race_condition"
    assert VulnerabilityType.AUTH_BYPASS.value == "auth_bypass"
