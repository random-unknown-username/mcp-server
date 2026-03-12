"""Tests for the response analyzer."""

from security_agent.models import HttpResponse, Severity
from security_agent.response_analyzer import DiffResult, compare_responses


def test_identical_responses():
    orig = HttpResponse(status_code=200, body='{"ok": true}')
    mod = HttpResponse(status_code=200, body='{"ok": true}')
    result = compare_responses(orig, mod)
    assert not result.is_anomalous


def test_unexpected_success():
    orig = HttpResponse(status_code=403, body="Forbidden")
    mod = HttpResponse(status_code=200, body="Welcome")
    result = compare_responses(orig, mod, mutation_description="Remove auth")
    assert result.is_anomalous
    assert result.status_diff
    assert any("unexpected success" in i.lower() for i in result.indicators)
    assert result.severity == Severity.HIGH


def test_request_blocked():
    orig = HttpResponse(status_code=200, body="OK")
    mod = HttpResponse(status_code=403, body="Forbidden")
    result = compare_responses(orig, mod)
    assert result.status_diff
    assert any("blocked" in i.lower() for i in result.indicators)


def test_significant_size_change():
    orig = HttpResponse(status_code=200, body="A" * 100)
    mod = HttpResponse(status_code=200, body="A" * 200)
    result = compare_responses(orig, mod)
    assert result.is_anomalous
    assert result.size_diff_pct > 30


def test_small_size_change_not_flagged():
    orig = HttpResponse(status_code=200, body="A" * 100)
    mod = HttpResponse(status_code=200, body="A" * 110)
    result = compare_responses(orig, mod)
    assert not result.is_anomalous


def test_json_new_fields():
    orig = HttpResponse(status_code=200, body='{"name": "test"}')
    mod = HttpResponse(status_code=200, body='{"name": "test", "secret_key": "abc"}')
    result = compare_responses(orig, mod)
    assert result.is_anomalous
    assert any("secret_key" in f for f in result.json_field_diff)
    assert any("sensitive" in i.lower() for i in result.indicators)


def test_json_missing_fields():
    orig = HttpResponse(status_code=200, body='{"name": "test", "email": "a@b.com"}')
    mod = HttpResponse(status_code=200, body='{"name": "test"}')
    result = compare_responses(orig, mod)
    assert any("-email" in f for f in result.json_field_diff)


def test_error_messages_detected():
    orig = HttpResponse(status_code=200, body="OK")
    mod = HttpResponse(status_code=500, body="Internal Server Error: stack trace here")
    result = compare_responses(orig, mod)
    assert result.is_anomalous
    assert len(result.error_messages) > 0


def test_empty_bodies():
    orig = HttpResponse(status_code=200, body="")
    mod = HttpResponse(status_code=200, body="")
    result = compare_responses(orig, mod)
    assert not result.is_anomalous


def test_non_json_bodies():
    orig = HttpResponse(status_code=200, body="<html>Hello</html>")
    mod = HttpResponse(status_code=200, body="<html>Hello</html>")
    result = compare_responses(orig, mod)
    assert not result.is_anomalous
    assert len(result.json_field_diff) == 0


def test_diff_result_to_dict():
    r = DiffResult(
        is_anomalous=True,
        severity=Severity.HIGH,
        indicators=["test indicator"],
        status_diff=True,
    )
    d = r.to_dict()
    assert d["is_anomalous"] is True
    assert d["severity"] == "high"
