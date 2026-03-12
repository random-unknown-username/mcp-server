"""Tests for the injection test engine helpers."""

from security_agent.injection_test_engine import (
    _inject_into_json_field,
    _inject_into_param,
    _inject_into_path,
    _is_json,
    _json_keys,
)
from security_agent.models import HttpRequest


def _make_request(**kwargs):
    defaults = {
        "method": "GET",
        "url": "https://example.com/api/items/42?search=test&page=1",
        "headers": {"Authorization": "Bearer tok"},
    }
    defaults.update(kwargs)
    return HttpRequest(**defaults)


def test_inject_into_param():
    req = _make_request()
    mutated = _inject_into_param(req, "search", "<script>alert(1)</script>")
    # urlencode will percent-encode special characters
    assert "search=" in mutated.url
    assert "alert" in mutated.url
    # Original should not be modified
    assert "alert" not in req.url


def test_inject_into_param_new():
    req = _make_request(url="https://example.com/api/items")
    mutated = _inject_into_param(req, "q", "' OR '1'='1")
    assert "q=" in mutated.url
    assert "OR" in mutated.url


def test_inject_into_path():
    req = _make_request(url="https://example.com/api/items/42")
    mutated = _inject_into_path(req, "../../../etc/passwd")
    assert mutated is not None
    assert "etc/passwd" in mutated.url
    assert "/api/items/" in mutated.url


def test_inject_into_path_too_short():
    req = _make_request(url="https://example.com/")
    result = _inject_into_path(req, "../etc/passwd")
    assert result is None


def test_inject_into_json_field():
    req = _make_request(body='{"name": "test", "role": "user"}')
    mutated = _inject_into_json_field(req, "name", "<script>alert(1)</script>")
    assert mutated is not None
    import json
    data = json.loads(mutated.body)
    assert data["name"] == "<script>alert(1)</script>"
    assert data["role"] == "user"  # untouched


def test_inject_into_json_field_missing_key():
    req = _make_request(body='{"name": "test"}')
    result = _inject_into_json_field(req, "nonexistent", "payload")
    assert result is None


def test_inject_into_json_field_no_body():
    req = _make_request(body=None)
    result = _inject_into_json_field(req, "name", "payload")
    assert result is None


def test_inject_into_json_field_non_json():
    req = _make_request(body="not json")
    result = _inject_into_json_field(req, "name", "payload")
    assert result is None


def test_is_json_valid():
    assert _is_json('{"key": "value"}')
    assert _is_json('[]')
    assert _is_json('"string"')


def test_is_json_invalid():
    assert not _is_json("not json")
    assert not _is_json("")
    assert not _is_json(None)


def test_json_keys():
    keys = _json_keys('{"name": "test", "role": "user", "id": 1}')
    assert "name" in keys
    assert "role" in keys
    assert "id" in keys


def test_json_keys_empty():
    assert _json_keys("") == []
    assert _json_keys("not json") == []
    assert _json_keys("[]") == []
