"""Tests for the mutation engine."""

import json

from security_agent.models import HttpRequest
from security_agent.mutation_engine import (
    MutateJsonBody,
    MutateJwt,
    RemoveAuth,
    ReplaceId,
    SwapCookie,
    SwapHeader,
    generate_auth_mutations,
    generate_idor_mutations,
    mutate_request,
    _b64_encode,
)


def _make_request(**kwargs):
    defaults = {
        "method": "GET",
        "url": "https://example.com/api/users/123",
        "headers": {"Authorization": "Bearer tok"},
        "cookies": {"session": "abc"},
    }
    defaults.update(kwargs)
    return HttpRequest(**defaults)


def test_replace_id_in_url():
    req = _make_request()
    mutation = ReplaceId("123", "456")
    result = mutate_request(req, mutation)
    assert "456" in result.url
    assert "123" not in result.url
    # Original unchanged
    assert "123" in req.url


def test_replace_id_in_body():
    req = _make_request(body='{"user_id": "123"}')
    mutation = ReplaceId("123", "999")
    result = mutate_request(req, mutation)
    assert "999" in result.body
    assert "123" not in result.body


def test_swap_header():
    req = _make_request()
    mutation = SwapHeader("Authorization", "Bearer other_token")
    result = mutate_request(req, mutation)
    assert result.headers["Authorization"] == "Bearer other_token"


def test_swap_header_remove():
    req = _make_request()
    mutation = SwapHeader("Authorization", None)
    result = mutate_request(req, mutation)
    assert "Authorization" not in result.headers


def test_swap_cookie():
    req = _make_request()
    mutation = SwapCookie("session", "xyz")
    result = mutate_request(req, mutation)
    assert result.cookies["session"] == "xyz"


def test_swap_cookie_remove():
    req = _make_request()
    mutation = SwapCookie("session", None)
    result = mutate_request(req, mutation)
    assert "session" not in result.cookies


def test_mutate_json_body():
    req = _make_request(body='{"role": "user", "name": "test"}')
    mutation = MutateJsonBody("role", "admin")
    result = mutate_request(req, mutation)
    data = json.loads(result.body)
    assert data["role"] == "admin"
    assert data["name"] == "test"


def test_mutate_json_body_nested():
    req = _make_request(body='{"user": {"role": "viewer"}}')
    mutation = MutateJsonBody("user.role", "admin")
    result = mutate_request(req, mutation)
    data = json.loads(result.body)
    assert data["user"]["role"] == "admin"


def test_mutate_json_body_no_body():
    req = _make_request(body=None)
    mutation = MutateJsonBody("role", "admin")
    result = mutate_request(req, mutation)
    assert result.body is None


def test_mutate_json_body_non_json():
    req = _make_request(body="not json")
    mutation = MutateJsonBody("role", "admin")
    result = mutate_request(req, mutation)
    assert result.body == "not json"


def test_mutate_jwt():
    header = _b64_encode('{"alg": "HS256", "typ": "JWT"}')
    payload = _b64_encode('{"sub": "user1", "role": "user"}')
    token = f"{header}.{payload}.signature"
    req = _make_request(headers={"Authorization": f"Bearer {token}"})

    mutation = MutateJwt({"role": "admin"})
    result = mutate_request(req, mutation)

    new_token = result.headers["Authorization"][7:]
    parts = new_token.split(".")
    assert len(parts) == 3
    # Payload should have role=admin
    import base64
    decoded = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    assert decoded["role"] == "admin"
    # Header should have alg=none
    decoded_header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    assert decoded_header["alg"] == "none"


def test_remove_auth():
    req = _make_request(
        headers={"Authorization": "Bearer tok", "Cookie": "session=abc"},
        cookies={"session": "abc"},
    )
    mutation = RemoveAuth()
    result = mutate_request(req, mutation)
    assert "Authorization" not in result.headers
    assert "Cookie" not in result.headers
    assert len(result.cookies) == 0


def test_generate_idor_mutations_numeric():
    req = _make_request(url="https://example.com/api/users/42/profile")
    mutations = generate_idor_mutations(req)
    descriptions = [d for _, d in mutations]
    assert any("42" in d and "43" in d for d in descriptions)


def test_generate_idor_mutations_with_replacements():
    req = _make_request(url="https://example.com/api/users/42")
    mutations = generate_idor_mutations(req, replacement_ids=["99", "100"])
    assert len(mutations) >= 3  # 2 replacements + 1 increment


def test_generate_idor_mutations_uuid():
    uuid_val = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    req = _make_request(url=f"https://example.com/api/items/{uuid_val}")
    mutations = generate_idor_mutations(req, replacement_ids=["00000000-0000-0000-0000-000000000000"])
    assert len(mutations) >= 1


def test_generate_auth_mutations():
    req = _make_request()
    mutations = generate_auth_mutations(req)
    descriptions = [d for _, d in mutations]
    assert any("Remove" in d for d in descriptions)


def test_generate_auth_mutations_with_jwt():
    header = _b64_encode('{"alg": "HS256"}')
    payload = _b64_encode('{"role": "user"}')
    token = f"{header}.{payload}.sig"
    req = _make_request(headers={"Authorization": f"Bearer {token}"})
    mutations = generate_auth_mutations(req)
    descriptions = [d for _, d in mutations]
    assert any("JWT" in d for d in descriptions)


def test_generate_auth_mutations_other_session():
    req = _make_request()
    other = {"Authorization": "Bearer other_tok"}
    mutations = generate_auth_mutations(req, other_session_headers=other)
    descriptions = [d for _, d in mutations]
    assert any("other session" in d.lower() for d in descriptions)
