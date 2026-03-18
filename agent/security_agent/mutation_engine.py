"""Intelligent request mutation engine.

Mutates IDs, JWT claims, headers, cookies, JSON bodies and hidden form
values to test for auth bypass, IDOR, privilege escalation and other
access control issues.
"""

from __future__ import annotations

import base64
import copy
import json
import logging
import re
from typing import Any

from .models import HttpRequest

logger = logging.getLogger(__name__)


def mutate_request(
    request: HttpRequest,
    mutation: Mutation,
) -> HttpRequest:
    """Apply a single *Mutation* to a request and return the result."""
    mutated = copy.deepcopy(request)
    mutation.apply(mutated)
    return mutated


class Mutation:
    """Base class for request mutations."""

    name: str = "base"

    def apply(self, request: HttpRequest) -> None:
        raise NotImplementedError


class ReplaceId(Mutation):
    """Replace a numeric or UUID-like ID in the URL or body."""

    name = "replace_id"

    def __init__(self, original: str, replacement: str) -> None:
        self.original = original
        self.replacement = replacement

    def apply(self, request: HttpRequest) -> None:
        request.url = request.url.replace(self.original, self.replacement)
        if request.body:
            request.body = request.body.replace(self.original, self.replacement)


class SwapHeader(Mutation):
    """Replace or remove a header value."""

    name = "swap_header"

    def __init__(self, header: str, new_value: str | None) -> None:
        self.header = header
        self.new_value = new_value

    def apply(self, request: HttpRequest) -> None:
        if self.new_value is None:
            request.headers.pop(self.header, None)
        else:
            request.headers[self.header] = self.new_value


class SwapCookie(Mutation):
    """Replace or remove a cookie."""

    name = "swap_cookie"

    def __init__(self, cookie: str, new_value: str | None) -> None:
        self.cookie = cookie
        self.new_value = new_value

    def apply(self, request: HttpRequest) -> None:
        if self.new_value is None:
            request.cookies.pop(self.cookie, None)
        else:
            request.cookies[self.cookie] = self.new_value


class MutateJsonBody(Mutation):
    """Change a value inside a JSON body."""

    name = "mutate_json_body"

    def __init__(self, key_path: str, new_value: Any) -> None:
        self.key_path = key_path
        self.new_value = new_value

    def apply(self, request: HttpRequest) -> None:
        if not request.body:
            return
        try:
            data = json.loads(request.body)
        except (json.JSONDecodeError, TypeError):
            return
        keys = self.key_path.split(".")
        obj = data
        for key in keys[:-1]:
            if isinstance(obj, dict) and key in obj:
                obj = obj[key]
            else:
                return
        if isinstance(obj, dict):
            obj[keys[-1]] = self.new_value
        request.body = json.dumps(data)


class MutateJwt(Mutation):
    """Modify claims in a JWT token found in the Authorization header.

    *WARNING*: the resulting token is unsigned / uses ``alg: none``.
    This is intentional – it tests whether the server validates signatures.
    """

    name = "mutate_jwt"

    def __init__(self, claim_overrides: dict[str, Any]) -> None:
        self.claim_overrides = claim_overrides

    def apply(self, request: HttpRequest) -> None:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return
        token = auth[7:]
        parts = token.split(".")
        if len(parts) != 3:
            return
        try:
            header_b = _b64_decode(parts[0])
            payload_b = _b64_decode(parts[1])
            header_data = json.loads(header_b)
            payload_data = json.loads(payload_b)
        except Exception:
            return
        header_data["alg"] = "none"
        payload_data.update(self.claim_overrides)
        new_header = _b64_encode(json.dumps(header_data))
        new_payload = _b64_encode(json.dumps(payload_data))
        request.headers["Authorization"] = f"Bearer {new_header}.{new_payload}."


class RemoveAuth(Mutation):
    """Strip all authentication headers and cookies."""

    name = "remove_auth"

    def apply(self, request: HttpRequest) -> None:
        for hdr in ("Authorization", "authorization", "Cookie", "cookie"):
            request.headers.pop(hdr, None)
        request.cookies.clear()


def generate_idor_mutations(
    request: HttpRequest,
    replacement_ids: list[str] | None = None,
) -> list[tuple[Mutation, str]]:
    """Detect numeric/UUID IDs in the URL/body and yield mutations."""
    if replacement_ids is None:
        replacement_ids = []
    mutations: list[tuple[Mutation, str]] = []
    id_pattern = re.compile(
        r"(?<=/)\d+(?=/|$|\?)|"
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        re.IGNORECASE,
    )
    found_ids = id_pattern.findall(request.url)
    if request.body:
        found_ids.extend(id_pattern.findall(request.body))
    for original_id in set(found_ids):
        for repl_id in replacement_ids:
            m = ReplaceId(original_id, repl_id)
            mutations.append(
                (m, f"Replace ID {original_id} → {repl_id}")
            )
        if original_id.isdigit():
            incremented = str(int(original_id) + 1)
            m = ReplaceId(original_id, incremented)
            mutations.append(
                (m, f"Increment ID {original_id} → {incremented}")
            )
    return mutations


def generate_auth_mutations(
    request: HttpRequest,
    other_session_headers: dict[str, str] | None = None,
) -> list[tuple[Mutation, str]]:
    """Generate mutations targeting authentication/authorization."""
    mutations: list[tuple[Mutation, str]] = []
    mutations.append((RemoveAuth(), "Remove all authentication"))
    if "Authorization" in request.headers:
        auth = request.headers["Authorization"]
        if auth.startswith("Bearer "):
            mutations.append(
                (MutateJwt({"role": "admin"}), "JWT role → admin")
            )
            mutations.append(
                (MutateJwt({"admin": True}), "JWT admin claim → true")
            )
    if other_session_headers:
        for hdr, val in other_session_headers.items():
            mutations.append(
                (SwapHeader(hdr, val), f"Swap {hdr} to other session")
            )
    return mutations


def _b64_decode(data: str) -> bytes:
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _b64_encode(data: str) -> str:
    return base64.urlsafe_b64encode(data.encode()).rstrip(b"=").decode()
