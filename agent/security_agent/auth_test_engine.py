"""Authentication and authorization test engine.

Tests for IDOR, privilege escalation, broken access control,
horizontal/vertical access violations, and session handling issues.
"""

from __future__ import annotations

import logging
from typing import Any

from .burp_mcp_client import BurpMcpClient
from .models import (
    Endpoint,
    Finding,
    HttpRequest,
    Severity,
    UserSession,
    VulnerabilityType,
)
from .mutation_engine import (
    RemoveAuth,
    generate_auth_mutations,
    generate_idor_mutations,
    mutate_request,
)
from .response_analyzer import compare_responses

logger = logging.getLogger(__name__)


class AuthTestEngine:
    """Runs authentication and authorization tests against endpoints."""

    def __init__(self, burp_client: BurpMcpClient) -> None:
        self._burp = burp_client

    async def test_endpoint(
        self,
        endpoint: Endpoint,
        primary_session: UserSession,
        *,
        secondary_session: UserSession | None = None,
        replacement_ids: list[str] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        base_request = _build_request(endpoint, primary_session)

        original_response = await self._burp.send_request(base_request)

        findings.extend(
            await self._test_idor(
                base_request, original_response, endpoint, replacement_ids
            )
        )

        findings.extend(
            await self._test_auth_bypass(
                base_request, original_response, endpoint
            )
        )

        if secondary_session:
            findings.extend(
                await self._test_horizontal_access(
                    base_request,
                    original_response,
                    endpoint,
                    secondary_session,
                )
            )

        return findings

    async def _test_idor(
        self,
        base_request: HttpRequest,
        original_response: Any,
        endpoint: Endpoint,
        replacement_ids: list[str] | None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        mutations = generate_idor_mutations(base_request, replacement_ids)
        for mutation, description in mutations:
            mutated = mutate_request(base_request, mutation)
            response = await self._burp.send_request(mutated)
            diff = compare_responses(
                original_response, response, mutation_description=description
            )
            if diff.is_anomalous:
                findings.append(
                    Finding(
                        vulnerability_type=VulnerabilityType.IDOR,
                        severity=diff.severity,
                        endpoint=endpoint.url,
                        description=(
                            f"Potential IDOR: {description}. "
                            f"Indicators: {diff.indicators}"
                        ),
                        original_request=base_request,
                        modified_request=mutated,
                        original_response=original_response,
                        modified_response=response,
                        reproduction_steps=[
                            f"Send original request to {endpoint.url}",
                            f"Apply mutation: {description}",
                            "Compare responses for data leakage",
                        ],
                    )
                )
        return findings

    async def _test_auth_bypass(
        self,
        base_request: HttpRequest,
        original_response: Any,
        endpoint: Endpoint,
    ) -> list[Finding]:
        findings: list[Finding] = []
        mutations = generate_auth_mutations(base_request)
        for mutation, description in mutations:
            mutated = mutate_request(base_request, mutation)
            response = await self._burp.send_request(mutated)
            diff = compare_responses(
                original_response, response, mutation_description=description
            )
            if diff.is_anomalous and "unexpected success" in " ".join(
                diff.indicators
            ).lower():
                vuln_type = (
                    VulnerabilityType.AUTH_BYPASS
                    if isinstance(mutation, RemoveAuth)
                    else VulnerabilityType.BROKEN_ACCESS_CONTROL
                )
                findings.append(
                    Finding(
                        vulnerability_type=vuln_type,
                        severity=Severity.HIGH,
                        endpoint=endpoint.url,
                        description=(
                            f"Auth bypass: {description}. "
                            f"Indicators: {diff.indicators}"
                        ),
                        original_request=base_request,
                        modified_request=mutated,
                        original_response=original_response,
                        modified_response=response,
                        reproduction_steps=[
                            f"Send authenticated request to {endpoint.url}",
                            f"Apply mutation: {description}",
                            "Observe that the server still returns success",
                        ],
                    )
                )
        return findings

    async def _test_horizontal_access(
        self,
        base_request: HttpRequest,
        original_response: Any,
        endpoint: Endpoint,
        other_session: UserSession,
    ) -> list[Finding]:
        findings: list[Finding] = []
        other_headers = {**other_session.headers}
        for k, v in other_session.tokens.items():
            other_headers[k] = v
        mutations = generate_auth_mutations(
            base_request, other_session_headers=other_headers
        )
        for mutation, description in mutations:
            if "other session" not in description.lower():
                continue
            mutated = mutate_request(base_request, mutation)
            response = await self._burp.send_request(mutated)
            diff = compare_responses(
                original_response, response, mutation_description=description
            )
            if diff.is_anomalous:
                findings.append(
                    Finding(
                        vulnerability_type=VulnerabilityType.HORIZONTAL_ACCESS,
                        severity=Severity.HIGH,
                        endpoint=endpoint.url,
                        description=(
                            f"Horizontal access: {description}. "
                            f"User B can access User A data. "
                            f"Indicators: {diff.indicators}"
                        ),
                        original_request=base_request,
                        modified_request=mutated,
                        original_response=original_response,
                        modified_response=response,
                        reproduction_steps=[
                            f"Send request as User A to {endpoint.url}",
                            f"Swap session to User B: {description}",
                            "Observe whether User B receives User A data",
                        ],
                    )
                )
        return findings


def _build_request(endpoint: Endpoint, session: UserSession) -> HttpRequest:
    headers = dict(session.headers)
    for k, v in session.tokens.items():
        headers[k] = v
    return HttpRequest(
        method=endpoint.method,
        url=endpoint.url,
        headers=headers,
        cookies=dict(session.cookies),
    )
