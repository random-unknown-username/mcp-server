"""Business logic vulnerability test engine.

Analyses checkout flows, payment validation, multi-step workflows,
discount logic, account linking, and password reset flows.
Looks for skipped steps, replay attacks, negative values, parameter
pollution, race conditions, and state desynchronization.
"""

from __future__ import annotations

import asyncio
import copy
import json
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
from .mutation_engine import MutateJsonBody, mutate_request
from .response_analyzer import compare_responses

logger = logging.getLogger(__name__)


class LogicTestEngine:
    """Tests for business logic vulnerabilities."""

    def __init__(self, burp_client: BurpMcpClient) -> None:
        self._burp = burp_client

    async def test_workflow_skip(
        self,
        workflow_steps: list[Endpoint],
        session: UserSession,
    ) -> list[Finding]:
        """Test whether steps in a multi-step workflow can be skipped."""
        findings: list[Finding] = []
        if len(workflow_steps) < 2:
            return findings

        final_step = workflow_steps[-1]
        request = _build_request(final_step, session)

        response = await self._burp.send_request(request)
        if response.status_code < 400:
            findings.append(
                Finding(
                    vulnerability_type=VulnerabilityType.WORKFLOW_BYPASS,
                    severity=Severity.HIGH,
                    endpoint=final_step.url,
                    description=(
                        f"Workflow skip: final step {final_step.url} "
                        f"accessible without completing prior steps. "
                        f"Status: {response.status_code}"
                    ),
                    modified_request=request,
                    modified_response=response,
                    reproduction_steps=[
                        "Skip to the final step of the workflow",
                        f"Send request directly to {final_step.url}",
                        f"Observe status {response.status_code} (expected >= 400)",
                    ],
                )
            )
        return findings

    async def test_negative_values(
        self,
        endpoint: Endpoint,
        session: UserSession,
        numeric_fields: list[str],
    ) -> list[Finding]:
        """Test whether negative numeric values are accepted."""
        findings: list[Finding] = []
        base_request = _build_request(endpoint, session)
        original_response = await self._burp.send_request(base_request)

        for field_name in numeric_fields:
            for bad_value in [-1, -9999, 0]:
                mutation = MutateJsonBody(field_name, bad_value)
                mutated = mutate_request(base_request, mutation)
                response = await self._burp.send_request(mutated)
                diff = compare_responses(
                    original_response,
                    response,
                    mutation_description=f"{field_name}={bad_value}",
                )
                if response.status_code < 400:
                    findings.append(
                        Finding(
                            vulnerability_type=VulnerabilityType.BUSINESS_LOGIC,
                            severity=Severity.MEDIUM,
                            endpoint=endpoint.url,
                            description=(
                                f"Negative value accepted: {field_name}={bad_value}. "
                                f"Status: {response.status_code}. "
                                f"Diff: {diff.indicators}"
                            ),
                            original_request=base_request,
                            modified_request=mutated,
                            original_response=original_response,
                            modified_response=response,
                            reproduction_steps=[
                                f"Send request to {endpoint.url}",
                                f"Set {field_name} = {bad_value}",
                                "Observe that the server accepts the request",
                            ],
                        )
                    )
        return findings

    async def test_replay(
        self,
        endpoint: Endpoint,
        session: UserSession,
        *,
        replay_count: int = 3,
    ) -> list[Finding]:
        """Replay the same request to detect replay attacks."""
        findings: list[Finding] = []
        request = _build_request(endpoint, session)

        first_response = await self._burp.send_request(request)
        success_count = 1 if first_response.status_code < 400 else 0

        for _ in range(replay_count):
            response = await self._burp.send_request(request)
            if response.status_code < 400:
                success_count += 1

        if success_count > 1:
            findings.append(
                Finding(
                    vulnerability_type=VulnerabilityType.BUSINESS_LOGIC,
                    severity=Severity.MEDIUM,
                    endpoint=endpoint.url,
                    description=(
                        f"Replay attack: {success_count}/{replay_count + 1} "
                        f"identical requests succeeded at {endpoint.url}"
                    ),
                    modified_request=request,
                    reproduction_steps=[
                        f"Send request to {endpoint.url}",
                        f"Replay the same request {replay_count} more times",
                        f"Observe that {success_count} requests succeeded",
                    ],
                )
            )
        return findings

    async def test_race_condition(
        self,
        endpoint: Endpoint,
        session: UserSession,
        *,
        concurrency: int = 5,
    ) -> list[Finding]:
        """Fire concurrent requests to detect race conditions."""
        findings: list[Finding] = []
        request = _build_request(endpoint, session)

        async def _fire() -> int:
            resp = await self._burp.send_request(request)
            return resp.status_code

        results = await asyncio.gather(*[_fire() for _ in range(concurrency)])
        success_count = sum(1 for s in results if s < 400)

        if success_count > 1:
            findings.append(
                Finding(
                    vulnerability_type=VulnerabilityType.RACE_CONDITION,
                    severity=Severity.HIGH,
                    endpoint=endpoint.url,
                    description=(
                        f"Race condition: {success_count}/{concurrency} "
                        f"concurrent requests succeeded at {endpoint.url}"
                    ),
                    modified_request=request,
                    reproduction_steps=[
                        f"Send {concurrency} concurrent requests to {endpoint.url}",
                        f"Observe that {success_count} requests succeeded",
                    ],
                )
            )
        return findings

    async def test_parameter_pollution(
        self,
        endpoint: Endpoint,
        session: UserSession,
        param_name: str,
        values: list[str],
    ) -> list[Finding]:
        """Test HTTP parameter pollution by sending duplicate parameters."""
        findings: list[Finding] = []
        base_request = _build_request(endpoint, session)
        original_response = await self._burp.send_request(base_request)

        polluted = copy.deepcopy(base_request)
        separator = "&" if "?" in polluted.url else "?"
        extra = "&".join(f"{param_name}={v}" for v in values)
        polluted.url = f"{polluted.url}{separator}{extra}"

        response = await self._burp.send_request(polluted)
        diff = compare_responses(
            original_response,
            response,
            mutation_description=f"parameter pollution: {param_name}",
        )
        if diff.is_anomalous:
            findings.append(
                Finding(
                    vulnerability_type=VulnerabilityType.PARAMETER_POLLUTION,
                    severity=diff.severity,
                    endpoint=endpoint.url,
                    description=(
                        f"Parameter pollution on {param_name}: "
                        f"Indicators: {diff.indicators}"
                    ),
                    original_request=base_request,
                    modified_request=polluted,
                    original_response=original_response,
                    modified_response=response,
                    reproduction_steps=[
                        f"Send request to {endpoint.url}",
                        f"Add duplicate parameter: {extra}",
                        "Compare responses",
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
