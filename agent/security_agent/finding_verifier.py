"""Vulnerability verification module.

When a potential bug is found, the verifier repeats the attack,
performs cross-account validation, creates a PoC request, and
saves reproduction steps.
"""

from __future__ import annotations

import logging

from .burp_mcp_client import BurpMcpClient
from .models import Finding, UserSession
from .mutation_engine import mutate_request, generate_idor_mutations, ReplaceId
from .response_analyzer import compare_responses

logger = logging.getLogger(__name__)

_VERIFICATION_ATTEMPTS = 3


class FindingVerifier:
    """Attempts to confirm or reject a potential finding."""

    def __init__(self, burp_client: BurpMcpClient) -> None:
        self._burp = burp_client

    async def verify(
        self,
        finding: Finding,
        *,
        cross_session: UserSession | None = None,
    ) -> Finding:
        """Try to reproduce the finding and optionally cross-validate."""
        if finding.modified_request is None:
            return finding

        success_count = 0
        for _ in range(_VERIFICATION_ATTEMPTS):
            response = await self._burp.send_request(finding.modified_request)
            if finding.original_response is not None:
                diff = compare_responses(finding.original_response, response)
                if diff.is_anomalous:
                    success_count += 1
            elif response.status_code < 400:
                success_count += 1

        if success_count >= 2:
            finding.verified = True
            finding.reproduction_steps.append(
                f"Verified: reproduced {success_count}/{_VERIFICATION_ATTEMPTS} times"
            )
            logger.info("Finding %s VERIFIED", finding.id)
        else:
            finding.verified = False
            finding.reproduction_steps.append(
                f"Unverified: only reproduced {success_count}/{_VERIFICATION_ATTEMPTS} times"
            )
            logger.info("Finding %s NOT verified", finding.id)

        if cross_session and finding.verified:
            await self._cross_validate(finding, cross_session)

        return finding

    async def _cross_validate(
        self, finding: Finding, session: UserSession
    ) -> None:
        if finding.modified_request is None:
            return
        from .auth_test_engine import _build_request
        from .models import Endpoint

        cross_request = finding.modified_request
        cross_request.headers.update(session.headers)
        cross_request.cookies.update(session.cookies)
        for k, v in session.tokens.items():
            cross_request.headers[k] = v

        response = await self._burp.send_request(cross_request)
        if response.status_code < 400:
            finding.reproduction_steps.append(
                f"Cross-account validation: request succeeded with different user "
                f"(status {response.status_code})"
            )
