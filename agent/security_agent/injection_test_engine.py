"""Injection vulnerability test engine.

Tests for XSS, SQL injection, SSRF, SSTI, path traversal, open redirect,
CORS misconfiguration, and header injection using payloads from the
vulnerability knowledge base.
"""

from __future__ import annotations

import copy
import logging
import re
from typing import Any
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from .burp_mcp_client import BurpMcpClient
from .models import (
    Endpoint,
    Finding,
    HttpRequest,
    HttpResponse,
    Severity,
    UserSession,
    VulnerabilityType,
)
from .vuln_knowledge import (
    WeaknessPattern,
    check_response_for_weakness,
    get_weakness_by_cwe,
    CORS_ORIGINS,
)

logger = logging.getLogger(__name__)


_CWE_TO_VULN: dict[str, VulnerabilityType] = {
    "CWE-79": VulnerabilityType.XSS,
    "CWE-89": VulnerabilityType.SQLI,
    "CWE-918": VulnerabilityType.SSRF,
    "CWE-1336": VulnerabilityType.SSTI,
    "CWE-22": VulnerabilityType.PATH_TRAVERSAL,
    "CWE-601": VulnerabilityType.OPEN_REDIRECT,
    "CWE-942": VulnerabilityType.CORS_MISCONFIGURATION,
    "CWE-113": VulnerabilityType.HEADER_INJECTION,
}

_CWE_TO_SEVERITY: dict[str, Severity] = {
    "CWE-79": Severity.MEDIUM,
    "CWE-89": Severity.CRITICAL,
    "CWE-918": Severity.HIGH,
    "CWE-1336": Severity.CRITICAL,
    "CWE-22": Severity.HIGH,
    "CWE-601": Severity.MEDIUM,
    "CWE-942": Severity.MEDIUM,
    "CWE-113": Severity.MEDIUM,
}


class InjectionTestEngine:
    """Tests endpoints for injection vulnerabilities."""

    def __init__(self, burp_client: BurpMcpClient) -> None:
        self._burp = burp_client

    async def test_endpoint(
        self,
        endpoint: Endpoint,
        session: UserSession,
        *,
        cwe_ids: list[str] | None = None,
    ) -> list[Finding]:
        """Test *endpoint* for injection vulnerabilities.

        If *cwe_ids* is provided only those weakness classes are tested,
        otherwise all applicable classes are tested.
        """
        findings: list[Finding] = []
        base_request = _build_request(endpoint, session)

        targets = cwe_ids or [
            "CWE-79", "CWE-89", "CWE-918", "CWE-1336",
            "CWE-22", "CWE-601", "CWE-113",
        ]

        for cwe_id in targets:
            weakness = get_weakness_by_cwe(cwe_id)
            if weakness is None:
                continue
            new_findings = await self._test_weakness(
                base_request, endpoint, weakness
            )
            findings.extend(new_findings)

        # Always test CORS separately
        if cwe_ids is None or "CWE-942" in (cwe_ids or []):
            cors_findings = await self._test_cors(base_request, endpoint)
            findings.extend(cors_findings)

        return findings

    async def _test_weakness(
        self,
        base_request: HttpRequest,
        endpoint: Endpoint,
        weakness: WeaknessPattern,
    ) -> list[Finding]:
        """Inject payloads from *weakness* into query params and body."""
        findings: list[Finding] = []

        # Get baseline response
        try:
            original_response = await self._burp.send_request(base_request)
        except Exception as exc:
            logger.warning("Baseline request failed: %s", exc)
            return findings

        for payload in weakness.payloads[:5]:  # cap per weakness to avoid excess
            # Test in query parameters
            for param in endpoint.parameters:
                mutated = _inject_into_param(base_request, param, payload)
                finding = await self._fire_and_check(
                    mutated, original_response, endpoint, weakness,
                    f"Injected {weakness.name} payload into param '{param}'",
                )
                if finding:
                    findings.append(finding)

            # Test in URL path segments (for path traversal, SSRF)
            if weakness.cwe_id in ("CWE-22", "CWE-918"):
                mutated = _inject_into_path(base_request, payload)
                if mutated:
                    finding = await self._fire_and_check(
                        mutated, original_response, endpoint, weakness,
                        f"Injected {weakness.name} payload into URL path",
                    )
                    if finding:
                        findings.append(finding)

            # Test in JSON body fields
            if base_request.body and _is_json(base_request.body):
                for key in _json_keys(base_request.body):
                    mutated = _inject_into_json_field(
                        base_request, key, payload
                    )
                    if mutated:
                        finding = await self._fire_and_check(
                            mutated, original_response, endpoint, weakness,
                            f"Injected {weakness.name} payload into JSON field '{key}'",
                        )
                        if finding:
                            findings.append(finding)

        return findings

    async def _fire_and_check(
        self,
        mutated: HttpRequest,
        original_response: HttpResponse,
        endpoint: Endpoint,
        weakness: WeaknessPattern,
        description: str,
    ) -> Finding | None:
        """Send the mutated request and check for weakness indicators."""
        try:
            response = await self._burp.send_request(mutated)
        except Exception:
            return None

        hits = check_response_for_weakness(
            response.body, response.headers, weakness
        )

        # For open redirect check the Location header
        if weakness.cwe_id == "CWE-601":
            location = response.headers.get(
                "Location", response.headers.get("location", "")
            )
            if location and any(
                p in location for p in ("evil.com", "//evil")
            ):
                hits.append(f"Open redirect to: {location}")

        # For reflected XSS check if payload appears in response
        if weakness.cwe_id == "CWE-79" and mutated.body:
            # Check if any XSS payload is reflected
            for payload in weakness.payloads[:3]:
                if payload in (response.body or ""):
                    hits.append(f"XSS payload reflected in response: {payload[:50]}")
                    break

        if hits:
            vuln_type = _CWE_TO_VULN.get(
                weakness.cwe_id, VulnerabilityType.INFORMATION_DISCLOSURE
            )
            severity = _CWE_TO_SEVERITY.get(weakness.cwe_id, Severity.MEDIUM)
            return Finding(
                vulnerability_type=vuln_type,
                severity=severity,
                endpoint=endpoint.url,
                description=f"{description}. Indicators: {hits}",
                original_request=None,
                modified_request=mutated,
                original_response=original_response,
                modified_response=response,
                reproduction_steps=[
                    f"Send request to {endpoint.url}",
                    f"Inject payload: {description}",
                    f"Observe indicators: {'; '.join(hits)}",
                ],
            )
        return None

    async def _test_cors(
        self,
        base_request: HttpRequest,
        endpoint: Endpoint,
    ) -> list[Finding]:
        """Test CORS misconfiguration by sending evil Origin headers."""
        findings: list[Finding] = []
        for origin in CORS_ORIGINS:
            mutated = copy.deepcopy(base_request)
            mutated.headers["Origin"] = origin
            try:
                response = await self._burp.send_request(mutated)
            except Exception:
                continue

            acao = response.headers.get(
                "Access-Control-Allow-Origin",
                response.headers.get("access-control-allow-origin", ""),
            )
            acac = response.headers.get(
                "Access-Control-Allow-Credentials",
                response.headers.get("access-control-allow-credentials", ""),
            )

            if acao and (acao == origin or acao == "*"):
                desc = f"CORS reflects origin '{origin}'"
                sev = Severity.MEDIUM
                if acac and acac.lower() == "true":
                    desc += " with credentials allowed"
                    sev = Severity.HIGH
                findings.append(Finding(
                    vulnerability_type=VulnerabilityType.CORS_MISCONFIGURATION,
                    severity=sev,
                    endpoint=endpoint.url,
                    description=desc,
                    modified_request=mutated,
                    modified_response=response,
                    reproduction_steps=[
                        f"Send request to {endpoint.url} with Origin: {origin}",
                        f"Observe ACAO={acao}, ACAC={acac}",
                    ],
                ))
        return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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


def _inject_into_param(
    request: HttpRequest, param: str, payload: str
) -> HttpRequest:
    """Inject *payload* into a query-string parameter."""
    mutated = copy.deepcopy(request)
    parsed = urlparse(mutated.url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [payload]
    new_query = urlencode(params, doseq=True)
    mutated.url = urlunparse(parsed._replace(query=new_query))
    return mutated


def _inject_into_path(
    request: HttpRequest, payload: str
) -> HttpRequest | None:
    """Replace the last path segment with *payload*."""
    mutated = copy.deepcopy(request)
    parsed = urlparse(mutated.url)
    segments = parsed.path.rstrip("/").split("/")
    if len(segments) < 2:
        return None
    segments[-1] = payload
    new_path = "/".join(segments)
    mutated.url = urlunparse(parsed._replace(path=new_path))
    return mutated


def _inject_into_json_field(
    request: HttpRequest, key: str, payload: str
) -> HttpRequest | None:
    """Set a JSON body field to *payload*."""
    import json
    mutated = copy.deepcopy(request)
    try:
        data = json.loads(mutated.body)
    except (json.JSONDecodeError, TypeError):
        return None
    if isinstance(data, dict) and key in data:
        data[key] = payload
        mutated.body = json.dumps(data)
        return mutated
    return None


def _is_json(body: str | None) -> bool:
    if not body:
        return False
    import json
    try:
        json.loads(body)
        return True
    except (json.JSONDecodeError, TypeError):
        return False


def _json_keys(body: str) -> list[str]:
    import json
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            return list(data.keys())
    except (json.JSONDecodeError, TypeError):
        pass
    return []
