"""Reconnaissance engine.

Performs passive and active recon through Burp proxy history and
direct probing: technology fingerprinting, security header analysis,
interesting path discovery, and subdomain/asset enumeration hints.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from .burp_mcp_client import BurpMcpClient
from .models import HttpResponse

logger = logging.getLogger(__name__)


# Well-known paths worth probing
INTERESTING_PATHS = [
    "/.env",
    "/.git/config",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/server-status",
    "/server-info",
    "/wp-json/wp/v2/users",
    "/api/swagger.json",
    "/api/v1/swagger.json",
    "/swagger-ui.html",
    "/openapi.json",
    "/graphql",
    "/graphql/playground",
    "/_debug",
    "/debug/pprof",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/info",
    "/trace",
    "/console",
    "/admin",
    "/phpmyadmin",
    "/.DS_Store",
    "/crossdomain.xml",
    "/elmah.axd",
    "/.htaccess",
    "/web.config",
    "/WEB-INF/web.xml",
]


@dataclass
class TechFingerprint:
    """Detected technology on the target."""

    name: str
    version: str = ""
    source: str = ""  # where we detected it (header, body, etc.)


@dataclass
class SecurityHeaderAudit:
    """Audit result for security-relevant HTTP headers."""

    missing_headers: list[str] = field(default_factory=list)
    weak_headers: list[str] = field(default_factory=list)
    info_leaks: list[str] = field(default_factory=list)


@dataclass
class ReconResult:
    """Aggregated recon findings."""

    technologies: list[TechFingerprint] = field(default_factory=list)
    security_headers: SecurityHeaderAudit = field(
        default_factory=SecurityHeaderAudit
    )
    interesting_paths: list[dict[str, Any]] = field(default_factory=list)
    discovered_endpoints: list[str] = field(default_factory=list)
    cors_policy: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "technologies": [
                {"name": t.name, "version": t.version, "source": t.source}
                for t in self.technologies
            ],
            "security_headers": {
                "missing": self.security_headers.missing_headers,
                "weak": self.security_headers.weak_headers,
                "info_leaks": self.security_headers.info_leaks,
            },
            "interesting_paths": self.interesting_paths,
            "discovered_endpoints": self.discovered_endpoints,
            "cors_policy": self.cors_policy,
        }


class ReconEngine:
    """Performs reconnaissance against a target through Burp."""

    def __init__(self, burp_client: BurpMcpClient) -> None:
        self._burp = burp_client

    async def run(self, base_url: str) -> ReconResult:
        """Run full recon suite against *base_url*."""
        result = ReconResult()

        # 1. Probe the base URL for fingerprinting & header audit
        from .models import HttpRequest
        probe_req = HttpRequest(method="GET", url=base_url)
        try:
            probe_resp = await self._burp.send_request(probe_req)
            result.technologies = fingerprint_technologies(
                probe_resp.headers, probe_resp.body
            )
            result.security_headers = audit_security_headers(probe_resp.headers)
        except Exception as exc:
            logger.warning("Base URL probe failed: %s", exc)

        # 2. Test CORS policy
        try:
            result.cors_policy = await self._test_cors(base_url)
        except Exception as exc:
            logger.warning("CORS test failed: %s", exc)

        # 3. Probe interesting paths
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        for path in INTERESTING_PATHS:
            url = origin + path
            try:
                req = HttpRequest(method="GET", url=url)
                resp = await self._burp.send_request(req)
                if resp.status_code < 400 and resp.status_code != 0:
                    result.interesting_paths.append({
                        "path": path,
                        "status": resp.status_code,
                        "size": len(resp.body) if resp.body else 0,
                    })
                    result.discovered_endpoints.append(url)
            except Exception:
                pass  # non-critical

        logger.info(
            "Recon complete: %d techs, %d interesting paths, %d header issues",
            len(result.technologies),
            len(result.interesting_paths),
            len(result.security_headers.missing_headers)
            + len(result.security_headers.weak_headers),
        )
        return result

    async def _test_cors(self, base_url: str) -> dict[str, str]:
        """Test CORS by sending requests with various Origin headers."""
        from .models import HttpRequest

        policy: dict[str, str] = {}
        test_origins = [
            "https://evil.com",
            "null",
        ]
        for origin in test_origins:
            req = HttpRequest(
                method="GET",
                url=base_url,
                headers={"Origin": origin},
            )
            try:
                resp = await self._burp.send_request(req)
                acao = resp.headers.get(
                    "Access-Control-Allow-Origin",
                    resp.headers.get("access-control-allow-origin", ""),
                )
                acac = resp.headers.get(
                    "Access-Control-Allow-Credentials",
                    resp.headers.get("access-control-allow-credentials", ""),
                )
                if acao:
                    policy[f"origin={origin}"] = f"ACAO={acao}, ACAC={acac}"
            except Exception:
                pass
        return policy


# ---------------------------------------------------------------------------
# Static analysis helpers (no network calls)
# ---------------------------------------------------------------------------

_TECH_PATTERNS: list[tuple[str, str, str]] = [
    # (header_or_body_pattern, tech_name, source_hint)
    (r"(?i)x-powered-by:\s*(.+)", "X-Powered-By", "header"),
    (r"(?i)server:\s*(apache[\w/. ]*)", "Apache", "header"),
    (r"(?i)server:\s*(nginx[\w/. ]*)", "Nginx", "header"),
    (r"(?i)server:\s*(Microsoft-IIS[\w/. ]*)", "IIS", "header"),
    (r"(?i)x-aspnet-version:\s*(.+)", "ASP.NET", "header"),
    (r"(?i)x-drupal-cache", "Drupal", "header"),
    (r"(?i)x-generator:\s*(.+)", "Generator", "header"),
    (r"(?i)wp-content/", "WordPress", "body"),
    (r"(?i)laravel_session", "Laravel", "cookie"),
    (r"(?i)django", "Django", "body"),
    (r"(?i)react", "React", "body"),
    (r"(?i)next\.js", "Next.js", "body"),
    (r"(?i)vue\.js", "Vue.js", "body"),
    (r"(?i)express", "Express", "body"),
    (r"(?i)spring", "Spring", "body"),
    (r"(?i)graphql", "GraphQL", "body"),
]

_REQUIRED_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
    "Referrer-Policy",
    "Permissions-Policy",
]

_INFO_LEAK_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
]


def fingerprint_technologies(
    headers: dict[str, str],
    body: str,
) -> list[TechFingerprint]:
    """Detect technologies from response headers and body content."""
    techs: list[TechFingerprint] = []
    combined = "\n".join(f"{k}: {v}" for k, v in headers.items()) + "\n" + body
    seen: set[str] = set()

    for pattern, name, source in _TECH_PATTERNS:
        m = re.search(pattern, combined)
        if m and name not in seen:
            version = m.group(1).strip() if m.lastindex else ""
            techs.append(TechFingerprint(name=name, version=version, source=source))
            seen.add(name)

    return techs


def audit_security_headers(headers: dict[str, str]) -> SecurityHeaderAudit:
    """Audit response headers for security best practices."""
    audit = SecurityHeaderAudit()
    header_lower = {k.lower(): v for k, v in headers.items()}

    for hdr in _REQUIRED_SECURITY_HEADERS:
        if hdr.lower() not in header_lower:
            audit.missing_headers.append(hdr)

    # Check for weak values
    csp = header_lower.get("content-security-policy", "")
    if csp and "unsafe-inline" in csp:
        audit.weak_headers.append("CSP allows unsafe-inline")
    if csp and "unsafe-eval" in csp:
        audit.weak_headers.append("CSP allows unsafe-eval")

    xfo = header_lower.get("x-frame-options", "")
    if xfo and xfo.upper() not in ("DENY", "SAMEORIGIN"):
        audit.weak_headers.append(f"Weak X-Frame-Options: {xfo}")

    # Check for info leaks
    for hdr in _INFO_LEAK_HEADERS:
        if hdr.lower() in header_lower:
            audit.info_leaks.append(f"{hdr}: {header_lower[hdr.lower()]}")

    return audit
