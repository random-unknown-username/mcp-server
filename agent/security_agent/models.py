"""Data models for the security research agent."""

from __future__ import annotations

import enum
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(str, enum.Enum):
    IDOR = "idor"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    HORIZONTAL_ACCESS = "horizontal_access"
    VERTICAL_ACCESS = "vertical_access"
    BUSINESS_LOGIC = "business_logic"
    AUTH_BYPASS = "auth_bypass"
    SESSION_HANDLING = "session_handling"
    RACE_CONDITION = "race_condition"
    STATE_VIOLATION = "state_violation"
    WORKFLOW_BYPASS = "workflow_bypass"
    PARAMETER_POLLUTION = "parameter_pollution"
    XSS = "xss"
    SQLI = "sqli"
    SSRF = "ssrf"
    SSTI = "ssti"
    OPEN_REDIRECT = "open_redirect"
    CORS_MISCONFIGURATION = "cors_misconfiguration"
    PATH_TRAVERSAL = "path_traversal"
    HEADER_INJECTION = "header_injection"
    INFORMATION_DISCLOSURE = "information_disclosure"
    GCP_IAM_BYPASS = "gcp_iam_bypass"
    GCP_PRIVILEGE_ESCALATION = "gcp_privilege_escalation"


class TaskStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class HttpRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    cookies: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "body": self.body,
            "cookies": self.cookies,
        }


@dataclass
class HttpResponse:
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "status_code": self.status_code,
            "headers": self.headers,
            "body": self.body,
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass
class Endpoint:
    url: str
    method: str
    parameters: list[str] = field(default_factory=list)
    requires_auth: bool = False
    discovered_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "parameters": self.parameters,
            "requires_auth": self.requires_auth,
        }


@dataclass
class UserSession:
    user_id: str
    role: str
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    tokens: dict[str, str] = field(default_factory=dict)


@dataclass
class Finding:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    vulnerability_type: VulnerabilityType = VulnerabilityType.BROKEN_ACCESS_CONTROL
    severity: Severity = Severity.MEDIUM
    endpoint: str = ""
    description: str = ""
    original_request: HttpRequest | None = None
    modified_request: HttpRequest | None = None
    original_response: HttpResponse | None = None
    modified_response: HttpResponse | None = None
    reproduction_steps: list[str] = field(default_factory=list)
    verified: bool = False
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "vulnerability_type": self.vulnerability_type.value,
            "severity": self.severity.value,
            "endpoint": self.endpoint,
            "description": self.description,
            "original_request": (
                self.original_request.to_dict() if self.original_request else None
            ),
            "modified_request": (
                self.modified_request.to_dict() if self.modified_request else None
            ),
            "original_response": (
                self.original_response.to_dict() if self.original_response else None
            ),
            "modified_response": (
                self.modified_response.to_dict() if self.modified_response else None
            ),
            "reproduction_steps": self.reproduction_steps,
            "verified": self.verified,
            "timestamp": self.timestamp,
        }


@dataclass
class RequestGraphNode:
    endpoint: Endpoint
    incoming: list[str] = field(default_factory=list)
    outgoing: list[str] = field(default_factory=list)
    state_changes: list[str] = field(default_factory=list)


@dataclass
class TestTask:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    task_type: str = ""
    target_endpoint: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    status: TaskStatus = TaskStatus.PENDING
    created_at: float = field(default_factory=time.time)
    completed_at: float | None = None
    result: dict[str, Any] | None = None
