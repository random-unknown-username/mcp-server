"""Differential response analysis.

Compares original and modified HTTP responses to detect indicators of
authorization flaws, data leakage, and unexpected behavior changes.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from .models import HttpResponse, Severity

logger = logging.getLogger(__name__)


@dataclass
class DiffResult:
    """Result of comparing two responses."""

    is_anomalous: bool = False
    severity: Severity = Severity.INFO
    indicators: list[str] = field(default_factory=list)
    status_diff: bool = False
    size_diff_pct: float = 0.0
    json_field_diff: list[str] = field(default_factory=list)
    error_messages: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_anomalous": self.is_anomalous,
            "severity": self.severity.value,
            "indicators": self.indicators,
            "status_diff": self.status_diff,
            "size_diff_pct": self.size_diff_pct,
            "json_field_diff": self.json_field_diff,
            "error_messages": self.error_messages,
        }


def compare_responses(
    original: HttpResponse,
    modified: HttpResponse,
    *,
    mutation_description: str = "",
) -> DiffResult:
    """Compare *original* with *modified* and flag anomalies."""
    result = DiffResult()

    _check_status(original, modified, result, mutation_description)
    _check_size(original, modified, result)
    _check_json_fields(original, modified, result)
    _check_error_messages(modified, result)

    if result.indicators:
        result.is_anomalous = True
        result.severity = _compute_severity(result)

    return result


def _check_status(
    orig: HttpResponse,
    mod: HttpResponse,
    result: DiffResult,
    description: str,
) -> None:
    if orig.status_code != mod.status_code:
        result.status_diff = True
        if mod.status_code < 400 and orig.status_code >= 400:
            result.indicators.append(
                f"Unexpected success: {orig.status_code} → {mod.status_code} "
                f"after {description}"
            )
        elif mod.status_code >= 400 and orig.status_code < 400:
            result.indicators.append(
                f"Request blocked: {orig.status_code} → {mod.status_code}"
            )


def _check_size(
    orig: HttpResponse, mod: HttpResponse, result: DiffResult
) -> None:
    orig_len = len(orig.body) if orig.body else 0
    mod_len = len(mod.body) if mod.body else 0
    if orig_len == 0 and mod_len == 0:
        return
    max_len = max(orig_len, mod_len, 1)
    diff_pct = abs(orig_len - mod_len) / max_len * 100
    result.size_diff_pct = round(diff_pct, 2)
    if diff_pct > 30:
        result.indicators.append(
            f"Significant body size change: {diff_pct:.1f}%"
        )


def _check_json_fields(
    orig: HttpResponse, mod: HttpResponse, result: DiffResult
) -> None:
    orig_json = _try_parse_json(orig.body)
    mod_json = _try_parse_json(mod.body)
    if orig_json is None or mod_json is None:
        return
    if not isinstance(orig_json, dict) or not isinstance(mod_json, dict):
        return
    new_fields = set(mod_json.keys()) - set(orig_json.keys())
    missing_fields = set(orig_json.keys()) - set(mod_json.keys())
    if new_fields:
        result.json_field_diff.extend(f"+{f}" for f in sorted(new_fields))
        result.indicators.append(
            f"New JSON fields in response: {sorted(new_fields)}"
        )
    if missing_fields:
        result.json_field_diff.extend(f"-{f}" for f in sorted(missing_fields))

    sensitive_patterns = {"password", "secret", "token", "key", "ssn", "credit"}
    for fld in new_fields:
        if any(p in fld.lower() for p in sensitive_patterns):
            result.indicators.append(
                f"Potentially sensitive field exposed: {fld}"
            )


def _check_error_messages(mod: HttpResponse, result: DiffResult) -> None:
    body_lower = (mod.body or "").lower()
    error_patterns = [
        "stack trace",
        "traceback",
        "exception",
        "sql syntax",
        "internal server error",
    ]
    for pattern in error_patterns:
        if pattern in body_lower:
            result.error_messages.append(f"Error indicator: '{pattern}'")


def _compute_severity(result: DiffResult) -> Severity:
    text = " ".join(result.indicators).lower()
    if "unexpected success" in text or "sensitive field" in text:
        return Severity.HIGH
    if "significant body size" in text:
        return Severity.MEDIUM
    if "error indicator" in text:
        return Severity.LOW
    return Severity.INFO


def _try_parse_json(body: str | None) -> Any | None:
    if not body:
        return None
    try:
        return json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None
