"""Tests for the report generator."""

import json
import tempfile
from pathlib import Path

from security_agent.models import Finding, HttpRequest, HttpResponse, Severity, VulnerabilityType
from security_agent.report_generator import ReportGenerator, _build_report_data, _render_markdown


def _make_finding(**kwargs):
    defaults = {
        "vulnerability_type": VulnerabilityType.IDOR,
        "severity": Severity.HIGH,
        "endpoint": "https://example.com/api/users/1",
        "description": "Test IDOR vulnerability",
        "verified": True,
        "reproduction_steps": ["Step 1", "Step 2"],
        "original_request": HttpRequest(method="GET", url="https://example.com/api/users/1"),
        "modified_request": HttpRequest(method="GET", url="https://example.com/api/users/2"),
        "original_response": HttpResponse(status_code=200, body='{"user": "A"}'),
        "modified_response": HttpResponse(status_code=200, body='{"user": "B"}'),
    }
    defaults.update(kwargs)
    return Finding(**defaults)


def test_build_report_data():
    findings = [_make_finding(), _make_finding(severity=Severity.MEDIUM, verified=False)]
    data = _build_report_data(findings)
    assert data["total_findings"] == 2
    assert data["verified_findings"] == 1
    assert data["severity_summary"]["high"] == 1
    assert data["severity_summary"]["medium"] == 1


def test_render_markdown():
    findings = [_make_finding()]
    data = _build_report_data(findings)
    md = _render_markdown(data)
    assert "# Security Research Agent" in md
    assert "IDOR" in md.lower() or "idor" in md
    assert "example.com" in md
    assert "Step 1" in md


def test_generate_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        gen = ReportGenerator(output_dir=tmpdir)
        findings = [_make_finding()]
        json_path, md_path = gen.generate(findings)
        assert json_path.exists()
        assert md_path.exists()
        report = json.loads(json_path.read_text())
        assert report["total_findings"] == 1
        md_content = md_path.read_text()
        assert "Security Research Agent" in md_content


def test_generate_empty():
    with tempfile.TemporaryDirectory() as tmpdir:
        gen = ReportGenerator(output_dir=tmpdir)
        json_path, md_path = gen.generate([])
        report = json.loads(json_path.read_text())
        assert report["total_findings"] == 0
