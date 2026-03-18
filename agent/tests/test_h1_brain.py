"""Tests for the h1-brain integration client."""

from security_agent.h1_brain import (
    AttackBriefing,
    DisclosedReport,
    H1BrainClient,
    H1BrainConfig,
    _extract_text,
    _parse_disclosed_reports,
)


def test_h1_brain_config_defaults():
    cfg = H1BrainConfig()
    assert cfg.host == "localhost"
    assert cfg.port == 3001
    assert cfg.enabled is False
    assert cfg.base_url == "http://localhost:3001"


def test_h1_brain_config_custom():
    cfg = H1BrainConfig(host="192.168.1.1", port=4000, enabled=True)
    assert cfg.base_url == "http://192.168.1.1:4000"


def test_client_not_connected_by_default():
    client = H1BrainClient(H1BrainConfig())
    assert not client.is_connected


def test_extract_text_from_string():
    assert _extract_text("hello") == "hello"


def test_extract_text_from_mcp_result():
    result = {
        "content": [
            {"type": "text", "text": "report data here"}
        ]
    }
    assert _extract_text(result) == "report data here"


def test_extract_text_from_other():
    assert _extract_text(42) == "42"


def test_parse_disclosed_reports_with_entries():
    text = """Found 2 reports:

- **#12345** [high] XSS in login form — acme_corp — CWE-79 — $500
- **#67890** [critical] SQL injection — acme_corp — CWE-89 — $2000

_Use get_disclosed_report(id) for details._"""
    reports = _parse_disclosed_reports(text)
    assert len(reports) == 2
    assert reports[0].report_id == "12345"
    assert reports[1].report_id == "67890"


def test_parse_disclosed_reports_empty():
    reports = _parse_disclosed_reports("No reports found.")
    assert len(reports) == 0


def test_attack_briefing_dataclass():
    briefing = AttackBriefing(
        program_handle="test_prog",
        raw_text="Attack briefing text",
    )
    assert briefing.program_handle == "test_prog"
    assert briefing.raw_text == "Attack briefing text"
    assert briefing.scope_assets == []
    assert briefing.disclosed_reports == []


def test_disclosed_report_dataclass():
    report = DisclosedReport(
        report_id="12345",
        title="Test XSS",
        weakness_name="CWE-79",
        program_handle="acme",
        bounty_amount=500.0,
    )
    assert report.report_id == "12345"
    assert report.bounty_amount == 500.0
