"""Tests for the vulnerability knowledge base."""

from security_agent.vuln_knowledge import (
    CWE_MAP,
    WeaknessPattern,
    check_response_for_weakness,
    get_all_weaknesses,
    get_payloads_for_context,
    get_weakness_by_cwe,
    suggest_attack_vectors,
)


def test_cwe_map_has_entries():
    assert len(CWE_MAP) > 0
    assert "CWE-79" in CWE_MAP
    assert "CWE-89" in CWE_MAP
    assert "CWE-918" in CWE_MAP


def test_get_weakness_by_cwe():
    xss = get_weakness_by_cwe("CWE-79")
    assert xss is not None
    assert xss.name == "Cross-Site Scripting (XSS)"
    assert len(xss.payloads) > 0


def test_get_weakness_by_cwe_missing():
    result = get_weakness_by_cwe("CWE-99999")
    assert result is None


def test_get_all_weaknesses():
    all_wp = get_all_weaknesses()
    assert len(all_wp) >= 9  # we registered at least 9


def test_get_payloads_for_context():
    payloads = get_payloads_for_context("query_param")
    assert len(payloads) > 0
    # Should include XSS and SQLi payloads
    cwe_ids = {wp.cwe_id for _, wp in payloads}
    assert "CWE-79" in cwe_ids
    assert "CWE-89" in cwe_ids


def test_get_payloads_for_unknown_context():
    payloads = get_payloads_for_context("nonexistent_context")
    assert len(payloads) == 0


def test_check_response_for_sqli():
    sqli = get_weakness_by_cwe("CWE-89")
    assert sqli is not None
    hits = check_response_for_weakness(
        "You have an error in your SQL syntax near...",
        {},
        sqli,
    )
    assert len(hits) > 0
    assert any("SQL" in h for h in hits)


def test_check_response_for_ssrf():
    ssrf = get_weakness_by_cwe("CWE-918")
    assert ssrf is not None
    hits = check_response_for_weakness(
        "root:x:0:0:root:/root:/bin/bash",
        {},
        ssrf,
    )
    assert len(hits) > 0


def test_check_response_no_match():
    xss = get_weakness_by_cwe("CWE-79")
    assert xss is not None
    hits = check_response_for_weakness(
        "Normal response body",
        {},
        xss,
    )
    assert len(hits) == 0


def test_suggest_attack_vectors_with_url_param():
    suggestions = suggest_attack_vectors(
        "https://example.com/api/fetch",
        ["url", "callback"],
        requires_auth=True,
    )
    cwe_ids = [s["cwe"] for s in suggestions]
    assert "CWE-918" in cwe_ids  # SSRF for url param
    assert "CWE-601" in cwe_ids  # Open redirect


def test_suggest_attack_vectors_with_file_param():
    suggestions = suggest_attack_vectors(
        "https://example.com/download",
        ["file", "name"],
        requires_auth=False,
    )
    cwe_ids = [s["cwe"] for s in suggestions]
    assert "CWE-22" in cwe_ids  # Path traversal


def test_suggest_attack_vectors_with_id_param():
    suggestions = suggest_attack_vectors(
        "https://example.com/api/users",
        ["user_id"],
        requires_auth=True,
    )
    cwe_ids = [s["cwe"] for s in suggestions]
    assert "CWE-639" in cwe_ids  # IDOR


def test_suggest_attack_vectors_always_includes_cors():
    suggestions = suggest_attack_vectors(
        "https://example.com/health",
        [],
        requires_auth=False,
    )
    cwe_ids = [s["cwe"] for s in suggestions]
    assert "CWE-942" in cwe_ids


def test_weakness_pattern_fields():
    wp = WeaknessPattern(
        cwe_id="CWE-TEST",
        name="Test Weakness",
        category="test",
        description="Test description",
        payloads=["payload1"],
        detection_patterns=[r"test"],
    )
    assert wp.cwe_id == "CWE-TEST"
    assert wp.severity_default == "medium"
    assert len(wp.payloads) == 1
