"""Tests for the recon engine (static helpers only — no network)."""

from security_agent.recon_engine import (
    SecurityHeaderAudit,
    TechFingerprint,
    audit_security_headers,
    fingerprint_technologies,
)


def test_fingerprint_apache():
    headers = {"Server": "Apache/2.4.51 (Ubuntu)"}
    techs = fingerprint_technologies(headers, "")
    names = [t.name for t in techs]
    assert "Apache" in names


def test_fingerprint_nginx():
    headers = {"Server": "nginx/1.21.0"}
    techs = fingerprint_technologies(headers, "")
    names = [t.name for t in techs]
    assert "Nginx" in names


def test_fingerprint_powered_by():
    headers = {"X-Powered-By": "Express"}
    techs = fingerprint_technologies(headers, "")
    names = [t.name for t in techs]
    assert "X-Powered-By" in names


def test_fingerprint_wordpress_body():
    techs = fingerprint_technologies({}, '<link rel="stylesheet" href="/wp-content/themes/style.css">')
    names = [t.name for t in techs]
    assert "WordPress" in names


def test_fingerprint_react_body():
    techs = fingerprint_technologies({}, '<div id="root"></div><script src="react.production.min.js"></script>')
    names = [t.name for t in techs]
    assert "React" in names


def test_fingerprint_no_match():
    techs = fingerprint_technologies({}, "plain html body")
    assert len(techs) == 0


def test_audit_missing_headers():
    headers = {"Content-Type": "text/html"}
    audit = audit_security_headers(headers)
    assert "Strict-Transport-Security" in audit.missing_headers
    assert "X-Content-Type-Options" in audit.missing_headers
    assert "Content-Security-Policy" in audit.missing_headers


def test_audit_all_present():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'self'",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    audit = audit_security_headers(headers)
    assert len(audit.missing_headers) == 0


def test_audit_weak_csp():
    headers = {
        "Content-Security-Policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval'",
        "Strict-Transport-Security": "max-age=0",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    audit = audit_security_headers(headers)
    assert any("unsafe-inline" in w for w in audit.weak_headers)
    assert any("unsafe-eval" in w for w in audit.weak_headers)


def test_audit_info_leak_headers():
    headers = {
        "Server": "Apache/2.4.51",
        "X-Powered-By": "PHP/7.4",
    }
    audit = audit_security_headers(headers)
    assert len(audit.info_leaks) >= 2
    assert any("Server" in leak for leak in audit.info_leaks)
    assert any("X-Powered-By" in leak for leak in audit.info_leaks)


def test_tech_fingerprint_dataclass():
    tf = TechFingerprint(name="Test", version="1.0", source="header")
    assert tf.name == "Test"
    assert tf.version == "1.0"
