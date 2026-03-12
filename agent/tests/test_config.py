"""Tests for configuration management."""

import json
import tempfile
from pathlib import Path

from security_agent.config import AgentConfig, BrowserConfig, BurpMcpConfig, TargetConfig


def test_default_config():
    config = AgentConfig()
    assert config.target.base_url == ""
    assert config.burp_mcp.port == 9876
    assert config.browser.headless is True
    assert config.max_concurrent_tests == 5


def test_burp_mcp_base_url():
    cfg = BurpMcpConfig(host="127.0.0.1", port=9999, use_ssl=False)
    assert cfg.base_url == "http://127.0.0.1:9999"


def test_burp_mcp_base_url_ssl():
    cfg = BurpMcpConfig(host="secure.local", port=443, use_ssl=True)
    assert cfg.base_url == "https://secure.local:443"


def test_browser_proxy_url():
    cfg = BrowserConfig(proxy_host="10.0.0.1", proxy_port=8888)
    assert cfg.proxy_url == "http://10.0.0.1:8888"


def test_from_dict():
    data = {
        "target": {"base_url": "https://target.example.com", "allowed_domains": ["target.example.com"]},
        "burp_mcp": {"host": "burp", "port": 1234},
        "browser": {"headless": False, "proxy_port": 9090},
        "max_concurrent_tests": 10,
    }
    config = AgentConfig.from_dict(data)
    assert config.target.base_url == "https://target.example.com"
    assert config.burp_mcp.port == 1234
    assert config.browser.headless is False
    assert config.max_concurrent_tests == 10


def test_from_file():
    data = {
        "target": {"base_url": "https://app.test"},
        "burp_mcp": {"port": 5555},
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        f.flush()
        config = AgentConfig.from_file(f.name)
    assert config.target.base_url == "https://app.test"
    assert config.burp_mcp.port == 5555


def test_from_file_missing():
    config = AgentConfig.from_file("/nonexistent/config.json")
    assert config.target.base_url == ""


def test_to_dict():
    config = AgentConfig(
        target=TargetConfig(base_url="https://test.com"),
        burp_mcp=BurpMcpConfig(port=7777),
    )
    d = config.to_dict()
    assert d["target"]["base_url"] == "https://test.com"
    assert d["burp_mcp"]["port"] == 7777


def test_is_url_allowed_by_base_url():
    config = AgentConfig(target=TargetConfig(base_url="https://example.com"))
    assert config.is_url_allowed("https://example.com/api/test")
    assert not config.is_url_allowed("https://other.com/api/test")


def test_is_url_allowed_by_domains():
    config = AgentConfig(
        target=TargetConfig(base_url="https://example.com", allowed_domains=["example.com", "api.example.com"])
    )
    assert config.is_url_allowed("https://api.example.com/v1/users")
    assert not config.is_url_allowed("https://evil.com/phish")
