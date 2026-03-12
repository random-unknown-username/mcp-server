"""Configuration management for the security agent."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

_DEFAULT_STATE_DIR = "agent_state"
_DEFAULT_REPORT_DIR = "reports"


@dataclass
class TargetConfig:
    base_url: str = ""
    allowed_domains: list[str] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=list)


@dataclass
class BurpMcpConfig:
    host: str = "localhost"
    port: int = 9876
    use_ssl: bool = False

    @property
    def base_url(self) -> str:
        scheme = "https" if self.use_ssl else "http"
        return f"{scheme}://{self.host}:{self.port}"


@dataclass
class BrowserConfig:
    headless: bool = True
    proxy_host: str = "localhost"
    proxy_port: int = 8080
    viewport_width: int = 1280
    viewport_height: int = 720
    timeout_ms: int = 30000

    @property
    def proxy_url(self) -> str:
        return f"http://{self.proxy_host}:{self.proxy_port}"


@dataclass
class AgentConfig:
    target: TargetConfig = field(default_factory=TargetConfig)
    burp_mcp: BurpMcpConfig = field(default_factory=BurpMcpConfig)
    browser: BrowserConfig = field(default_factory=BrowserConfig)
    max_concurrent_tests: int = 5
    state_dir: str = _DEFAULT_STATE_DIR
    report_dir: str = _DEFAULT_REPORT_DIR
    user_sessions: list[dict[str, str]] = field(default_factory=list)

    @classmethod
    def from_file(cls, path: str | Path) -> AgentConfig:
        path = Path(path)
        if not path.exists():
            logger.warning("Config file %s not found, using defaults", path)
            return cls()
        data = json.loads(path.read_text())
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> AgentConfig:
        target = TargetConfig(**data.get("target", {}))
        burp_mcp = BurpMcpConfig(**data.get("burp_mcp", {}))
        browser = BrowserConfig(**data.get("browser", {}))
        return cls(
            target=target,
            burp_mcp=burp_mcp,
            browser=browser,
            max_concurrent_tests=data.get("max_concurrent_tests", 5),
            state_dir=data.get("state_dir", _DEFAULT_STATE_DIR),
            report_dir=data.get("report_dir", _DEFAULT_REPORT_DIR),
            user_sessions=data.get("user_sessions", []),
        )

    def to_dict(self) -> dict:
        return {
            "target": {
                "base_url": self.target.base_url,
                "allowed_domains": self.target.allowed_domains,
                "excluded_paths": self.target.excluded_paths,
            },
            "burp_mcp": {
                "host": self.burp_mcp.host,
                "port": self.burp_mcp.port,
                "use_ssl": self.burp_mcp.use_ssl,
            },
            "browser": {
                "headless": self.browser.headless,
                "proxy_host": self.browser.proxy_host,
                "proxy_port": self.browser.proxy_port,
                "viewport_width": self.browser.viewport_width,
                "viewport_height": self.browser.viewport_height,
                "timeout_ms": self.browser.timeout_ms,
            },
            "max_concurrent_tests": self.max_concurrent_tests,
            "state_dir": self.state_dir,
            "report_dir": self.report_dir,
            "user_sessions": self.user_sessions,
        }

    def is_url_allowed(self, url: str) -> bool:
        if not self.target.allowed_domains:
            return url.startswith(self.target.base_url)
        hostname = urlparse(url).hostname or ""
        return any(
            hostname == domain or hostname.endswith("." + domain)
            for domain in self.target.allowed_domains
        )
