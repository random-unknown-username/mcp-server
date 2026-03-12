"""Configuration management for the security agent."""

from __future__ import annotations

import json
import logging
import os
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
    program_handle: str = ""


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
class H1BrainConfig:
    """Connection settings for h1-brain MCP server."""
    host: str = "localhost"
    port: int = 3001
    enabled: bool = False

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"


@dataclass
class AgentConfig:
    target: TargetConfig = field(default_factory=TargetConfig)
    burp_mcp: BurpMcpConfig = field(default_factory=BurpMcpConfig)
    browser: BrowserConfig = field(default_factory=BrowserConfig)
    h1_brain: H1BrainConfig = field(default_factory=H1BrainConfig)
    max_concurrent_tests: int = 5
    state_dir: str = _DEFAULT_STATE_DIR
    report_dir: str = _DEFAULT_REPORT_DIR
    user_sessions: list[dict[str, str]] = field(default_factory=list)
    enable_injection_tests: bool = True
    enable_recon: bool = True

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
        h1_brain = H1BrainConfig(**data.get("h1_brain", {}))
        return cls(
            target=target,
            burp_mcp=burp_mcp,
            browser=browser,
            h1_brain=h1_brain,
            max_concurrent_tests=data.get("max_concurrent_tests", 5),
            state_dir=data.get("state_dir", _DEFAULT_STATE_DIR),
            report_dir=data.get("report_dir", _DEFAULT_REPORT_DIR),
            user_sessions=data.get("user_sessions", []),
            enable_injection_tests=data.get("enable_injection_tests", True),
            enable_recon=data.get("enable_recon", True),
        )

    def apply_env_overrides(self) -> None:
        """Override config values from environment variables.

        Supported variables:
          TARGET_URL          – target base URL
          BURP_MCP_URL        – full Burp MCP URL (e.g. http://localhost:9876)
          BURP_MCP_HOST       – Burp MCP host
          BURP_MCP_PORT       – Burp MCP port
          BROWSER_PROXY_PORT  – Burp proxy port for Playwright
          H1_BRAIN_URL        – h1-brain URL (enables h1-brain integration)
          PROGRAM_HANDLE      – HackerOne program handle
          HEADLESS            – "true"/"false" for headless browser mode
        """
        if val := os.environ.get("TARGET_URL"):
            self.target.base_url = val
            parsed = urlparse(val)
            if parsed.hostname and parsed.hostname not in self.target.allowed_domains:
                self.target.allowed_domains.append(parsed.hostname)

        if val := os.environ.get("BURP_MCP_URL"):
            parsed = urlparse(val)
            self.burp_mcp.host = parsed.hostname or "localhost"
            self.burp_mcp.port = parsed.port or 9876
            self.burp_mcp.use_ssl = parsed.scheme == "https"
        if val := os.environ.get("BURP_MCP_HOST"):
            self.burp_mcp.host = val
        if val := os.environ.get("BURP_MCP_PORT"):
            self.burp_mcp.port = int(val)

        if val := os.environ.get("BROWSER_PROXY_PORT"):
            self.browser.proxy_port = int(val)

        if val := os.environ.get("H1_BRAIN_URL"):
            parsed = urlparse(val)
            self.h1_brain.host = parsed.hostname or "localhost"
            self.h1_brain.port = parsed.port or 3001
            self.h1_brain.enabled = True

        if val := os.environ.get("PROGRAM_HANDLE"):
            self.target.program_handle = val

        if val := os.environ.get("HEADLESS"):
            self.browser.headless = val.lower() in ("true", "1", "yes")

    def to_dict(self) -> dict:
        return {
            "target": {
                "base_url": self.target.base_url,
                "allowed_domains": self.target.allowed_domains,
                "excluded_paths": self.target.excluded_paths,
                "program_handle": self.target.program_handle,
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
            "h1_brain": {
                "host": self.h1_brain.host,
                "port": self.h1_brain.port,
                "enabled": self.h1_brain.enabled,
            },
            "max_concurrent_tests": self.max_concurrent_tests,
            "state_dir": self.state_dir,
            "report_dir": self.report_dir,
            "user_sessions": self.user_sessions,
            "enable_injection_tests": self.enable_injection_tests,
            "enable_recon": self.enable_recon,
        }

    def is_url_allowed(self, url: str) -> bool:
        if not self.target.allowed_domains:
            return url.startswith(self.target.base_url)
        hostname = urlparse(url).hostname or ""
        return any(
            hostname == domain or hostname.endswith("." + domain)
            for domain in self.target.allowed_domains
        )


def generate_default_config(target_url: str = "", program_handle: str = "") -> dict:
    """Generate a starter config dict suitable for writing to a JSON file."""
    config = AgentConfig(
        target=TargetConfig(
            base_url=target_url,
            program_handle=program_handle,
        ),
    )
    if target_url:
        parsed = urlparse(target_url)
        if parsed.hostname:
            config.target.allowed_domains = [parsed.hostname]
    return config.to_dict()
