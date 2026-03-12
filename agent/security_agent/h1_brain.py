"""Integration with h1-brain MCP server.

If the user has h1-brain running (https://github.com/PatrikFehrenbach/h1-brain),
this module connects to it to pull:
  - Public disclosed vulnerability reports for the target program
  - Weakness patterns from community data
  - Attack briefings via the hack() tool

When h1-brain is not available the agent falls back gracefully to
its built-in vulnerability knowledge base.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 15.0


@dataclass
class H1BrainConfig:
    """Connection settings for a running h1-brain MCP server."""

    host: str = "localhost"
    port: int = 3001
    enabled: bool = False

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"


@dataclass
class DisclosedReport:
    """A public HackerOne disclosed report."""

    report_id: str = ""
    title: str = ""
    weakness_name: str = ""
    program_handle: str = ""
    asset_identifier: str = ""
    bounty_amount: float = 0.0
    vulnerability_info: str = ""


@dataclass
class AttackBriefing:
    """Structured attack briefing from h1-brain's hack() tool."""

    program_handle: str = ""
    scope_assets: list[dict[str, Any]] = field(default_factory=list)
    past_findings: list[dict[str, Any]] = field(default_factory=list)
    weakness_patterns: list[str] = field(default_factory=list)
    untouched_assets: list[str] = field(default_factory=list)
    suggested_vectors: list[str] = field(default_factory=list)
    disclosed_reports: list[DisclosedReport] = field(default_factory=list)
    raw_text: str = ""


class H1BrainClient:
    """Client that talks to a running h1-brain MCP server."""

    def __init__(self, config: H1BrainConfig) -> None:
        self._config = config
        self._http: httpx.AsyncClient | None = None

    async def connect(self) -> bool:
        """Try to connect; return True if h1-brain is reachable."""
        if not self._config.enabled:
            return False
        try:
            self._http = httpx.AsyncClient(
                base_url=self._config.base_url,
                timeout=httpx.Timeout(_DEFAULT_TIMEOUT),
            )
            # Quick health check — list tools
            resp = await self._http.post("/mcp", json={
                "jsonrpc": "2.0", "id": 1,
                "method": "tools/list", "params": {},
            })
            resp.raise_for_status()
            logger.info("Connected to h1-brain at %s", self._config.base_url)
            return True
        except Exception as exc:
            logger.info("h1-brain not available (%s) — using built-in knowledge", exc)
            self._http = None
            return False

    async def close(self) -> None:
        if self._http:
            await self._http.aclose()
            self._http = None

    @property
    def is_connected(self) -> bool:
        return self._http is not None

    async def _call_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        if not self._http:
            return None
        try:
            resp = await self._http.post("/mcp", json={
                "jsonrpc": "2.0", "id": 1,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": arguments},
            })
            resp.raise_for_status()
            body = resp.json()
            return body.get("result")
        except Exception as exc:
            logger.warning("h1-brain tool %s failed: %s", tool_name, exc)
            return None

    async def get_attack_briefing(self, program_handle: str) -> AttackBriefing | None:
        """Call h1-brain's hack(handle) tool for a full attack briefing."""
        result = await self._call_tool("hack", {"handle": program_handle})
        if result is None:
            return None
        text = _extract_text(result)
        return AttackBriefing(
            program_handle=program_handle,
            raw_text=text,
        )

    async def search_disclosed_reports(
        self,
        query: str = "",
        program: str = "",
        weakness: str = "",
        limit: int = 20,
    ) -> list[DisclosedReport]:
        """Search public disclosed reports via h1-brain."""
        args: dict[str, Any] = {"limit": limit}
        if query:
            args["query"] = query
        if program:
            args["program"] = program
        if weakness:
            args["weakness"] = weakness
        result = await self._call_tool("search_disclosed_reports", args)
        if result is None:
            return []
        text = _extract_text(result)
        return _parse_disclosed_reports(text)

    async def search_personal_reports(
        self,
        query: str = "",
        program: str = "",
        weakness: str = "",
        limit: int = 20,
    ) -> list[DisclosedReport]:
        """Search the user's own rewarded reports (if synced)."""
        args: dict[str, Any] = {"limit": limit}
        if query:
            args["query"] = query
        if program:
            args["program"] = program
        if weakness:
            args["weakness"] = weakness
        result = await self._call_tool("search_reports", args)
        if result is None:
            return []
        text = _extract_text(result)
        return _parse_disclosed_reports(text)


def _extract_text(result: Any) -> str:
    """Pull text out of an MCP tool result."""
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        for item in result.get("content", []):
            if isinstance(item, dict) and item.get("type") == "text":
                return item.get("text", "")
    return str(result)


def _parse_disclosed_reports(text: str) -> list[DisclosedReport]:
    """Best-effort parse of h1-brain's markdown-ish report output."""
    reports: list[DisclosedReport] = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("- **#"):
            # Format: - **#12345** [severity] Title — program — weakness — $amount
            parts = line.split("**")
            if len(parts) >= 3:
                report_id = parts[1].lstrip("#").strip()
                remainder = parts[2] if len(parts) > 2 else ""
                reports.append(DisclosedReport(
                    report_id=report_id,
                    title=remainder.strip(" —-"),
                ))
    return reports
