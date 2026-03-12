"""Client for interacting with the Burp Suite MCP server.

This module communicates with the Burp MCP server's SSE/HTTP endpoint
to read proxy history, replay/modify requests, and perform fuzzing operations.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from .config import BurpMcpConfig
from .models import HttpRequest, HttpResponse

logger = logging.getLogger(__name__)


class BurpMcpClient:
    """Client that communicates with the Burp Suite MCP server."""

    def __init__(self, config: BurpMcpConfig) -> None:
        self._config = config
        self._http: httpx.AsyncClient | None = None

    async def connect(self) -> None:
        self._http = httpx.AsyncClient(
            base_url=self._config.base_url,
            timeout=httpx.Timeout(30.0),
        )
        logger.info("Connected to Burp MCP at %s", self._config.base_url)

    async def close(self) -> None:
        if self._http:
            await self._http.aclose()
            self._http = None

    async def _call_tool(self, tool_name: str, arguments: dict[str, Any]) -> Any:
        """Invoke an MCP tool on the Burp server via JSON-RPC over HTTP."""
        if not self._http:
            raise RuntimeError("Client not connected. Call connect() first.")

        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
        resp = await self._http.post("/mcp", json=payload)
        resp.raise_for_status()
        body = resp.json()
        if "error" in body:
            raise RuntimeError(f"MCP error: {body['error']}")
        return body.get("result")

    async def get_proxy_history(
        self, *, max_items: int = 100
    ) -> list[dict[str, Any]]:
        result = await self._call_tool(
            "proxy_history", {"max_entries": max_items}
        )
        if isinstance(result, list):
            return result
        if isinstance(result, dict) and "content" in result:
            for item in result["content"]:
                if item.get("type") == "text":
                    return json.loads(item["text"])
        return []

    async def send_request(self, request: HttpRequest) -> HttpResponse:
        result = await self._call_tool(
            "send_request",
            {
                "method": request.method,
                "url": request.url,
                "headers": json.dumps(request.headers),
                "body": request.body or "",
            },
        )
        return _parse_response(result)

    async def replay_request(
        self,
        request: HttpRequest,
        *,
        modifications: dict[str, Any] | None = None,
    ) -> HttpResponse:
        args: dict[str, Any] = {
            "method": request.method,
            "url": request.url,
            "headers": json.dumps(request.headers),
            "body": request.body or "",
        }
        if modifications:
            args["modifications"] = json.dumps(modifications)
        result = await self._call_tool("send_request", args)
        return _parse_response(result)

    async def scan_endpoint(self, url: str) -> list[dict[str, Any]]:
        result = await self._call_tool("scan", {"url": url})
        if isinstance(result, list):
            return result
        return []


def _parse_response(result: Any) -> HttpResponse:
    if isinstance(result, dict):
        if "content" in result:
            for item in result["content"]:
                if item.get("type") == "text":
                    data = json.loads(item["text"])
                    return HttpResponse(
                        status_code=data.get("status_code", 0),
                        headers=data.get("headers", {}),
                        body=data.get("body", ""),
                        elapsed_ms=data.get("elapsed_ms", 0.0),
                    )
        return HttpResponse(
            status_code=result.get("status_code", 0),
            headers=result.get("headers", {}),
            body=result.get("body", ""),
            elapsed_ms=result.get("elapsed_ms", 0.0),
        )
    return HttpResponse(status_code=0, body=str(result))
