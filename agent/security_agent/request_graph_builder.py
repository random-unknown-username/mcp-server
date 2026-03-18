"""Builds and maintains a graph model of application behavior.

Tracks endpoints, parameters, tokens, user roles, workflow states,
and object identifiers.  Constructs a request graph:
  user actions → API calls → state changes
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from .models import Endpoint, RequestGraphNode

logger = logging.getLogger(__name__)


class RequestGraphBuilder:
    """Incrementally builds a request graph from observed traffic."""

    def __init__(self) -> None:
        self._nodes: dict[str, RequestGraphNode] = {}
        self._endpoints: dict[str, Endpoint] = {}

    @property
    def endpoints(self) -> dict[str, Endpoint]:
        return dict(self._endpoints)

    @property
    def nodes(self) -> dict[str, RequestGraphNode]:
        return dict(self._nodes)

    def _key(self, method: str, url: str) -> str:
        parsed = urlparse(url)
        return f"{method.upper()}:{parsed.path}"

    def add_endpoint(self, endpoint: Endpoint) -> None:
        key = self._key(endpoint.method, endpoint.url)
        self._endpoints[key] = endpoint
        if key not in self._nodes:
            self._nodes[key] = RequestGraphNode(endpoint=endpoint)

    def add_edge(
        self,
        source_method: str,
        source_url: str,
        target_method: str,
        target_url: str,
        *,
        state_change: str | None = None,
    ) -> None:
        src_key = self._key(source_method, source_url)
        tgt_key = self._key(target_method, target_url)
        if src_key in self._nodes and tgt_key in self._nodes:
            src_node = self._nodes[src_key]
            tgt_node = self._nodes[tgt_key]
            if tgt_key not in src_node.outgoing:
                src_node.outgoing.append(tgt_key)
            if src_key not in tgt_node.incoming:
                tgt_node.incoming.append(src_key)
            if state_change:
                src_node.state_changes.append(state_change)

    def ingest_proxy_history(self, history: list[dict[str, Any]]) -> None:
        for entry in history:
            method = entry.get("method", "GET").upper()
            url = entry.get("url", "")
            if not url:
                continue
            params = list(entry.get("parameters", {}).keys()) if isinstance(
                entry.get("parameters"), dict
            ) else []
            requires_auth = bool(entry.get("headers", {}).get("Authorization"))
            endpoint = Endpoint(
                url=url,
                method=method,
                parameters=params,
                requires_auth=requires_auth,
            )
            self.add_endpoint(endpoint)

    def get_auth_endpoints(self) -> list[Endpoint]:
        return [ep for ep in self._endpoints.values() if ep.requires_auth]

    def get_endpoints_with_params(self) -> list[Endpoint]:
        return [ep for ep in self._endpoints.values() if ep.parameters]

    def to_dict(self) -> dict[str, Any]:
        return {
            key: {
                "endpoint": node.endpoint.to_dict(),
                "incoming": node.incoming,
                "outgoing": node.outgoing,
                "state_changes": node.state_changes,
            }
            for key, node in self._nodes.items()
        }
