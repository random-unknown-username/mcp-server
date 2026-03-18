"""Tests for the request graph builder."""

from security_agent.models import Endpoint
from security_agent.request_graph_builder import RequestGraphBuilder


def test_add_endpoint():
    graph = RequestGraphBuilder()
    ep = Endpoint(url="https://example.com/api/users", method="GET")
    graph.add_endpoint(ep)
    assert len(graph.endpoints) == 1
    assert "GET:/api/users" in graph.endpoints


def test_add_duplicate_endpoint():
    graph = RequestGraphBuilder()
    ep1 = Endpoint(url="https://example.com/api/users", method="GET")
    ep2 = Endpoint(url="https://example.com/api/users", method="GET", parameters=["page"])
    graph.add_endpoint(ep1)
    graph.add_endpoint(ep2)
    assert len(graph.endpoints) == 1
    assert graph.endpoints["GET:/api/users"].parameters == ["page"]


def test_add_edge():
    graph = RequestGraphBuilder()
    ep1 = Endpoint(url="https://example.com/login", method="POST")
    ep2 = Endpoint(url="https://example.com/dashboard", method="GET")
    graph.add_endpoint(ep1)
    graph.add_endpoint(ep2)
    graph.add_edge("POST", "https://example.com/login", "GET", "https://example.com/dashboard", state_change="authenticated")
    node1 = graph.nodes["POST:/login"]
    node2 = graph.nodes["GET:/dashboard"]
    assert "GET:/dashboard" in node1.outgoing
    assert "POST:/login" in node2.incoming
    assert "authenticated" in node1.state_changes


def test_ingest_proxy_history():
    graph = RequestGraphBuilder()
    history = [
        {"method": "GET", "url": "https://example.com/api/users", "headers": {"Authorization": "Bearer tok"}},
        {"method": "POST", "url": "https://example.com/api/users", "headers": {}},
        {"method": "GET", "url": "https://example.com/api/items", "parameters": {"page": "1"}},
    ]
    graph.ingest_proxy_history(history)
    assert len(graph.endpoints) == 3


def test_get_auth_endpoints():
    graph = RequestGraphBuilder()
    history = [
        {"method": "GET", "url": "https://example.com/public", "headers": {}},
        {"method": "GET", "url": "https://example.com/private", "headers": {"Authorization": "Bearer tok"}},
    ]
    graph.ingest_proxy_history(history)
    auth_eps = graph.get_auth_endpoints()
    assert len(auth_eps) == 1
    assert auth_eps[0].url == "https://example.com/private"


def test_get_endpoints_with_params():
    graph = RequestGraphBuilder()
    history = [
        {"method": "GET", "url": "https://example.com/api/items", "parameters": {"page": "1", "limit": "10"}},
        {"method": "GET", "url": "https://example.com/health", "headers": {}},
    ]
    graph.ingest_proxy_history(history)
    param_eps = graph.get_endpoints_with_params()
    assert len(param_eps) == 1
    assert "page" in param_eps[0].parameters


def test_to_dict():
    graph = RequestGraphBuilder()
    ep = Endpoint(url="https://example.com/api/users", method="GET")
    graph.add_endpoint(ep)
    d = graph.to_dict()
    assert "GET:/api/users" in d
    assert d["GET:/api/users"]["endpoint"]["url"] == "https://example.com/api/users"


def test_ingest_empty_history():
    graph = RequestGraphBuilder()
    graph.ingest_proxy_history([])
    assert len(graph.endpoints) == 0


def test_ingest_history_missing_url():
    graph = RequestGraphBuilder()
    graph.ingest_proxy_history([{"method": "GET"}])
    assert len(graph.endpoints) == 0
