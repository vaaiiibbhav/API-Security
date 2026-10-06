"""Unit tests for Phase 6 SAGA Authorization Graph."""

from pathlib import Path

from fastapi.testclient import TestClient

from saga.parser.ast_parser import parse_ast_routes_from_directory
from saga.parser.correlator import correlate_endpoints
from saga.parser.openapi import parse_openapi_spec
from saga.static.graph import (
    AuthorizationGraph,
    EdgeType,
    NodeType,
    build_authorization_graph,
)
from testbed.app import app

client = TestClient(app)
TESTBED_DIR = Path(__file__).parent.parent / "testbed"


def test_typed_nodes_and_edges():
    """Test manual creation and querying of typed nodes and edges."""
    ag = AuthorizationGraph()

    ag.add_node("ENDPOINT:GET:/test", NodeType.ENDPOINT)
    ag.add_node("PRINCIPAL:user1", NodeType.PRINCIPAL)
    ag.add_node("OBJECT:Order", NodeType.OBJECT)
    ag.add_node("ACTION:GET", NodeType.ACTION)

    ag.add_edge("ENDPOINT:GET:/test", "PRINCIPAL:user1", EdgeType.AUTHENTICATES)
    ag.add_edge("ENDPOINT:GET:/test", "OBJECT:Order", EdgeType.REFERENCES)
    ag.add_edge("PRINCIPAL:user1", "OBJECT:Order", EdgeType.OWNS)

    nodes = ag.get_nodes(NodeType.PRINCIPAL)
    assert len(nodes) == 1
    assert nodes[0]["id"] == "PRINCIPAL:user1"

    edges = ag.get_edges(EdgeType.OWNS)
    assert len(edges) == 1
    assert edges[0]["source"] == "PRINCIPAL:user1"
    assert edges[0]["target"] == "OBJECT:Order"


def test_graph_serialization_json():
    """Test graph serialization to JSON and reconstruction from JSON."""
    ag = AuthorizationGraph()
    ag.add_node("EP1", NodeType.ENDPOINT)
    ag.add_node("P1", NodeType.PRINCIPAL)
    ag.add_edge("EP1", "P1", EdgeType.AUTHENTICATES)

    json_str = ag.to_json()
    assert '"id": "EP1"' in json_str

    reconstructed = AuthorizationGraph.from_json(json_str)
    assert len(reconstructed.get_nodes()) == 2
    assert len(reconstructed.get_edges()) == 1


def test_graph_construction_from_testbed():
    """Test building AuthorizationGraph from testbed static extraction results."""
    openapi_spec = client.get("/openapi.json").json()
    openapi_endpoints = parse_openapi_spec(openapi_spec)
    ast_endpoints = parse_ast_routes_from_directory(TESTBED_DIR)
    correlated = correlate_endpoints(openapi_endpoints, ast_endpoints)

    ag = build_authorization_graph(correlated)

    # Inspect Secure Ownership Endpoint
    ownership_auth = ag.inspect_endpoint_auth(
        "/api/v1/secure/documents/{doc_id}", method="GET"
    )
    assert ownership_auth["found"] is True
    assert ownership_auth["has_ownership_rule"] is True
    assert ownership_auth["has_tenant_rule"] is False

    # Inspect Secure Tenant Endpoint
    tenant_auth = ag.inspect_endpoint_auth(
        "/api/v1/secure/tenant/documents/{doc_id}", method="GET"
    )
    assert tenant_auth["found"] is True
    assert tenant_auth["has_tenant_rule"] is True
    assert tenant_auth["has_ownership_rule"] is False

    # Inspect Vulnerable BOLA Endpoint -> Must NOT have ownership or tenant rule!
    bola_auth = ag.inspect_endpoint_auth("/api/v1/documents/{doc_id}", method="GET")
    assert bola_auth["found"] is True
    assert bola_auth["has_ownership_rule"] is False
    assert bola_auth["has_tenant_rule"] is False

    # Inspect UNKNOWN Endpoint -> Must have is_delegated_rule True!
    unknown_auth = ag.inspect_endpoint_auth(
        "/api/v1/secure/unknown/documents/{doc_id}", method="GET"
    )
    assert unknown_auth["found"] is True
    assert unknown_auth["is_delegated_rule"] is True


def test_deterministic_graph_construction():
    """Verify graph construction is deterministic across multiple invocations."""
    openapi_spec = client.get("/openapi.json").json()
    openapi_endpoints = parse_openapi_spec(openapi_spec)
    ast_endpoints = parse_ast_routes_from_directory(TESTBED_DIR)
    correlated = correlate_endpoints(openapi_endpoints, ast_endpoints)

    ag1 = build_authorization_graph(correlated)
    ag2 = build_authorization_graph(correlated)

    assert ag1.to_json() == ag2.to_json()

