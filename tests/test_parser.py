"""Unit tests for SAGA Phase 2 parser components.

Tests OpenAPI spec parser, AST route discovery, decorator forms, and route correlation.
"""

from pathlib import Path

from fastapi.testclient import TestClient

from saga.core.models import Endpoint
from saga.parser.ast_parser import (
    parse_ast_routes_from_directory,
    parse_ast_routes_from_file,
)
from saga.parser.correlator import correlate_endpoints, normalize_path
from saga.parser.openapi import parse_openapi_spec
from testbed.app import app

client = TestClient(app)
TESTBED_DIR = Path(__file__).parent.parent / "testbed"


def test_openapi_parser_against_testbed():
    """Test OpenAPI spec parser using live OpenAPI JSON from FastAPI testbed."""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    spec_dict = response.json()

    endpoints = parse_openapi_spec(spec_dict)
    assert len(endpoints) >= 4

    paths = {ep.path: ep for ep in endpoints}
    assert "/api/v1/documents/{doc_id}" in paths
    assert "/api/v1/secure/documents/{doc_id}" in paths
    assert "/api/v1/secure/tenant/documents/{doc_id}" in paths
    assert "/api/v1/admin/users/{user_id}" in paths

    # Verify endpoint properties
    bola_ep = paths["/api/v1/documents/{doc_id}"]
    assert bola_ep.http_method == "GET"
    assert any(p.name == "doc_id" for p in bola_ep.path_parameters)


def test_ast_route_discovery_file():
    """Test AST route discovery on vulnerable.py router file."""
    vulnerable_file = TESTBED_DIR / "routers" / "vulnerable.py"
    assert vulnerable_file.is_file()

    endpoints = parse_ast_routes_from_file(vulnerable_file)
    assert len(endpoints) == 2

    handler_names = {ep.handler_name: ep for ep in endpoints}
    assert "get_document_vulnerable_bola" in handler_names
    assert "delete_user_vulnerable_bfla" in handler_names

    bola_ast = handler_names["get_document_vulnerable_bola"]
    assert bola_ast.http_method == "GET"
    assert bola_ast.source_file == vulnerable_file
    assert isinstance(bola_ast.source_line, int)
    assert bola_ast.source_line > 0
    assert bola_ast.security_metadata.requires_auth is True

    bfla_ast = handler_names["delete_user_vulnerable_bfla"]
    assert bfla_ast.http_method == "DELETE"
    assert bfla_ast.security_metadata.requires_auth is True


def test_ast_route_discovery_secure():
    """Test AST route discovery on secure.py router file for security checks detection."""
    secure_file = TESTBED_DIR / "routers" / "secure.py"
    endpoints = parse_ast_routes_from_file(secure_file)

    handler_names = {ep.handler_name: ep for ep in endpoints}
    assert "get_document_secure_ownership" in handler_names
    assert "get_document_secure_tenant" in handler_names

    ownership_ep = handler_names["get_document_secure_ownership"]
    assert any(p.predicate_type.value == "ownership" for p in ownership_ep.predicates)

    tenant_ep = handler_names["get_document_secure_tenant"]
    assert any(p.predicate_type.value == "tenant" for p in tenant_ep.predicates)


def test_ast_route_discovery_directory():
    """Test AST route discovery across all python files in testbed directory."""
    endpoints = parse_ast_routes_from_directory(TESTBED_DIR)
    assert len(endpoints) >= 4

    methods = {ep.http_method for ep in endpoints}
    assert "GET" in methods
    assert "DELETE" in methods


def test_correlate_endpoints():
    """Test route-to-handler correlation combining OpenAPI spec and AST results."""
    response = client.get("/openapi.json")
    openapi_endpoints = parse_openapi_spec(response.json())
    ast_endpoints = parse_ast_routes_from_directory(TESTBED_DIR)

    correlated = correlate_endpoints(openapi_endpoints, ast_endpoints)
    assert len(correlated) >= 4

    for ep in correlated:
        assert isinstance(ep, Endpoint)
        assert ep.http_method in ("GET", "POST", "PUT", "PATCH", "DELETE")
        assert ep.path.startswith("/")
        assert ep.handler_name != ""

    # Check correlated metadata for BOLA endpoint
    bola_corr = next(ep for ep in correlated if "vulnerable_bola" in ep.handler_name)
    assert bola_corr.source_file is not None
    assert bola_corr.source_line is not None
    assert bola_corr.security_metadata.requires_auth is True
    assert not any(p.predicate_type.value == "ownership" for p in bola_corr.predicates)



def test_all_decorator_forms():
    """Test support for @app.get, @app.post, @app.put, @app.patch, @app.delete decorators."""
    code = """
from fastapi import FastAPI

app = FastAPI()

@app.get("/items")
def get_items():
    pass

@app.post("/items")
def create_item():
    pass

@app.put("/items/{id}")
def update_item(id: int):
    pass

@app.patch("/items/{id}")
def patch_item(id: int):
    pass

@app.delete("/items/{id}")
def delete_item(id: int):
    pass
"""
    import ast

    from saga.parser.ast_parser import FastAPIRouteVisitor

    tree = ast.parse(code)
    visitor = FastAPIRouteVisitor()
    visitor.visit(tree)

    methods = [ep.http_method for ep in visitor.endpoints]
    assert methods == ["GET", "POST", "PUT", "PATCH", "DELETE"]


def test_normalize_path():
    """Test route path normalization helper."""
    assert normalize_path("/api/v1/documents/{doc_id}") == "/api/v1/documents/{param}"
    assert normalize_path("/users/{user_id}") == "/users/{param}"
