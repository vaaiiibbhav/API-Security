"""Unit tests for Phase 3-5 static AST extraction.

Tests principal extraction, object reference extraction, and authorization predicate extraction.
"""

import ast
from pathlib import Path

from saga.static.ast_extractor import (
    SecurityASTVisitor,
    extract_ast_security_from_file,
)
from saga.static.models import (
    ASTAnalysisResult,
    ExtractedAuthPredicate,
    ExtractedPrincipal,
)

TESTBED_ROUTERS_DIR = Path(__file__).parent.parent / "testbed" / "routers"


def test_principal_extraction_explicit_pattern():
    """Test principal extraction on explicit pattern `current_user = Depends(...)`."""
    code = """
from fastapi import Depends
from saga.models import User

def get_current_user():
    pass

@app.get("/profile")
def get_profile(current_user: User = Depends(get_current_user)):
    return current_user
"""
    tree = ast.parse(code)
    visitor = SecurityASTVisitor()
    visitor.visit(tree)

    assert len(visitor.results) == 1
    res = visitor.results[0]
    assert res.handler_name == "get_profile"
    assert len(res.principals) == 1

    principal = res.principals[0]
    assert isinstance(principal, ExtractedPrincipal)
    assert principal.param_name == "current_user"
    assert principal.type_annotation == "User"
    assert principal.dependency_func == "get_current_user"
    assert principal.confidence == 1.0
    assert isinstance(principal.source_line, int)


def test_object_ref_extraction_explicit_patterns():
    """Test object reference extraction for db.query(Order), Order.get(...), and ORM filters."""
    code = """
@app.get("/orders/{order_id}")
def get_order(order_id: int):
    doc = db.query(Order)
    item = Order.get(order_id)
    filtered = db.query(Order).filter(Order.id == order_id)
"""
    tree = ast.parse(code)
    visitor = SecurityASTVisitor()
    visitor.visit(tree)

    assert len(visitor.results) == 1
    res = visitor.results[0]
    assert len(res.objects) >= 2

    entities = [obj.entity_name for obj in res.objects]
    assert "Order" in entities
    assert "ORM_Filter" in entities


def test_auth_predicate_extraction_explicit_patterns():
    """Test authorization predicate extraction for required explicit comparison patterns."""
    code = """
@app.get("/test1")
def test_ownership_1(current_user: User = Depends(get_current_user)):
    if Order.user_id == current_user.id:
        pass

@app.get("/test2")
def test_ownership_2(current_user: User = Depends(get_current_user)):
    if current_user.id == Order.user_id:
        pass

@app.get("/test3")
def test_ownership_3(current_user: User = Depends(get_current_user)):
    if Order.owner_id == current_user.id:
        pass

@app.get("/test4")
def test_tenant(current_user: User = Depends(get_current_user)):
    if Order.tenant_id == current_user.tenant_id:
        pass
"""
    tree = ast.parse(code)
    visitor = SecurityASTVisitor()
    visitor.visit(tree)

    assert len(visitor.results) == 4
    for res in visitor.results:
        assert len(res.auth_predicates) == 1
        pred = res.auth_predicates[0]
        assert isinstance(pred, ExtractedAuthPredicate)
        assert pred.confidence == 1.0
        assert pred.predicate_type in ("ownership", "tenant")


def test_extraction_against_vulnerable_testbed():
    """Test AST extraction against vulnerable testbed endpoint (vulnerable.py)."""
    vulnerable_file = TESTBED_ROUTERS_DIR / "vulnerable.py"
    results = extract_ast_security_from_file(vulnerable_file)

    handler_map: dict[str, ASTAnalysisResult] = {res.handler_name: res for res in results}
    assert "get_document_vulnerable_bola" in handler_map

    bola_res = handler_map["get_document_vulnerable_bola"]
    assert len(bola_res.principals) == 1
    assert bola_res.principals[0].param_name == "current_user"
    assert len(bola_res.objects) >= 1
    assert any(obj.entity_name == "Document" for obj in bola_res.objects)

    # PROVE VULNERABILITY IN AST: No authorization predicates extracted for BOLA endpoint
    assert len(bola_res.auth_predicates) == 0


def test_extraction_against_secure_testbed():
    """Test AST extraction against secure testbed endpoints (secure.py)."""
    secure_file = TESTBED_ROUTERS_DIR / "secure.py"
    results = extract_ast_security_from_file(secure_file)

    handler_map: dict[str, ASTAnalysisResult] = {res.handler_name: res for res in results}
    assert "get_document_secure_ownership" in handler_map
    assert "get_document_secure_tenant" in handler_map

    ownership_res = handler_map["get_document_secure_ownership"]
    assert len(ownership_res.auth_predicates) == 1
    assert ownership_res.auth_predicates[0].predicate_type == "ownership"
    assert ownership_res.auth_predicates[0].confidence == 1.0

    tenant_res = handler_map["get_document_secure_tenant"]
    assert len(tenant_res.auth_predicates) == 1
    assert tenant_res.auth_predicates[0].predicate_type == "tenant"
    assert tenant_res.auth_predicates[0].confidence == 1.0
