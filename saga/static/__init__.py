"""Static analysis module for AST security extraction and Authorization Graph construction."""

from saga.static.ast_extractor import (
    SecurityASTVisitor,
    extract_ast_security_from_directory,
    extract_ast_security_from_file,
)
from saga.static.graph import (
    AuthorizationGraph,
    EdgeType,
    NodeType,
    build_authorization_graph,
)
from saga.static.models import (
    ASTAnalysisResult,
    ExtractedAuthPredicate,
    ExtractedObjectRef,
    ExtractedPrincipal,
)

__all__ = [
    "ASTAnalysisResult",
    "AuthorizationGraph",
    "EdgeType",
    "ExtractedAuthPredicate",
    "ExtractedObjectRef",
    "ExtractedPrincipal",
    "NodeType",
    "SecurityASTVisitor",
    "build_authorization_graph",
    "extract_ast_security_from_directory",
    "extract_ast_security_from_file",
]
