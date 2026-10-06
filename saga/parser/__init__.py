"""Parser module for OpenAPI specs, AST route discovery, and correlation."""

from saga.parser.ast_parser import (
    FastAPIRouteVisitor,
    parse_ast_routes_from_directory,
    parse_ast_routes_from_file,
)
from saga.parser.correlator import correlate_endpoints, normalize_path
from saga.parser.openapi import parse_openapi_spec

__all__ = [
    "FastAPIRouteVisitor",
    "correlate_endpoints",
    "normalize_path",
    "parse_ast_routes_from_directory",
    "parse_ast_routes_from_file",
    "parse_openapi_spec",
]
