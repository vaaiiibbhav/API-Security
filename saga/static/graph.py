"""Backward compatibility alias for saga.graph."""

from saga.graph.builder import (
    AuthorizationGraph,
    EdgeType,
    NodeType,
    build_authorization_graph,
)

__all__ = [
    "AuthorizationGraph",
    "EdgeType",
    "NodeType",
    "build_authorization_graph",
]
