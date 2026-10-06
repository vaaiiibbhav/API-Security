"""Correlator module merging OpenAPI spec endpoints with Python AST discovered routes."""

import re

from saga.ir.models import EndpointIR, SecurityMetadata


def normalize_path(path: str) -> str:
    """Normalize route path for comparison (e.g., converting parameter syntax)."""
    # Replace variable parameter syntax like {id} or {doc_id} with generic placeholder {param}
    normalized = re.sub(r"\{[a-zA-Z0-9_]+\}", "{param}", path.rstrip("/"))
    return normalized if normalized.startswith("/") else "/" + normalized


def correlate_endpoints(
    openapi_endpoints: list[EndpointIR], ast_endpoints: list[EndpointIR]
) -> list[EndpointIR]:
    """Correlate OpenAPI endpoints with AST-discovered route handlers.

    Combines runtime/spec metadata (OpenAPI parameters/schemas) with static
    source code metadata (source file, line number, security check heuristics,
    extracted principals, objects, predicates, evidence).

    Args:
        openapi_endpoints: Endpoints parsed from OpenAPI specification.
        ast_endpoints: Endpoints discovered via AST source code parsing.

    Returns:
        List of correlated EndpointIR instances containing merged metadata.
    """
    correlated: list[EndpointIR] = []

    # Map AST endpoints by (http_method, normalized_path) and by handler_name
    ast_map: dict[tuple[str, str], EndpointIR] = {}
    ast_handler_map: dict[str, EndpointIR] = {}

    for ast_ep in ast_endpoints:
        key = (ast_ep.http_method.upper(), normalize_path(ast_ep.path))
        ast_map[key] = ast_ep
        ast_handler_map[ast_ep.handler_name] = ast_ep

    for o_ep in openapi_endpoints:
        key = (o_ep.http_method.upper(), normalize_path(o_ep.path))
        matched_ast = ast_map.get(key) or ast_handler_map.get(o_ep.handler_name)

        if matched_ast:
            # Merge security metadata
            merged_sec = SecurityMetadata(
                requires_auth=o_ep.security_metadata.requires_auth
                or matched_ast.security_metadata.requires_auth,
                security_schemes=list(
                    set(
                        o_ep.security_metadata.security_schemes
                        + matched_ast.security_metadata.security_schemes
                    )
                ),
                auth_dependencies=list(
                    set(
                        o_ep.security_metadata.auth_dependencies
                        + matched_ast.security_metadata.auth_dependencies
                    )
                ),
                required_roles=list(
                    set(
                        o_ep.security_metadata.required_roles
                        + matched_ast.security_metadata.required_roles
                    )
                ),
            )

            merged_ep = EndpointIR(
                http_method=o_ep.http_method,
                path=o_ep.path,
                handler_name=matched_ast.handler_name or o_ep.handler_name,
                source_file=matched_ast.source_file or o_ep.source_file,
                source_line=matched_ast.source_line or o_ep.source_line,
                path_parameters=o_ep.path_parameters or matched_ast.path_parameters,
                query_parameters=o_ep.query_parameters or matched_ast.query_parameters,
                request_body=o_ep.request_body or matched_ast.request_body,
                security_metadata=merged_sec,
                principals=matched_ast.principals or o_ep.principals,
                objects=matched_ast.objects or o_ep.objects,
                predicates=matched_ast.predicates or o_ep.predicates,
                evidence=matched_ast.evidence or o_ep.evidence,
            )
            correlated.append(merged_ep)
        else:
            correlated.append(o_ep)

    # Add any AST endpoints that were not in OpenAPI spec
    openapi_keys = {
        (o_ep.http_method.upper(), normalize_path(o_ep.path)) for o_ep in openapi_endpoints
    }
    openapi_handlers = {o_ep.handler_name for o_ep in openapi_endpoints}

    for ast_ep in ast_endpoints:
        key = (ast_ep.http_method.upper(), normalize_path(ast_ep.path))
        if key not in openapi_keys and ast_ep.handler_name not in openapi_handlers:
            correlated.append(ast_ep)

    return correlated

