"""Static verifier evaluating Authorization Graph against SAGA tri-state security rules."""

import re

from saga.graph.builder import AuthorizationGraph, build_authorization_graph
from saga.ir.models import EndpointIR, PredicateType
from saga.verifier.models import (
    CandidateVulnerability,
    EndpointAnalysisReport,
    SAGAAnalysisSummary,
    VerificationStatus,
)


def verify_endpoint_security(
    ep: EndpointIR, graph: AuthorizationGraph
) -> EndpointAnalysisReport:
    """Analyze single endpoint against SAGA Authorization Graph using tri-state logic.

    Args:
        ep: EndpointIR model instance.
        graph: Populated AuthorizationGraph instance.

    Returns:
        EndpointAnalysisReport with PROVEN / UNPROVEN / UNKNOWN status.
    """
    auth_info = graph.inspect_endpoint_auth(ep.path, method=ep.http_method)

    # Extract principal label
    principal_name = "NONE"
    if ep.principals:
        p = ep.principals[0]
        type_str = f": {p.type_annotation}" if p.type_annotation else ""
        principal_name = f"{p.param_name}{type_str}"
    elif ep.security_metadata.requires_auth:
        principal_name = "current_user: User"

    # Extract object entity name
    object_entity = "NONE"
    if ep.objects:
        ignored = ("ORM_Filter", "router", "app")
        valid_objs = [o.entity_name for o in ep.objects if o.entity_name not in ignored]
        if valid_objs:
            object_entity = valid_objs[0]

    if object_entity == "NONE" and "{" in ep.path:
        if "doc" in ep.path or "document" in ep.path:
            object_entity = "Document"
        elif "order" in ep.path:
            object_entity = "Order"
        elif "user" in ep.path:
            object_entity = "User"
        else:
            object_entity = "Resource"

    # Extract reference parameter (path param)
    reference_param = "NONE"
    if ep.path_parameters:
        reference_param = ep.path_parameters[0].name
    elif "{" in ep.path:
        params = re.findall(r"\{([a-zA-Z0-9_]+)\}", ep.path)
        if params:
            reference_param = params[0]

    # Inspect predicate relationships
    has_ownership = auth_info.get("has_ownership_rule", False)
    has_tenant = auth_info.get("has_tenant_rule", False)
    is_delegated = auth_info.get("is_delegated_rule", False) or any(
        p.predicate_type == PredicateType.DELEGATED for p in ep.predicates
    )

    auth_rule = "NONE"
    if has_ownership:
        auth_rule = f"{object_entity}.owner_id == current_user.id"
    elif has_tenant:
        auth_rule = f"{object_entity}.tenant_id == current_user.tenant_id"
    elif is_delegated:
        auth_rule = "DELEGATED_CHECK"

    # Graph edge visualization summary
    graph_edges: list[str] = []
    p_label = principal_name.split(":")[0] if principal_name != "NONE" else "User"

    if ep.security_metadata.requires_auth or ep.principals:
        graph_edges.append(f"{p_label} ---authenticated---> Endpoint")

    if object_entity != "NONE":
        graph_edges.append(f"Endpoint ---references---> {object_entity}")

    if has_ownership:
        graph_edges.insert(0, f"{p_label} ---owns---> {object_entity}")
    elif has_tenant:
        graph_edges.insert(0, f"{p_label} ---same_tenant---> {object_entity}")
    elif is_delegated:
        graph_edges.insert(0, f"{p_label} ---delegates---> {object_entity}")

    # Deterministic Evidence Scoring Model:
    # +0.25 Authenticated principal detected
    # +0.25 Externally controllable reference parameter identified
    # +0.25 Security-sensitive object entity identified
    # +0.25 Proven relationship established (or +0.15 for delegated check)
    score = 0.0
    if ep.security_metadata.requires_auth or ep.principals:
        score += 0.25
    if reference_param != "NONE":
        score += 0.25
    if object_entity != "NONE":
        score += 0.25

    is_externally_controllable = reference_param != "NONE"
    is_security_sensitive = object_entity != "NONE"
    has_rel = has_ownership or has_tenant

    if has_rel:
        result = VerificationStatus.PROVEN
        candidate = CandidateVulnerability.NONE
        score += 0.25
        explanation = "Principal-object authorization relationship established statically."
    elif is_delegated:
        result = VerificationStatus.UNKNOWN
        candidate = CandidateVulnerability.NONE
        score += 0.15
        explanation = (
            "Authorization logic is delegated to an unresolved helper "
            "function or external policy check."
        )
    elif is_externally_controllable and is_security_sensitive:
        result = VerificationStatus.UNPROVEN
        candidate = CandidateVulnerability.BOLA
        explanation = (
            "Externally controllable security-sensitive object accessed without locally "
            "established principal-object authorization relationship."
        )
    else:
        result = VerificationStatus.UNPROVEN
        candidate = CandidateVulnerability.NONE
        explanation = "No static principal-object authorization relationship established."

    confidence = round(min(1.0, score), 2)

    return EndpointAnalysisReport(
        http_method=ep.http_method,
        path=ep.path,
        handler_name=ep.handler_name,
        source_file=ep.source_file,
        source_line=ep.source_line,
        principal=principal_name,
        object_entity=object_entity,
        reference_param=reference_param,
        authorization_rule=auth_rule,
        graph_edges=graph_edges,
        result=result,
        candidate=candidate,
        confidence=confidence,
        explanation=explanation,
    )


def analyze_target_security(
    endpoints: list[EndpointIR],
    target_path: str = "./",
) -> SAGAAnalysisSummary:
    """Run full static verifier pipeline across all discovered endpoints.

    Args:
        endpoints: List of correlated EndpointIR models.
        target_path: String path of analyzed target repository.

    Returns:
        SAGAAnalysisSummary containing detailed verification reports.
    """

    graph = build_authorization_graph(endpoints)

    reports: list[EndpointAnalysisReport] = []
    for ep in sorted(endpoints, key=lambda e: (e.http_method, e.path)):
        report = verify_endpoint_security(ep, graph)
        reports.append(report)

    return SAGAAnalysisSummary(
        target_path=str(target_path),
        discovered_endpoints=len(reports),
        reports=reports,
    )

