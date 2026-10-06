"""Evidence-preserving SAGA Authorization Graph using NetworkX."""

import json
from enum import Enum
from typing import Any

import networkx as nx

from saga.ir.evidence import Evidence
from saga.ir.models import EndpointIR, PredicateType


class NodeType(str, Enum):
    """Typed nodes for SAGA Authorization Graph."""

    PRINCIPAL = "Principal"
    OBJECT = "Object"
    RELATIONSHIP = "Relationship"
    ACTION = "Action"
    ENDPOINT = "Endpoint"


class EdgeType(str, Enum):
    """Typed edges for SAGA Authorization Graph."""

    OWNS = "owns"
    SAME_TENANT = "same_tenant"
    ASSIGNED_TO = "assigned_to"
    AUTHENTICATES = "authenticates"
    PERMITS = "permits"
    REFERENCES = "references"
    DELEGATES = "delegates"


def _clean_data(val: Any) -> Any:
    """Recursively convert Path objects to strings for JSON serializability."""
    from pathlib import Path
    if isinstance(val, Path):
        return str(val)
    if isinstance(val, dict):
        return {k: _clean_data(v) for k, v in val.items()}
    if isinstance(val, list):
        return [_clean_data(v) for v in val]
    return val


class AuthorizationGraph:
    """Evidence-preserving SAGA Authorization Graph built on NetworkX."""

    def __init__(self) -> None:
        self.graph = nx.DiGraph()

    def add_node(
        self,
        node_id: str,
        node_type: NodeType,
        label: str | None = None,
        evidence: Evidence | dict[str, Any] | None = None,
        **attrs: Any,
    ) -> str:
        """Add a typed node to graph preserving source code evidence."""
        ev_dict = (
            evidence.model_dump(mode="json")
            if isinstance(evidence, Evidence)
            else (evidence or {})
        )
        cleaned_ev = _clean_data(ev_dict)
        cleaned_attrs = _clean_data(attrs)
        self.graph.add_node(
            node_id,
            node_type=node_type.value if isinstance(node_type, NodeType) else node_type,
            label=label or node_id,
            evidence=cleaned_ev,
            **cleaned_attrs,
        )
        return node_id

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType,
        evidence: Evidence | dict[str, Any] | None = None,
        **attrs: Any,
    ) -> None:
        """Add a typed edge to graph preserving source code evidence."""
        ev_dict = (
            evidence.model_dump(mode="json")
            if isinstance(evidence, Evidence)
            else (evidence or {})
        )
        cleaned_ev = _clean_data(ev_dict)
        cleaned_attrs = _clean_data(attrs)
        self.graph.add_edge(
            source_id,
            target_id,
            edge_type=edge_type.value if isinstance(edge_type, EdgeType) else edge_type,
            evidence=cleaned_ev,
            **cleaned_attrs,
        )


    def get_nodes(self, node_type: NodeType | str | None = None) -> list[dict[str, Any]]:
        """Return graph nodes filtered by node_type."""
        result: list[dict[str, Any]] = []
        target_type = node_type.value if isinstance(node_type, NodeType) else node_type

        for n, data in sorted(self.graph.nodes(data=True)):
            if target_type is None or data.get("node_type") == target_type:
                result.append({"id": n, **data})

        return result

    def get_edges(self, edge_type: EdgeType | str | None = None) -> list[dict[str, Any]]:
        """Return graph edges filtered by edge_type."""
        result: list[dict[str, Any]] = []
        target_type = edge_type.value if isinstance(edge_type, EdgeType) else edge_type

        for u, v, data in sorted(self.graph.edges(data=True)):
            if target_type is None or data.get("edge_type") == target_type:
                result.append({"source": u, "target": v, **data})

        return result

    def has_edge(
        self, source_id: str, target_id: str, edge_type: EdgeType | str | None = None
    ) -> bool:
        """Check if edge exists between source and target with optional edge_type filter."""
        if not self.graph.has_edge(source_id, target_id):
            return False

        if edge_type is None:
            return True

        target_type = edge_type.value if isinstance(edge_type, EdgeType) else edge_type
        edge_data = self.graph.get_edge_data(source_id, target_id, {})
        return edge_data.get("edge_type") == target_type

    def inspect_endpoint_auth(
        self, endpoint_id_or_path: str, method: str = "GET"
    ) -> dict[str, Any]:
        """Inspect security, nodes, relationships, and evidence associated with an endpoint."""
        node_id = endpoint_id_or_path
        if not node_id.startswith("ENDPOINT:"):
            node_id = f"ENDPOINT:{method.upper()}:{endpoint_id_or_path}"

        if not self.graph.has_node(node_id):
            return {"found": False, "error": f"Endpoint node {node_id} not found"}

        outgoing_edges = self.graph.out_edges(node_id, data=True)
        principals = []
        objects = []
        actions = []
        has_ownership = False
        has_tenant = False
        is_delegated = False

        for _, target, _data in outgoing_edges:
            target_data = self.graph.nodes[target]

            target_type = target_data.get("node_type")

            if target_type == NodeType.PRINCIPAL.value:
                principals.append(target)
            elif target_type == NodeType.OBJECT.value:
                objects.append(target)
            elif target_type == NodeType.ACTION.value:
                actions.append(target)
            elif target_type == NodeType.RELATIONSHIP.value:
                check_type = target_data.get("check_type")
                if check_type == PredicateType.OWNERSHIP.value:
                    has_ownership = True
                elif check_type == PredicateType.TENANT.value:
                    has_tenant = True
                elif check_type == PredicateType.DELEGATED.value:
                    is_delegated = True

        return {
            "found": True,
            "endpoint": node_id,
            "principals": principals,
            "objects": objects,
            "actions": actions,
            "has_ownership_rule": has_ownership,
            "has_tenant_rule": has_tenant,
            "is_delegated_rule": is_delegated,
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize graph to dictionary."""
        nodes = [{"id": n, **data} for n, data in sorted(self.graph.nodes(data=True))]
        edges = [
            {"source": u, "target": v, **data}
            for u, v, data in sorted(self.graph.edges(data=True))
        ]
        return {"nodes": nodes, "edges": edges}

    def to_json(self, indent: int = 2) -> str:
        """Serialize graph to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuthorizationGraph":
        """Deserialize graph from dictionary."""
        ag = cls()
        for node in data.get("nodes", []):
            n_id = node["id"]
            n_type = node.get("node_type", NodeType.ENDPOINT.value)
            label = node.get("label", n_id)
            evidence = node.get("evidence")
            attrs = {
                k: v
                for k, v in node.items()
                if k not in ("id", "node_type", "label", "evidence")
            }
            ag.add_node(n_id, NodeType(n_type), label=label, evidence=evidence, **attrs)

        for edge in data.get("edges", []):
            src = edge["source"]
            tgt = edge["target"]
            e_type = edge.get("edge_type", EdgeType.REFERENCES.value)
            evidence = edge.get("evidence")
            attrs = {
                k: v
                for k, v in edge.items()
                if k not in ("source", "target", "edge_type", "evidence")
            }
            ag.add_edge(src, tgt, EdgeType(e_type), evidence=evidence, **attrs)

        return ag

    @classmethod
    def from_json(cls, json_str: str) -> "AuthorizationGraph":
        """Deserialize graph from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)


def build_authorization_graph(endpoints_ir: list[EndpointIR]) -> AuthorizationGraph:
    """Construct a SAGA Authorization Graph directly from Canonical EndpointIR models.

    Args:
        endpoints_ir: List of Canonical EndpointIR instances.

    Returns:
        Populated AuthorizationGraph instance.
    """
    ag = AuthorizationGraph()

    for ep in sorted(endpoints_ir, key=lambda e: (e.http_method, e.path)):
        ep_id = f"ENDPOINT:{ep.http_method.upper()}:{ep.path}"
        ep_ev = ep.evidence or Evidence(source_file=ep.source_file, source_line=ep.source_line)

        ag.add_node(
            ep_id,
            NodeType.ENDPOINT,
            label=f"{ep.http_method} {ep.path}",
            handler_name=ep.handler_name,
            evidence=ep_ev,
        )

        # Action Node & Edge
        action_id = f"ACTION:{ep.http_method.upper()}"
        ag.add_node(action_id, NodeType.ACTION, label=ep.http_method.upper(), evidence=ep_ev)
        ag.add_edge(ep_id, action_id, EdgeType.PERMITS, evidence=ep_ev)

        # Principal Nodes & Edges
        principal_ids: list[str] = []
        if ep.principals:
            for p in ep.principals:
                p_id = f"PRINCIPAL:{p.param_name}"
                p_ev = p.evidence or ep_ev
                ag.add_node(p_id, NodeType.PRINCIPAL, label=p.param_name, evidence=p_ev)
                ag.add_edge(ep_id, p_id, EdgeType.AUTHENTICATES, evidence=p_ev)
                principal_ids.append(p_id)
        elif ep.security_metadata.requires_auth:
            p_id = "PRINCIPAL:current_user"
            ag.add_node(p_id, NodeType.PRINCIPAL, label="current_user", evidence=ep_ev)
            ag.add_edge(ep_id, p_id, EdgeType.AUTHENTICATES, evidence=ep_ev)
            principal_ids.append(p_id)

        # Object Nodes & Edges
        object_ids: list[str] = []
        if ep.objects:
            for obj in ep.objects:
                if obj.entity_name in ("ORM_Filter", "router", "app"):
                    continue
                o_id = f"OBJECT:{obj.entity_name}"
                o_ev = obj.evidence or ep_ev
                ag.add_node(o_id, NodeType.OBJECT, label=obj.entity_name, evidence=o_ev)
                ag.add_edge(ep_id, o_id, EdgeType.REFERENCES, evidence=o_ev)
                object_ids.append(o_id)

        # Authorization Predicate Nodes & Edges
        for pred in ep.predicates:
            pred_ev = pred.evidence or ep_ev
            rel_id = f"RELATIONSHIP:{pred.predicate_type.value}:{ep.handler_name}"
            ag.add_node(
                rel_id,
                NodeType.RELATIONSHIP,
                label=f"{pred.predicate_type.value}_check",
                check_type=pred.predicate_type.value,
                subject=pred.subject_expr,
                object=pred.object_expr,
                evidence=pred_ev,
            )
            ag.add_edge(ep_id, rel_id, EdgeType.REFERENCES, evidence=pred_ev)

            if pred.predicate_type == PredicateType.OWNERSHIP:
                for p_id in principal_ids:
                    for o_id in object_ids:
                        ag.add_edge(p_id, o_id, EdgeType.OWNS, evidence=pred_ev)
                        ag.add_edge(p_id, rel_id, EdgeType.OWNS, evidence=pred_ev)
                        ag.add_edge(rel_id, o_id, EdgeType.REFERENCES, evidence=pred_ev)

            elif pred.predicate_type == PredicateType.TENANT:
                for p_id in principal_ids:
                    for o_id in object_ids:
                        ag.add_edge(p_id, o_id, EdgeType.SAME_TENANT, evidence=pred_ev)
                        ag.add_edge(p_id, rel_id, EdgeType.SAME_TENANT, evidence=pred_ev)
                        ag.add_edge(rel_id, o_id, EdgeType.REFERENCES, evidence=pred_ev)

            elif pred.predicate_type == PredicateType.DELEGATED:
                for p_id in principal_ids:
                    for o_id in object_ids:
                        ag.add_edge(p_id, rel_id, EdgeType.DELEGATES, evidence=pred_ev)
                        ag.add_edge(rel_id, o_id, EdgeType.REFERENCES, evidence=pred_ev)

    return ag
