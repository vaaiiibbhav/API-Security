"""Canonical Intermediate Representation (IR) models for SAGA."""

from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from saga.ir.evidence import Evidence


class Parameter(BaseModel):
    """Path, query, or body parameter definition."""

    name: str
    location: str  # "path", "query", "header", "body"
    param_type: str = "str"
    required: bool = True
    default_value: Any = None
    evidence: Evidence | None = None


class RequestBody(BaseModel):
    """Structured request body model."""

    content_type: str = "application/json"
    schema_name: str | None = None
    properties: dict[str, Any] = Field(default_factory=dict)
    required_fields: list[str] = Field(default_factory=list)
    evidence: Evidence | None = None


class Principal(BaseModel):
    """Authenticated user context or principal representation."""

    param_name: str
    type_annotation: str | None = None
    dependency_func: str | None = None
    evidence: Evidence | None = None

    @property
    def confidence(self) -> float:
        return self.evidence.confidence_score if self.evidence else 1.0

    @property
    def source_line(self) -> int | None:
        return self.evidence.source_line if self.evidence else None


class ObjectReference(BaseModel):
    """Database model, entity, or resource reference."""

    entity_name: str
    access_method: str  # "query", "get", "filter", "path_param"
    filter_param: str | None = None
    is_externally_controlled: bool = False
    is_security_sensitive: bool = True
    evidence: Evidence | None = None

    @property
    def confidence(self) -> float:
        return self.evidence.confidence_score if self.evidence else 1.0

    @property
    def source_line(self) -> int | None:
        return self.evidence.source_line if self.evidence else None


class PredicateType(str, Enum):
    """Semantic authorization predicate types."""

    OWNERSHIP = "ownership"
    TENANT = "tenant"
    ROLE = "role"
    DELEGATED = "delegated"  # e.g., auth_service.can_access(...)
    CUSTOM = "custom"


class AuthorizationPredicate(BaseModel):
    """Semantic authorization condition extracted from route or helper."""

    predicate_type: PredicateType
    subject_expr: str
    object_expr: str
    operator: str = "=="
    normalized_relation: str = "NONE"
    evidence: Evidence | None = None

    @property
    def confidence(self) -> float:
        return self.evidence.confidence_score if self.evidence else 1.0

    @property
    def source_line(self) -> int | None:
        return self.evidence.source_line if self.evidence else None




class SecurityMetadata(BaseModel):
    """Security attributes associated with an endpoint."""

    requires_auth: bool = False
    security_schemes: list[str] = Field(default_factory=list)
    auth_dependencies: list[str] = Field(default_factory=list)
    required_roles: list[str] = Field(default_factory=list)


class EndpointIR(BaseModel):
    """Canonical Intermediate Representation of an API Endpoint."""

    http_method: str
    path: str
    handler_name: str
    source_file: Path | str | None = None
    source_line: int | None = None

    path_parameters: list[Parameter] = Field(default_factory=list)
    query_parameters: list[Parameter] = Field(default_factory=list)
    request_body: RequestBody | None = None
    security_metadata: SecurityMetadata = Field(default_factory=SecurityMetadata)

    principals: list[Principal] = Field(default_factory=list)
    objects: list[ObjectReference] = Field(default_factory=list)
    predicates: list[AuthorizationPredicate] = Field(default_factory=list)
    evidence: Evidence | None = None

    @property
    def auth_predicates(self) -> list[AuthorizationPredicate]:
        """Backward compatibility alias for predicates."""
        return self.predicates

