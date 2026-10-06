"""Canonical Intermediate Representation (IR) package for SAGA."""

from saga.ir.evidence import Evidence
from saga.ir.models import (
    AuthorizationPredicate,
    EndpointIR,
    ObjectReference,
    Parameter,
    PredicateType,
    Principal,
    RequestBody,
    SecurityMetadata,
)
from saga.ir.normalizer import normalize_predicate

__all__ = [
    "AuthorizationPredicate",
    "EndpointIR",
    "Evidence",
    "ObjectReference",
    "Parameter",
    "PredicateType",
    "Principal",
    "RequestBody",
    "SecurityMetadata",
    "normalize_predicate",
]
