"""Normalizer converting extracted expressions into canonical security predicates."""

from saga.ir.evidence import Evidence
from saga.ir.models import AuthorizationPredicate, PredicateType


def normalize_predicate(
    subject_expr: str,
    object_expr: str,
    operator: str = "==",
    raw_type: str = "ownership",
    evidence: Evidence | None = None,
) -> AuthorizationPredicate:
    """Normalize raw code comparison into canonical AuthorizationPredicate.

    Ensures commutativity: e.g. `doc.owner_id == current_user.id` and
    `current_user.id == doc.owner_id` produce identical normalized_relation.

    Args:
        subject_expr: Subject expression string.
        object_expr: Object expression string.
        operator: Operator string ("==", "!=").
        raw_type: Raw predicate type string.
        evidence: Optional source code evidence.

    Returns:
        Normalized AuthorizationPredicate instance.
    """
    all_str = f"{subject_expr} {operator} {object_expr}"

    if "owner" in all_str.lower() or "user_id" in all_str.lower():
        p_type = PredicateType.OWNERSHIP
        relation = "owns"
    elif "tenant" in all_str.lower():
        p_type = PredicateType.TENANT
        relation = "same_tenant"
    elif "role" in all_str.lower():
        p_type = PredicateType.ROLE
        relation = "has_role"
    elif "can_access" in all_str.lower() or "check" in all_str.lower():
        p_type = PredicateType.DELEGATED
        relation = "delegated_access"
    else:
        p_type = PredicateType.CUSTOM
        relation = "custom_check"

    # Canonical ordering: ensure subject contains current_user/principal
    s_expr, o_expr = subject_expr, object_expr
    if "current_user" in object_expr or "principal" in object_expr:
        s_expr, o_expr = object_expr, subject_expr

    return AuthorizationPredicate(
        predicate_type=p_type,
        subject_expr=s_expr,
        object_expr=o_expr,
        operator=operator,
        normalized_relation=relation,
        evidence=evidence,
    )
