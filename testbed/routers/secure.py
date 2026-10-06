"""Secure API endpoints enforcing ownership and tenant authorization."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from testbed.auth import get_current_user
from testbed.database import get_db
from testbed.models import Document, User
from testbed.schemas import DocumentResponse

router = APIRouter(prefix="/api/v1/secure", tags=["secure"])


@router.get("/documents/{doc_id}", response_model=DocumentResponse)
def get_document_secure_ownership(
    doc_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Document:
    """SECURE OWNERSHIP ENDPOINT.

    Retrieves document by ID enforcing strict owner verification (doc.owner_id == current_user.id).
    """
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Document with ID {doc_id} not found",
        )

    if doc.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You are not the owner of this document",
        )

    return doc


@router.get("/tenant/documents/{doc_id}", response_model=DocumentResponse)
def get_document_secure_tenant(
    doc_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Document:
    """SECURE TENANT ENDPOINT.

    Retrieves document by ID enforcing tenant isolation
    (doc.tenant_id == current_user.tenant_id).
    """
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Document with ID {doc_id} not found",
        )

    if doc.tenant_id != current_user.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Tenant isolation mismatch",
        )

    return doc


def check_custom_policy(user: User, doc: Document) -> bool:
    """Unresolved external policy helper function."""
    return doc.owner_id == user.id


@router.get("/unknown/documents/{doc_id}", response_model=DocumentResponse)
def get_document_unknown_policy(
    doc_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Document:
    """UNKNOWN AUTHORIZATION ENDPOINT.

    Retrieves document after delegating authorization to external helper check_custom_policy.
    SAGA static analysis flags this as UNKNOWN because policy semantics are unresolved.
    """
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Document with ID {doc_id} not found",
        )

    if not check_custom_policy(current_user, doc):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied by policy engine",
        )

    return doc

