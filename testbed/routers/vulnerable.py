"""Deliberately vulnerable API endpoints for BOLA and BFLA research."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from testbed.auth import get_current_user
from testbed.database import get_db
from testbed.models import Document, User
from testbed.schemas import DocumentResponse, MessageResponse

router = APIRouter(prefix="/api/v1", tags=["vulnerable"])


@router.get("/documents/{doc_id}", response_model=DocumentResponse)
def get_document_vulnerable_bola(
    doc_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Document:
    """VULNERABLE BOLA ENDPOINT.

    Retrieves document by ID for any authenticated user without validating
    ownership or tenant authorization.
    """
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Document with ID {doc_id} not found",
        )

    # Intentionally missing check: doc.owner_id == current_user.id
    return doc


@router.delete("/admin/users/{user_id}", response_model=MessageResponse)
def delete_user_vulnerable_bfla(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """VULNERABLE BFLA ENDPOINT.

    Administrative user deletion endpoint that requires authentication but
    intentionally omits role authorization checks (e.g. current_user.role == 'admin').
    """
    user_to_delete = db.query(User).filter(User.id == user_id).first()
    if not user_to_delete:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found",
        )

    # Intentionally missing check: if current_user.role != "admin": raise 403
    db.delete(user_to_delete)
    db.commit()

    return {"message": f"User {user_id} deleted successfully"}
