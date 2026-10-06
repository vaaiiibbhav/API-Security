"""Authentication router for testbed."""

from fastapi import APIRouter, Depends

from testbed.auth import get_current_user
from testbed.models import User
from testbed.schemas import UserResponse

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)) -> User:
    """Return currently authenticated user information."""
    return current_user
