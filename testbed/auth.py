"""Authentication dependency for testbed API endpoints."""

from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from testbed.database import get_db
from testbed.models import User


def get_current_user(
    x_api_token: Annotated[str | None, Header(alias="X-API-Token")] = None,
    db: Session = Depends(get_db),
) -> User:
    """Extract and authenticate user based on X-API-Token header.

    Raises:
        HTTPException 401 if token is missing or invalid.
    """
    if not x_api_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication header: X-API-Token",
        )

    user = db.query(User).filter(User.token == x_api_token).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )

    return user
