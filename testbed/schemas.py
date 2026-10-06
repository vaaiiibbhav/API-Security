"""Pydantic schemas for testbed API responses."""

from pydantic import BaseModel, ConfigDict


class UserResponse(BaseModel):
    """User response schema."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: str
    tenant_id: str


class DocumentResponse(BaseModel):
    """Document response schema."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    content: str
    owner_id: int
    tenant_id: str


class MessageResponse(BaseModel):
    """Generic message response schema."""

    message: str
