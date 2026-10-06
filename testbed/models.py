"""SQLAlchemy models for testbed."""

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from testbed.database import Base


class User(Base):
    """User database model."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    token: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    role: Mapped[str] = mapped_column(String(20), default="user")
    tenant_id: Mapped[str] = mapped_column(String(50), index=True)

    documents: Mapped[list["Document"]] = relationship(
        back_populates="owner", cascade="all, delete-orphan"
    )


class Document(Base):
    """Document database model."""

    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(100))
    content: Mapped[str] = mapped_column(String(500))
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    tenant_id: Mapped[str] = mapped_column(String(50), index=True)

    owner: Mapped[User] = relationship(back_populates="documents")
