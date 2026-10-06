"""Database seeding for testbed research environment."""

from sqlalchemy.orm import Session

from testbed.database import Base, SessionLocal, engine
from testbed.models import Document, User


def seed_db(db: Session) -> None:
    """Populate database with initial test users and documents."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    # Seed Users
    user1 = User(
        id=1,
        username="alice",
        token="token_alice_123",
        role="user",
        tenant_id="tenant_A",
    )
    user2 = User(
        id=2,
        username="bob",
        token="token_bob_456",
        role="user",
        tenant_id="tenant_B",
    )
    admin1 = User(
        id=3,
        username="admin_carol",
        token="token_admin_789",
        role="admin",
        tenant_id="tenant_A",
    )

    db.add_all([user1, user2, admin1])
    db.commit()

    # Seed Documents
    doc1 = Document(
        id=101,
        title="Alice's Secret Document",
        content="Confidential financial report for Tenant A",
        owner_id=user1.id,
        tenant_id=user1.tenant_id,
    )
    doc2 = Document(
        id=102,
        title="Bob's Private Notes",
        content="Personal notes for Tenant B",
        owner_id=user2.id,
        tenant_id=user2.tenant_id,
    )

    db.add_all([doc1, doc2])
    db.commit()


def init_db() -> None:
    """Helper function to initialize and seed the database."""
    db = SessionLocal()
    try:
        seed_db(db)
    finally:
        db.close()


if __name__ == "__main__":
    init_db()
    print("Testbed database seeded successfully.")
