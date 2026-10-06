"""Integration tests for SAGA research testbed.

Proves vulnerability exploitability and secure enforcement per ground_truth.yaml.
"""

from pathlib import Path

import yaml
from fastapi.testclient import TestClient

from testbed.app import app
from testbed.seed import init_db

client = TestClient(app)

# Authentication headers for seeded users
ALICE_HEADERS = {"X-API-Token": "token_alice_123"}
BOB_HEADERS = {"X-API-Token": "token_bob_456"}
ADMIN_HEADERS = {"X-API-Token": "token_admin_789"}


def setup_function():
    """Re-seed database before each test run to ensure isolated test state."""
    init_db()


def test_auth_me_endpoint():
    """Verify user authentication dependency and user details."""
    response = client.get("/api/v1/auth/me", headers=ALICE_HEADERS)
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "alice"
    assert data["role"] == "user"
    assert data["tenant_id"] == "tenant_A"


def test_vulnerable_bola_exploit():
    """PROVE BOLA VULNERABILITY:

    Bob (user_id=2, tenant_B) reads Alice's (user_id=1, tenant_A) document (doc_id=101).
    Expected result: HTTP 200 OK with Alice's document data.
    """
    response = client.get("/api/v1/documents/101", headers=BOB_HEADERS)
    assert response.status_code == 200, f"Expected 200 OK (BOLA), got {response.status_code}"
    doc_data = response.json()
    assert doc_data["id"] == 101
    assert doc_data["owner_id"] == 1
    assert doc_data["title"] == "Alice's Secret Document"


def test_secure_ownership_enforcement():
    """PROVE OWNERSHIP SECURITY:

    Bob attempts to read Alice's document (doc_id=101) on secure ownership endpoint.
    Expected result: HTTP 403 Forbidden.
    """
    response = client.get("/api/v1/secure/documents/101", headers=BOB_HEADERS)
    assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}"
    assert "not the owner" in response.json()["detail"]

    # Verify Alice can access her own document
    alice_response = client.get("/api/v1/secure/documents/101", headers=ALICE_HEADERS)
    assert alice_response.status_code == 200


def test_secure_tenant_enforcement():
    """PROVE TENANT SECURITY:

    Bob (Tenant B) attempts to read Alice's document (Tenant A) on secure tenant endpoint.
    Expected result: HTTP 403 Forbidden.
    """
    response = client.get("/api/v1/secure/tenant/documents/101", headers=BOB_HEADERS)
    assert response.status_code == 403, f"Expected 403 Forbidden, got {response.status_code}"
    assert "Tenant isolation mismatch" in response.json()["detail"]

    # Verify Alice (Tenant A) can access Tenant A document
    alice_response = client.get("/api/v1/secure/tenant/documents/101", headers=ALICE_HEADERS)
    assert alice_response.status_code == 200


def test_vulnerable_bfla_exploit():
    """PROVE BFLA VULNERABILITY:

    Alice (role="user", standard privilege) executes admin deletion of Bob (user_id=2).
    Expected result: HTTP 200 OK (User deleted despite lacking admin role).
    """
    response = client.delete("/api/v1/admin/users/2", headers=ALICE_HEADERS)
    assert response.status_code == 200, f"Expected 200 OK (BFLA), got {response.status_code}"
    assert response.json()["message"] == "User 2 deleted successfully"


def test_unauthenticated_access_rejected():
    """Verify missing authentication tokens are rejected with HTTP 401."""
    response = client.get("/api/v1/documents/101")
    assert response.status_code == 401


def test_unknown_policy_enforcement():
    """Verify UNKNOWN policy endpoint behavior (rejects unauthorized access)."""
    response = client.get("/api/v1/secure/unknown/documents/101", headers=BOB_HEADERS)
    assert response.status_code == 403

    alice_response = client.get("/api/v1/secure/unknown/documents/101", headers=ALICE_HEADERS)
    assert alice_response.status_code == 200


def test_openapi_generation():
    """Verify FastAPI automatically generates OpenAPI schema containing testbed routes."""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()

    paths = schema.get("paths", {})
    assert "/api/v1/documents/{doc_id}" in paths
    assert "/api/v1/secure/documents/{doc_id}" in paths
    assert "/api/v1/secure/tenant/documents/{doc_id}" in paths
    assert "/api/v1/admin/users/{user_id}" in paths
    assert "/api/v1/secure/unknown/documents/{doc_id}" in paths


def test_ground_truth_file():
    """Verify ground_truth.yaml exists and parses cleanly."""
    ground_truth_path = Path(__file__).parent.parent / "testbed" / "ground_truth.yaml"
    assert ground_truth_path.is_file()

    with ground_truth_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    assert data["testbed_version"] == "1.0"
    endpoints = data["endpoints"]
    assert len(endpoints) == 5

    classifications = {ep["path"]: ep["classification"] for ep in endpoints}
    assert classifications["/api/v1/documents/{doc_id}"] == "vulnerable_bola"
    assert classifications["/api/v1/secure/documents/{doc_id}"] == "secure_ownership"
    assert classifications["/api/v1/secure/tenant/documents/{doc_id}"] == "secure_tenant"
    assert classifications["/api/v1/admin/users/{user_id}"] == "vulnerable_bfla"
    assert classifications["/api/v1/secure/unknown/documents/{doc_id}"] == "unknown_delegated"

