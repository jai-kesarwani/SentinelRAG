"""
SentinelRAG — Authentication and User Management Tests.

Tests the full Phase 2 authentication pipeline:
  - Registration with duplicate prevention and password hashing
  - Login with correct and incorrect credentials
  - JWT Bearer access token verification
  - Protected /api/v1/auth/me access
  - Refresh session issuance and rotation
  - Refresh token revocation on logout and protection against revoked tokens
"""
from __future__ import annotations

import uuid
import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.db.mongodb import mongodb_manager
from app.db.users_repo import users_repo


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def auth_client():
    """Async client initialized with live lifespan context for database connectivity."""
    async with app.router.lifespan_context(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            yield client


@pytest.fixture
def unique_email():
    """Generate a unique test email address."""
    return f"tester_{uuid.uuid4().hex[:8]}@example.com"


# --------------------------------------------------------------------------- #
# Registration Tests
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_register_user_success(auth_client, unique_email):
    """Registering a new valid user should return HTTP 201 and public user profile."""
    payload = {
        "email": unique_email,
        "password": "SecurePassword123!",
        "display_name": "Test Engineer",
    }
    response = await auth_client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201
    body = response.json()
    assert "data" in body
    assert body["data"]["email"] == unique_email.lower()
    assert body["data"]["display_name"] == "Test Engineer"
    assert body["data"]["role"] == "user"
    assert "password" not in body["data"]
    assert "password_hash" not in body["data"]
    assert "correlation_id" in body.get("meta", {})


@pytest.mark.asyncio
async def test_register_duplicate_email_rejected(auth_client, unique_email):
    """Registering an already-registered email should return HTTP 409 conflict."""
    payload = {
        "email": unique_email,
        "password": "SecurePassword123!",
        "display_name": "First User",
    }
    res1 = await auth_client.post("/api/v1/auth/register", json=payload)
    assert res1.status_code == 201

    # Second registration with duplicate email
    res2 = await auth_client.post("/api/v1/auth/register", json=payload)
    assert res2.status_code == 409
    body = res2.json()
    assert "error" in body
    assert body["error"]["code"] == "EMAIL_EXISTS"


@pytest.mark.asyncio
async def test_password_never_stored_in_plaintext(auth_client, unique_email):
    """Verify in MongoDB that the stored password is an Argon2 hash, not plaintext."""
    raw_password = "PlaintextSecret999!"
    payload = {
        "email": unique_email,
        "password": raw_password,
        "display_name": "Security Check",
    }
    res = await auth_client.post("/api/v1/auth/register", json=payload)
    assert res.status_code == 201

    user = await users_repo.get_by_email(unique_email)
    assert user is not None
    assert user.password_hash != raw_password
    assert user.password_hash.startswith("$argon2id$")


# --------------------------------------------------------------------------- #
# Login Tests
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_login_success(auth_client, unique_email):
    """Logging in with valid credentials returns access token and sets refresh cookie."""
    password = "CorrectPassword123!"
    reg_payload = {
        "email": unique_email,
        "password": password,
        "display_name": "Login User",
    }
    await auth_client.post("/api/v1/auth/register", json=reg_payload)

    login_payload = {"email": unique_email, "password": password}
    response = await auth_client.post("/api/v1/auth/login", json=login_payload)
    assert response.status_code == 200
    body = response.json()
    assert "data" in body
    assert "access_token" in body["data"]
    assert body["data"]["token_type"] == "bearer"
    assert body["data"]["user"]["email"] == unique_email.lower()
    # Check that Set-Cookie header contains sentinel_refresh
    set_cookie = response.headers.get("set-cookie", "")
    assert "sentinel_refresh" in set_cookie


@pytest.mark.asyncio
async def test_login_incorrect_password(auth_client, unique_email):
    """Logging in with wrong password returns HTTP 401."""
    reg_payload = {
        "email": unique_email,
        "password": "CorrectPassword123!",
        "display_name": "Test User",
    }
    await auth_client.post("/api/v1/auth/register", json=reg_payload)

    login_payload = {"email": unique_email, "password": "WrongPassword999!"}
    response = await auth_client.post("/api/v1/auth/login", json=login_payload)
    assert response.status_code == 401
    body = response.json()
    assert "error" in body
    assert body["error"]["code"] == "INVALID_CREDENTIALS"


# --------------------------------------------------------------------------- #
# Protected Endpoint (/me) Tests
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_protected_route_rejects_unauthenticated(auth_client):
    """Accessing /api/v1/auth/me without token must return HTTP 401."""
    response = await auth_client.get("/api/v1/auth/me")
    assert response.status_code == 401
    body = response.json()
    assert "error" in body
    assert body["error"]["code"] == "AUTHENTICATION_REQUIRED"


@pytest.mark.asyncio
async def test_protected_route_with_valid_token(auth_client, unique_email):
    """Accessing /api/v1/auth/me with valid Bearer token returns user profile."""
    password = "ValidPassword123!"
    await auth_client.post(
        "/api/v1/auth/register",
        json={"email": unique_email, "password": password, "display_name": "Alice"},
    )
    login_res = await auth_client.post(
        "/api/v1/auth/login",
        json={"email": unique_email, "password": password},
    )
    token = login_res.json()["data"]["access_token"]

    response = await auth_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["data"]["email"] == unique_email.lower()
    assert body["data"]["display_name"] == "Alice"


@pytest.mark.asyncio
async def test_protected_route_with_invalid_token(auth_client):
    """Accessing /api/v1/auth/me with invalid token returns HTTP 401."""
    response = await auth_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer invalid.token.value"},
    )
    assert response.status_code == 401
    body = response.json()
    assert body["error"]["code"] == "INVALID_TOKEN"


# --------------------------------------------------------------------------- #
# Refresh & Logout Tests
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_refresh_token_rotation_and_logout(auth_client, unique_email):
    """Full refresh token lifecycle: login -> refresh -> rotated -> logout -> revocation."""
    password = "PasswordLifecycle123!"
    await auth_client.post(
        "/api/v1/auth/register",
        json={"email": unique_email, "password": password, "display_name": "Bob"},
    )
    login_res = await auth_client.post(
        "/api/v1/auth/login",
        json={"email": unique_email, "password": password},
    )
    # Extract cookie
    cookie = login_res.cookies.get("sentinel_refresh")
    assert cookie is not None

    # Refresh session
    refresh_res = await auth_client.post("/api/v1/auth/refresh", cookies={"sentinel_refresh": cookie})
    assert refresh_res.status_code == 200
    new_access_token = refresh_res.json()["data"]["access_token"]
    assert new_access_token is not None

    new_cookie = refresh_res.cookies.get("sentinel_refresh")
    assert new_cookie is not None
    # Token rotation: new cookie must differ from old cookie
    assert new_cookie != cookie

    # Verify new access token works
    me_res = await auth_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {new_access_token}"},
    )
    assert me_res.status_code == 200

    # Old refresh token is revoked: presenting it must fail
    old_res = await auth_client.post("/api/v1/auth/refresh", cookies={"sentinel_refresh": cookie})
    assert old_res.status_code == 401

    # Logout with current cookie
    logout_res = await auth_client.post("/api/v1/auth/logout", cookies={"sentinel_refresh": new_cookie})
    assert logout_res.status_code == 200

    # Current cookie is now also revoked
    after_logout_res = await auth_client.post("/api/v1/auth/refresh", cookies={"sentinel_refresh": new_cookie})
    assert after_logout_res.status_code == 401

