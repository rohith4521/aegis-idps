import pytest
from fastapi import status


def test_login_success_admin(client):
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "Admin@123456"}
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["username"] == "admin"
    assert data["user"]["role"] == "admin"
    assert "hashed_password" not in data["user"]


def test_login_success_analyst(client):
    response = client.post(
        "/api/auth/login",
        json={"username": "analyst", "password": "Analyst@123456"}
    )
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "access_token" in data
    assert data["user"]["role"] == "analyst"


def test_login_invalid_password(client):
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "WrongPassword!"}
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Incorrect username or password" in response.json()["detail"]


def test_login_nonexistent_user(client):
    response = client.post(
        "/api/auth/login",
        json={"username": "nonexistent_hacker", "password": "Password123!"}
    )
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_get_current_user_profile(client):
    # 1. Login
    login_resp = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "Admin@123456"}
    )
    token = login_resp.json()["access_token"]

    # 2. Access /me
    headers = {"Authorization": f"Bearer {token}"}
    me_resp = client.get("/api/auth/me", headers=headers)
    assert me_resp.status_code == status.HTTP_200_OK
    user_data = me_resp.json()
    assert user_data["username"] == "admin"
    assert user_data["email"] == "admin@aegis-idps.net"


def test_get_current_user_unauthorized(client):
    # Missing token
    resp = client.get("/api/auth/me")
    assert resp.status_code == status.HTTP_401_UNAUTHORIZED

    # Invalid token
    resp2 = client.get("/api/auth/me", headers={"Authorization": "Bearer invalid_token_xyz"})
    assert resp2.status_code == status.HTTP_401_UNAUTHORIZED


def test_expired_token_rejection(client):
    from datetime import timedelta
    from app.core.security import create_access_token
    expired_token = create_access_token(
        subject="admin",
        role="admin",
        expires_delta=timedelta(seconds=-10)
    )
    resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert resp.status_code == status.HTTP_401_UNAUTHORIZED
    assert "token expired" in resp.json()["detail"].lower() or "credentials" in resp.json()["detail"].lower()


def test_tampered_token_signature_rejection(client):
    from app.core.security import create_access_token
    token = create_access_token(subject="admin", role="admin")
    # Tamper with the signature portion
    parts = token.split(".")
    tampered_sig = parts[2][:-2] + "xx"
    tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"
    resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {tampered_token}"})
    assert resp.status_code == status.HTTP_401_UNAUTHORIZED


def test_malformed_token_rejection(client):
    resp = client.get("/api/auth/me", headers={"Authorization": "Bearer not.a.valid.jwt"})
    assert resp.status_code == status.HTTP_401_UNAUTHORIZED


def test_token_missing_sub_rejection(client):
    import jwt
    from app.core.config import settings
    # Token without 'sub'
    payload = {"role": "admin"}
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == status.HTTP_401_UNAUTHORIZED


def test_inactive_user_token_rejection(client, db):
    from app.models.user import User
    from app.core.security import create_access_token, get_password_hash
    # Create an inactive user
    inactive_user = User(
        username="suspended_user",
        email="suspended@aegis-idps.net",
        full_name="Suspended Analyst",
        hashed_password=get_password_hash("SomePassword123!"),
        role="analyst",
        is_active=False
    )
    db.add(inactive_user)
    db.commit()

    token = create_access_token(subject="suspended_user", role="analyst")
    resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == status.HTTP_403_FORBIDDEN
    assert "Inactive" in resp.json()["detail"]


def test_production_configuration_validation():
    from app.core.config import Settings

    # 1. Insecure default secret in production -> error
    with pytest.raises(ValueError, match="strong SECRET_KEY"):
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="short",
            ADMIN_PASSWORD="StrongProductionPassword987!"
        )

    # 2. DEMO_MODE enabled in production -> error
    with pytest.raises(ValueError, match="DEMO_MODE cannot be enabled"):
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="A"*32,
            DEMO_MODE=True,
            ADMIN_PASSWORD="StrongProductionPassword987!"
        )

    # 3. Default or missing ADMIN_PASSWORD in production -> error
    with pytest.raises(ValueError, match="ADMIN_PASSWORD"):
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="A"*32,
            DEMO_MODE=False,
            ADMIN_PASSWORD="Admin@123456"
        )

    # 4. Valid production settings -> passes
    prod_settings = Settings(
        ENVIRONMENT="production",
        SECRET_KEY="SuperSecretProductionKeyWith32CharsMinimum!",
        DEMO_MODE=False,
        ADMIN_PASSWORD="UltraSecureCustomAdminKey2026!"
    )
    assert prod_settings.ENVIRONMENT == "production"
    assert prod_settings.DEMO_MODE is False

