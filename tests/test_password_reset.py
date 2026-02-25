from app.auth import routes as auth_routes
from app.extensions import db
from app.models import User
from app.security import hash_password


def login(client, email, password):
    return client.post(
        "/login",
        data={
            "email": email,
            "password": password,
            "cf-turnstile-response": "test-token",
        },
        follow_redirects=False,
    )


def test_forgot_password_and_reset_flow(client, app, monkeypatch):
    with app.app_context():
        user = User(
            username="reset_owner",
            email="resetowner@example.com",
            password_hash=hash_password("OldPass1234!"),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

    monkeypatch.setattr(auth_routes.secrets, "token_urlsafe", lambda _n: "fixed-reset-token")

    forgot_response = client.post(
        "/forgot-password",
        data={"email": "resetowner@example.com", "cf-turnstile-response": "ok"},
        follow_redirects=True,
    )
    assert forgot_response.status_code == 200
    assert b"Password reset link" in forgot_response.data

    reset_response = client.post(
        "/reset-password/fixed-reset-token",
        data={
            "password": "NewPass1234!@",
            "confirm_password": "NewPass1234!@",
        },
        follow_redirects=True,
    )
    assert reset_response.status_code == 200
    assert b"Password updated successfully" in reset_response.data

    login_response = login(client, "resetowner@example.com", "NewPass1234!@")
    assert login_response.status_code == 302
    assert "/dashboard" in login_response.headers["Location"]


def test_reset_password_invalid_token_redirects(client):
    response = client.get("/reset-password/invalid-token", follow_redirects=True)
    assert response.status_code == 200
    assert b"Reset link is invalid or expired" in response.data
