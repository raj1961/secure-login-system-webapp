from datetime import datetime, timedelta

from app import create_app
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
        },
        follow_redirects=False,
    )


def test_csrf_missing_token_rejected():
    app = create_app(
        test_config={
            "TESTING": True,
            "SECRET_KEY": "csrf-secret",
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "WTF_CSRF_ENABLED": True,
            "TURNSTILE_ENABLED": False,
            "TURNSTILE_BYPASS": True,
        }
    )

    with app.app_context():
        db.create_all()
        client = app.test_client()
        response = client.post(
            "/register",
            data={
                "username": "csrf_user",
                "email": "csrf@example.com",
                "password": "StrongPass123!",
                "role": "user",
            },
            follow_redirects=False,
        )
        assert response.status_code == 400
        db.drop_all()


def test_sql_injection_payload_does_not_bypass_login(client, app):
    with app.app_context():
        user = User(
            username="inj_user",
            email="inj@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

    response = client.post(
        "/login",
        data={
            "email": "inj@example.com' OR '1'='1",
            "password": "anything",
        },
        follow_redirects=True,
    )

    assert response.status_code == 401
    assert b"Invalid email or password" in response.data


def test_invalid_captcha_blocks_login(client, app, monkeypatch):
    with app.app_context():
        user = User(
            username="captcha_user",
            email="captcha@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

    app.config.update(
        TURNSTILE_ENABLED=True,
        TURNSTILE_BYPASS=False,
        TURNSTILE_SECRET_KEY="dummy-secret",
    )

    monkeypatch.setattr(auth_routes, "verify_turnstile_token", lambda _token, _ip=None: False)

    response = client.post(
        "/login",
        data={
            "email": "captcha@example.com",
            "password": "StrongPass123!",
            "cf-turnstile-response": "invalid-token",
        },
        follow_redirects=True,
    )

    assert response.status_code == 400
    assert b"CAPTCHA validation failed" in response.data


def test_session_cookie_has_secure_flags(client, app):
    with app.app_context():
        user = User(
            username="cookie_user",
            email="cookie@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

    response = login(client, "cookie@example.com", "StrongPass123!")
    cookie_header = response.headers.get("Set-Cookie", "")

    assert "HttpOnly" in cookie_header
    assert "SameSite=Lax" in cookie_header


def test_logout_invalidates_session(client, app):
    with app.app_context():
        user = User(
            username="logout_user",
            email="logout@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

    login(client, "logout@example.com", "StrongPass123!")
    client.post("/logout", follow_redirects=False)

    response = client.get("/dashboard", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_failed_attempts_reset_after_successful_login(client, app):
    with app.app_context():
        user = User(
            username="reset_user",
            email="reset@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

    for _ in range(4):
        login(client, "reset@example.com", "WrongPass123!")

    login(client, "reset@example.com", "StrongPass123!")

    with app.app_context():
        user = User.query.filter_by(email="reset@example.com").first()
        assert user.failed_attempts == 0
        assert user.lockout_until is None


def test_lockout_does_not_persist_after_timeout(client, app):
    with app.app_context():
        user = User(
            username="timeout_user",
            email="timeout@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="user",
            is_active=True,
            failed_attempts=0,
            lockout_until=datetime.utcnow() - timedelta(minutes=1),
        )
        db.session.add(user)
        db.session.commit()

    response = login(client, "timeout@example.com", "StrongPass123!")
    assert response.status_code == 302
    assert "/dashboard" in response.headers["Location"]


def test_disabled_user_cannot_authenticate(client, app):
    with app.app_context():
        user = User(
            username="disabled_user",
            email="disabled@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="user",
            is_active=False,
        )
        db.session.add(user)
        db.session.commit()

    response = client.post(
        "/login",
        data={"email": "disabled@example.com", "password": "StrongPass123!"},
        follow_redirects=True,
    )

    assert response.status_code == 401
    assert b"Invalid email or password" in response.data
