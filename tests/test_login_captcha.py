from app.extensions import db
from app.models import User
from app.security import hash_password


def test_login_requires_local_captcha_when_turnstile_disabled(client, app):
    app.config.update(TURNSTILE_BYPASS=False, TURNSTILE_ENABLED=False)

    with app.app_context():
        user = User(
            username="local_captcha_user",
            email="localcaptcha@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

    # Fetch login page to receive local captcha token in form.
    page = client.get("/login")
    assert page.status_code == 200
    assert b"I am not a robot" in page.data

    # Missing checkbox confirmation should fail.
    fail = client.post(
        "/login",
        data={
            "email": "localcaptcha@example.com",
            "password": "StrongPass123!",
        },
        follow_redirects=True,
    )
    assert fail.status_code == 400
    assert b"CAPTCHA validation failed" in fail.data

    # Fetch a fresh token after failed attempt (token rotates per render).
    page = client.get("/login")

    # Extract hidden token and pass local clickable captcha confirmation.
    token_marker = b'name="local_captcha_token" value="'
    idx = page.data.find(token_marker)
    assert idx != -1
    start = idx + len(token_marker)
    end = page.data.find(b'"', start)
    token = page.data[start:end].decode("utf-8")

    success = client.post(
        "/login",
        data={
            "email": "localcaptcha@example.com",
            "password": "StrongPass123!",
            "local_captcha_token": token,
            "local_captcha_confirm": "yes",
        },
        follow_redirects=False,
    )

    assert success.status_code == 302
    assert "/dashboard" in success.headers["Location"]
