from app.extensions import db
from app.models import User
from app.security import hash_password


def register(client, username, email, password, role="user"):
    return client.post(
        "/register",
        data={
            "username": username,
            "email": email,
            "password": password,
            "role": role,
        },
        follow_redirects=True,
    )


def login(client, email, password):
    return client.post(
        "/login",
        data={
            "email": email,
            "password": password,
        },
        follow_redirects=True,
    )


def test_registration_success(client, app):
    response = register(client, "alice_01", "alice@example.com", "StrongPass123!")
    assert response.status_code == 200
    assert b"Registration successful" in response.data

    with app.app_context():
        user = User.query.filter_by(email="alice@example.com").first()
        assert user is not None
        assert user.role == "user"


def test_registration_duplicate_email(client):
    register(client, "first_user", "dup@example.com", "StrongPass123!")
    response = register(client, "second_user", "dup@example.com", "StrongPass123!")

    assert response.status_code == 400
    assert b"Email is already registered" in response.data


def test_registration_weak_password(client):
    response = register(client, "bob_01", "bob@example.com", "weak")
    assert response.status_code == 400
    assert b"Password must be at least 12 characters long" in response.data


def test_registration_tampered_role_still_creates_user(client, app):
    response = register(client, "mallory_01", "mallory@example.com", "StrongPass123!", role="admin")
    assert response.status_code == 200

    with app.app_context():
        user = User.query.filter_by(email="mallory@example.com").first()
        assert user is not None
        assert user.role == "user"


def test_registration_member_role_creates_member_user(client, app):
    response = register(client, "member_01", "member01@example.com", "StrongPass123!", role="member")
    assert response.status_code == 200

    with app.app_context():
        user = User.query.filter_by(email="member01@example.com").first()
        assert user is not None
        assert user.role == "member"


def test_login_valid_credentials(client, app):
    with app.app_context():
        user = User(
            username="valid_user",
            email="valid@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

    response = client.post(
        "/login",
        data={"email": "valid@example.com", "password": "StrongPass123!"},
        follow_redirects=False,
    )

    assert response.status_code == 302
    assert "/dashboard" in response.headers["Location"]


def test_login_invalid_password(client, app):
    with app.app_context():
        user = User(
            username="wrong_pwd_user",
            email="wrongpwd@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

    response = login(client, "wrongpwd@example.com", "WrongPass123!")
    assert response.status_code == 401
    assert b"Invalid email or password" in response.data


def test_login_non_existent_user(client):
    response = login(client, "nobody@example.com", "SomePass123!")
    assert response.status_code == 401
    assert b"Invalid email or password" in response.data


def test_login_lockout_after_five_failures(client, app):
    with app.app_context():
        user = User(
            username="lock_user",
            email="lock@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

    for _ in range(4):
        login(client, "lock@example.com", "WrongPass123!")

    locked_response = login(client, "lock@example.com", "WrongPass123!")
    assert locked_response.status_code == 423
    assert b"Account temporarily locked" in locked_response.data

    blocked_response = login(client, "lock@example.com", "StrongPass123!")
    assert blocked_response.status_code == 423
