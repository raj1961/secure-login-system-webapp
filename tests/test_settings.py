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


def test_settings_requires_authentication(client):
    response = client.get("/dashboard/settings", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_authenticated_user_can_open_settings(client, app):
    with app.app_context():
        user = User(
            username="settings_user",
            email="settings@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

    login(client, "settings@example.com", "StrongPass123!")
    response = client.get("/dashboard/settings", follow_redirects=False)
    assert response.status_code == 200
    assert b"Settings" in response.data
    assert b"Change Password" in response.data
    assert b"Delete Account" in response.data


def test_change_password_wrong_current_password_fails(client, app):
    with app.app_context():
        user = User(
            username="cp_user_1",
            email="cp1@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

    login(client, "cp1@example.com", "StrongPass123!")
    response = client.post(
        "/dashboard/settings/change-password",
        data={
            "current_password": "WrongPass123!",
            "new_password": "NewStrongPass123!",
            "confirm_password": "NewStrongPass123!",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Current password is incorrect" in response.data


def test_change_password_mismatch_fails(client, app):
    with app.app_context():
        user = User(
            username="cp_user_2",
            email="cp2@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

    login(client, "cp2@example.com", "StrongPass123!")
    response = client.post(
        "/dashboard/settings/change-password",
        data={
            "current_password": "StrongPass123!",
            "new_password": "NewStrongPass123!",
            "confirm_password": "MismatchPass123!",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"do not match" in response.data


def test_change_password_success_updates_login_password(client, app):
    with app.app_context():
        user = User(
            username="cp_user_3",
            email="cp3@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

    login(client, "cp3@example.com", "StrongPass123!")
    response = client.post(
        "/dashboard/settings/change-password",
        data={
            "current_password": "StrongPass123!",
            "new_password": "NewStrongPass123!",
            "confirm_password": "NewStrongPass123!",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Password changed successfully" in response.data

    client.post("/logout", follow_redirects=False)
    old_login = login(client, "cp3@example.com", "StrongPass123!")
    assert old_login.status_code == 401

    new_login = login(client, "cp3@example.com", "NewStrongPass123!")
    assert new_login.status_code == 302
    assert "/dashboard" in new_login.headers["Location"]


def test_delete_account_wrong_password_fails(client, app):
    with app.app_context():
        user = User(
            username="del_user_1",
            email="del1@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

    login(client, "del1@example.com", "StrongPass123!")
    response = client.post(
        "/dashboard/settings/delete-account",
        data={"current_password": "WrongPass123!", "confirm_text": "CONFIRM"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Current password is incorrect" in response.data

    with app.app_context():
        user = User.query.filter_by(email="del1@example.com").first()
        assert user is not None
        assert user.is_active is True


def test_delete_account_wrong_confirm_text_fails(client, app):
    with app.app_context():
        user = User(
            username="del_user_2",
            email="del2@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

    login(client, "del2@example.com", "StrongPass123!")
    response = client.post(
        "/dashboard/settings/delete-account",
        data={"current_password": "StrongPass123!", "confirm_text": "confirm"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Type CONFIRM exactly" in response.data

    with app.app_context():
        user = User.query.filter_by(email="del2@example.com").first()
        assert user is not None
        assert user.is_active is True


def test_user_delete_account_success_soft_delete(client, app):
    with app.app_context():
        user = User(
            username="del_user_3",
            email="del3@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="user",
            is_active=True,
            failed_attempts=2,
        )
        db.session.add(user)
        db.session.commit()

    login(client, "del3@example.com", "StrongPass123!")
    response = client.post(
        "/dashboard/settings/delete-account",
        data={"current_password": "StrongPass123!", "confirm_text": "CONFIRM"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Your account has been deleted successfully" in response.data

    with app.app_context():
        user = User.query.filter_by(email="del3@example.com").first()
        assert user is not None
        assert user.is_active is False
        assert user.failed_attempts == 0

    dashboard_response = client.get("/dashboard", follow_redirects=False)
    assert dashboard_response.status_code == 302
    assert "/login" in dashboard_response.headers["Location"]


def test_last_admin_cannot_self_delete(client, app):
    with app.app_context():
        admin = User(
            username="only_admin",
            email="onlyadmin@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="admin",
            is_active=True,
        )
        db.session.add(admin)
        db.session.commit()

    login(client, "onlyadmin@example.com", "StrongPass123!")
    response = client.post(
        "/dashboard/settings/delete-account",
        data={"current_password": "StrongPass123!", "confirm_text": "CONFIRM"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"At least one active admin must remain" in response.data

    with app.app_context():
        admin = User.query.filter_by(email="onlyadmin@example.com").first()
        assert admin is not None
        assert admin.is_active is True


def test_admin_can_delete_when_other_admin_exists(client, app):
    with app.app_context():
        admin_1 = User(
            username="admin_a",
            email="admina@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="admin",
            is_active=True,
        )
        admin_2 = User(
            username="admin_b",
            email="adminb@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="admin",
            is_active=True,
        )
        db.session.add_all([admin_1, admin_2])
        db.session.commit()

    login(client, "admina@example.com", "StrongPass123!")
    response = client.post(
        "/dashboard/settings/delete-account",
        data={"current_password": "StrongPass123!", "confirm_text": "CONFIRM"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Your account has been deleted successfully" in response.data

    with app.app_context():
        admin_1 = User.query.filter_by(email="admina@example.com").first()
        admin_2 = User.query.filter_by(email="adminb@example.com").first()
        assert admin_1 is not None and admin_1.is_active is False
        assert admin_2 is not None and admin_2.is_active is True
