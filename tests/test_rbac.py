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


def test_user_cannot_access_admin_page(client, seeded_users):
    login(client, "user@example.com", "UserPass123!")
    response = client.get("/admin/users", follow_redirects=False)
    assert response.status_code == 403


def test_admin_can_access_admin_page(client, seeded_users):
    login(client, "admin@example.com", "AdminPass123!")
    response = client.get("/admin/users", follow_redirects=False)
    assert response.status_code == 200
    assert b"Admin User Management" in response.data


def test_user_cannot_delete_user_via_admin_route(client, seeded_users):
    login(client, "user@example.com", "UserPass123!")
    response = client.post("/admin/users/1/delete", follow_redirects=False)
    assert response.status_code == 403


def test_admin_can_delete_non_admin_user(client, app):
    with app.app_context():
        admin = User(
            username="admin_delete_1",
            email="admin_delete_1@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="admin",
            is_active=True,
        )
        user = User(
            username="delete_me_1",
            email="delete_me_1@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="user",
            is_active=True,
        )
        db.session.add_all([admin, user])
        db.session.commit()
        user_id = user.id

    login(client, "admin_delete_1@example.com", "StrongPass123!")
    response = client.post(f"/admin/users/{user_id}/delete", follow_redirects=True)

    assert response.status_code == 200
    assert b"User account deleted" in response.data

    with app.app_context():
        deleted = db.session.get(User, user_id)
        assert deleted is None


def test_admin_cannot_delete_self(client, app):
    with app.app_context():
        admin = User(
            username="admin_self_1",
            email="admin_self_1@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="admin",
            is_active=True,
        )
        db.session.add(admin)
        db.session.commit()
        admin_id = admin.id

    login(client, "admin_self_1@example.com", "StrongPass123!")
    response = client.post(f"/admin/users/{admin_id}/delete", follow_redirects=True)

    assert response.status_code == 200
    assert b"You cannot delete your own account" in response.data

    with app.app_context():
        still_exists = db.session.get(User, admin_id)
        assert still_exists is not None


def test_admin_cannot_delete_another_admin(client, app):
    with app.app_context():
        admin_a = User(
            username="admin_a_del",
            email="admin_a_del@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="admin",
            is_active=True,
        )
        admin_b = User(
            username="admin_b_del",
            email="admin_b_del@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="admin",
            is_active=True,
        )
        db.session.add_all([admin_a, admin_b])
        db.session.commit()
        admin_b_id = admin_b.id

    login(client, "admin_a_del@example.com", "StrongPass123!")
    response = client.post(f"/admin/users/{admin_b_id}/delete", follow_redirects=True)

    assert response.status_code == 200
    assert b"Admin accounts cannot be deleted" in response.data

    with app.app_context():
        still_exists = db.session.get(User, admin_b_id)
        assert still_exists is not None
