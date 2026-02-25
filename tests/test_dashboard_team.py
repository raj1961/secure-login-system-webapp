from app.extensions import db
from app.models import TeamMember, User
from app.security import hash_password


def login(client, email, password):
    return client.post(
        "/login",
        data={"email": email, "password": password},
        follow_redirects=False,
    )


def test_home_page_accessible_without_login(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"Secure Login System" in response.data
    assert b"data-theme-quick-toggle" in response.data


def test_about_page_accessible_without_login(client):
    response = client.get("/about")
    assert response.status_code == 200
    assert b"About Us" in response.data
    assert b"Raja Ansari" in response.data


def test_add_show_delete_team_member(client, app):
    with app.app_context():
        user = User(
            username="team_owner",
            email="teamowner@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

    login(client, "teamowner@example.com", "StrongPass123!")

    add_response = client.post(
        "/dashboard/team-members",
        data={"name": "Ravi Kumar", "email": "ravi@example.com", "role": "Member"},
        follow_redirects=True,
    )
    assert add_response.status_code == 200
    assert b"Team member added successfully" in add_response.data
    assert b"ravi@example.com" in add_response.data

    with app.app_context():
        member = TeamMember.query.filter_by(email="ravi@example.com").first()
        assert member is not None
        member_id = member.id

    delete_response = client.post(
        f"/dashboard/team-members/{member_id}/delete",
        follow_redirects=True,
    )
    assert delete_response.status_code == 200
    assert b"Team member deleted" in delete_response.data

    with app.app_context():
        member = TeamMember.query.filter_by(email="ravi@example.com").first()
        assert member is None


def test_user_cannot_delete_other_users_team_member(client, app):
    with app.app_context():
        owner = User(
            username="owner_1",
            email="owner1@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="user",
            is_active=True,
        )
        attacker = User(
            username="attacker_1",
            email="attacker1@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="user",
            is_active=True,
        )
        db.session.add_all([owner, attacker])
        db.session.commit()

        member = TeamMember(owner_id=owner.id, name="Secret User", email="secret@example.com", role="Analyst")
        db.session.add(member)
        db.session.commit()
        member_id = member.id

    login(client, "attacker1@example.com", "StrongPass123!")
    response = client.post(f"/dashboard/team-members/{member_id}/delete", follow_redirects=True)

    assert response.status_code == 200
    assert b"Team member not found" in response.data

    with app.app_context():
        member = db.session.get(TeamMember, member_id)
        assert member is not None


def test_dashboard_search_filters_team_members(client, app):
    with app.app_context():
        user = User(
            username="search_owner",
            email="searchowner@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

        db.session.add_all(
            [
                TeamMember(owner_id=user.id, name="Ravi Kumar", email="ravi@example.com", role="Member"),
                TeamMember(owner_id=user.id, name="Anita Sharma", email="anita@example.com", role="Admin"),
            ]
        )
        db.session.commit()

    login(client, "searchowner@example.com", "StrongPass123!")
    response = client.get("/dashboard?q=ravi", follow_redirects=True)

    assert response.status_code == 200
    assert b"ravi@example.com" in response.data
    assert b"anita@example.com" not in response.data


def test_team_member_role_validation_allows_only_member_or_admin(client, app):
    with app.app_context():
        user = User(
            username="role_owner",
            email="roleowner@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

    login(client, "roleowner@example.com", "StrongPass123!")
    response = client.post(
        "/dashboard/team-members",
        data={"name": "Bad Role User", "email": "badrole@example.com", "role": "SuperAdmin"},
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"either Member or Admin" in response.data

    with app.app_context():
        member = TeamMember.query.filter_by(email="badrole@example.com").first()
        assert member is None
