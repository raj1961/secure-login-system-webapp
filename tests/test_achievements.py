import io

from app.extensions import db
from app.models import Achievement, User
from app.security import hash_password


def login(client, email, password):
    return client.post(
        "/login",
        data={"email": email, "password": password},
        follow_redirects=False,
    )


def test_achievements_page_is_accessible(client):
    response = client.get("/achievements")
    assert response.status_code == 200
    assert b"Upload Proofs" in response.data
    assert b"Bug Bounty Reward" in response.data
    assert b"Hall of Fame" in response.data
    assert b"Certificate" in response.data


def test_achievement_upload_requires_login(client):
    response = client.post("/achievements/upload", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_upload_achievement_with_screenshot(client, app, tmp_path):
    with app.app_context():
        app.config["ACHIEVEMENTS_UPLOAD_DIR"] = str(tmp_path / "achievements")
        user = User(
            username="achiever_1",
            email="achiever@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

    login(client, "achiever@example.com", "StrongPass123!")
    response = client.post(
        "/achievements/upload",
        data={
            "title": "Critical Bug Hall of Fame",
            "category": "Hall of Fame",
            "description": "Received recognition for reporting a critical issue.",
            "screenshot": (io.BytesIO(b"fake image bytes"), "proof.png"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Achievement uploaded successfully" in response.data

    with app.app_context():
        item = Achievement.query.filter_by(title="Critical Bug Hall of Fame").first()
        assert item is not None
        saved_path = tmp_path / "achievements" / item.image_filename
        assert saved_path.exists()


def test_upload_rejects_invalid_file_extension(client, app, tmp_path):
    with app.app_context():
        app.config["ACHIEVEMENTS_UPLOAD_DIR"] = str(tmp_path / "achievements")
        user = User(
            username="achiever_2",
            email="achiever2@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

    login(client, "achiever2@example.com", "StrongPass123!")
    response = client.post(
        "/achievements/upload",
        data={
            "title": "Not Allowed File",
            "category": "Certificate",
            "screenshot": (io.BytesIO(b"binary"), "proof.exe"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Only PNG, JPG, JPEG, and WEBP files are allowed" in response.data

    with app.app_context():
        item = Achievement.query.filter_by(title="Not Allowed File").first()
        assert item is None


def test_owner_can_delete_uploaded_achievement(client, app, tmp_path):
    with app.app_context():
        app.config["ACHIEVEMENTS_UPLOAD_DIR"] = str(tmp_path / "achievements")
        user = User(
            username="achiever_3",
            email="achiever3@example.com",
            password_hash=hash_password("StrongPass123!"),
            role="user",
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

    login(client, "achiever3@example.com", "StrongPass123!")
    client.post(
        "/achievements/upload",
        data={
            "title": "Bounty Reward Win",
            "category": "Bug Bounty Reward",
            "screenshot": (io.BytesIO(b"fake image bytes"), "reward.jpg"),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    with app.app_context():
        item = Achievement.query.filter_by(title="Bounty Reward Win").first()
        assert item is not None
        item_id = item.id
        saved_path = tmp_path / "achievements" / item.image_filename
        assert saved_path.exists()

    response = client.post(f"/achievements/{item_id}/delete", follow_redirects=True)
    assert response.status_code == 200
    assert b"Achievement deleted" in response.data

    with app.app_context():
        deleted = db.session.get(Achievement, item_id)
        assert deleted is None
        assert not saved_path.exists()
