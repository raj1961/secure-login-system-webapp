import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from app.extensions import db
from app.models import User
from app.security import hash_password


@pytest.fixture
def app():
    app = create_app(
        test_config={
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "WTF_CSRF_ENABLED": False,
            "TURNSTILE_BYPASS": True,
            "TURNSTILE_ENABLED": False,
            "SESSION_COOKIE_SECURE": False,
        }
    )

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def seeded_users(app):
    with app.app_context():
        admin = User(
            username="admin_user",
            email="admin@example.com",
            password_hash=hash_password("AdminPass123!"),
            role="admin",
            is_active=True,
        )
        user = User(
            username="normal_user",
            email="user@example.com",
            password_hash=hash_password("UserPass123!"),
            role="user",
            is_active=True,
        )
        db.session.add_all([admin, user])
        db.session.commit()
        return {"admin_id": admin.id, "user_id": user.id}
