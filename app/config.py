import os
from datetime import timedelta
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
INSTANCE_DIR = BASE_DIR / "instance"


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class BaseConfig:
    SECRET_KEY = os.getenv("SECRET_KEY", "change-this-secret")
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{(INSTANCE_DIR / 'app.db').as_posix()}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _as_bool(os.getenv("SESSION_COOKIE_SECURE"), False)

    SESSION_IDLE_MINUTES = int(os.getenv("SESSION_IDLE_MINUTES", "30"))
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=SESSION_IDLE_MINUTES)

    MAX_FAILED_ATTEMPTS = int(os.getenv("MAX_FAILED_ATTEMPTS", "5"))
    LOCKOUT_MINUTES = int(os.getenv("LOCKOUT_MINUTES", "15"))

    TURNSTILE_ENABLED = _as_bool(os.getenv("TURNSTILE_ENABLED"), True)
    TURNSTILE_SITE_KEY = os.getenv("TURNSTILE_SITE_KEY", "1x00000000000000000000AA")
    TURNSTILE_SECRET_KEY = os.getenv("TURNSTILE_SECRET_KEY", "1x0000000000000000000000000000000AA")
    TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    TURNSTILE_BYPASS = _as_bool(os.getenv("TURNSTILE_BYPASS"), False)
    PASSWORD_RESET_TOKEN_MINUTES = int(os.getenv("PASSWORD_RESET_TOKEN_MINUTES", "30"))

    MAX_ACHIEVEMENT_IMAGE_MB = int(os.getenv("MAX_ACHIEVEMENT_IMAGE_MB", "5"))
    MAX_CONTENT_LENGTH = MAX_ACHIEVEMENT_IMAGE_MB * 1024 * 1024
    ALLOWED_ACHIEVEMENT_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
    ACHIEVEMENTS_UPLOAD_DIR = str(BASE_DIR / "static" / "uploads" / "achievements")


class DevelopmentConfig(BaseConfig):
    DEBUG = True


class TestingConfig(BaseConfig):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    TURNSTILE_BYPASS = True


class ProductionConfig(BaseConfig):
    DEBUG = False
    SESSION_COOKIE_SECURE = True


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}
