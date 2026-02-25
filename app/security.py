import hashlib
import re
from functools import wraps

import requests
from flask import abort, current_app, redirect, request, session, url_for
from passlib.hash import argon2

from app.extensions import db
from app.models import AuthLog, User


USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,30}$")
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PASSWORD_POLICY = {
    "min_length": 12,
    "uppercase": re.compile(r"[A-Z]"),
    "lowercase": re.compile(r"[a-z]"),
    "digit": re.compile(r"\d"),
    "special": re.compile(r"[^A-Za-z0-9]"),
}


def validate_username(username: str) -> list[str]:
    errors: list[str] = []
    if not username:
        return ["Username is required."]
    if not USERNAME_PATTERN.fullmatch(username):
        errors.append("Username must be 3-30 characters and use letters, numbers, or underscores.")
    return errors


def validate_email(email: str) -> list[str]:
    errors: list[str] = []
    if not email:
        return ["Email is required."]
    if not EMAIL_PATTERN.fullmatch(email):
        errors.append("Please provide a valid email address.")
    return errors


def validate_password_strength(password: str) -> list[str]:
    errors: list[str] = []
    if len(password) < PASSWORD_POLICY["min_length"]:
        errors.append("Password must be at least 12 characters long.")
    if not PASSWORD_POLICY["uppercase"].search(password):
        errors.append("Password must include at least one uppercase letter.")
    if not PASSWORD_POLICY["lowercase"].search(password):
        errors.append("Password must include at least one lowercase letter.")
    if not PASSWORD_POLICY["digit"].search(password):
        errors.append("Password must include at least one number.")
    if not PASSWORD_POLICY["special"].search(password):
        errors.append("Password must include at least one special character.")
    return errors


def hash_password(password: str) -> str:
    return argon2.using(type="ID").hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return argon2.verify(password, password_hash)
    except Exception:
        return False


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_turnstile_token(token: str, remote_ip: str | None = None) -> bool:
    if current_app.config["TURNSTILE_BYPASS"]:
        return True

    if not current_app.config["TURNSTILE_ENABLED"]:
        return False

    if not token:
        return False

    secret_key = current_app.config.get("TURNSTILE_SECRET_KEY", "")
    if not secret_key:
        return False

    payload = {
        "secret": secret_key,
        "response": token,
    }
    if remote_ip:
        payload["remoteip"] = remote_ip

    try:
        response = requests.post(
            current_app.config["TURNSTILE_VERIFY_URL"],
            data=payload,
            timeout=5,
        )
        response.raise_for_status()
        data = response.json()
        return bool(data.get("success", False))
    except requests.RequestException:
        return False


def get_current_user() -> User | None:
    user_id = session.get("user_id")
    if not user_id:
        return None
    user = db.session.get(User, user_id)
    if not user or not user.is_active:
        session.clear()
        return None
    return user


def login_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if not get_current_user():
            return redirect(url_for("auth.login"))
        return view_func(*args, **kwargs)

    return wrapped_view


def role_required(expected_role: str):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(*args, **kwargs):
            user = get_current_user()
            if not user:
                return redirect(url_for("auth.login"))
            if user.role != expected_role:
                abort(403)
            return view_func(*args, **kwargs)

        return wrapped_view

    return decorator


def record_auth_event(email_attempted: str, status: str) -> None:
    log_entry = AuthLog(
        email_attempted=email_attempted or "",
        ip_address=request.headers.get("X-Forwarded-For", request.remote_addr),
        user_agent=request.user_agent.string[:512] if request.user_agent else None,
        status=status,
    )
    db.session.add(log_entry)
    db.session.commit()
