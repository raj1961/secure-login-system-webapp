import secrets
from datetime import datetime, timedelta

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from sqlalchemy import and_, or_

from app.extensions import db
from app.models import User
from app.security import (
    hash_password,
    hash_token,
    login_required,
    record_auth_event,
    validate_email,
    validate_password_strength,
    validate_username,
    verify_password,
    verify_turnstile_token,
)


auth_bp = Blueprint("auth", __name__)


def _should_use_turnstile() -> bool:
    return bool(
        current_app.config.get("TURNSTILE_ENABLED")
        and current_app.config.get("TURNSTILE_SITE_KEY")
        and current_app.config.get("TURNSTILE_SECRET_KEY")
        and not current_app.config.get("TURNSTILE_BYPASS")
    )


def _issue_local_login_captcha_token() -> str:
    token = secrets.token_urlsafe(18)
    session["local_login_captcha_token"] = token
    return token


def _render_login(form_data: dict[str, str], status_code: int = 200):
    use_turnstile = _should_use_turnstile()
    local_captcha_token = None if use_turnstile else _issue_local_login_captcha_token()
    return (
        render_template(
            "login.html",
            form_data=form_data,
            use_turnstile=use_turnstile,
            local_captcha_token=local_captcha_token,
        ),
        status_code,
    )


def _validate_login_captcha() -> bool:
    if current_app.config.get("TESTING") and current_app.config.get("TURNSTILE_BYPASS"):
        return True

    if _should_use_turnstile():
        captcha_token = request.form.get("cf-turnstile-response", "")
        return verify_turnstile_token(captcha_token, request.remote_addr)

    expected_token = session.get("local_login_captcha_token", "")
    provided_token = request.form.get("local_captcha_token", "")
    confirmed = request.form.get("local_captcha_confirm", "") == "yes"

    return bool(confirmed and expected_token and provided_token and secrets.compare_digest(expected_token, provided_token))


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("main.portal"))

    form_data = {"username": "", "email": "", "role": "user"}

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role_from_form = request.form.get("role", "user").strip().lower()

        form_data = {"username": username, "email": email, "role": role_from_form}
        selected_role = role_from_form if role_from_form in {"user", "member"} else "user"

        errors: list[str] = []
        errors.extend(validate_username(username))
        errors.extend(validate_email(email))
        errors.extend(validate_password_strength(password))

        existing_user = User.query.filter(or_(User.username == username, User.email == email)).first()
        if existing_user:
            if existing_user.username == username:
                errors.append("Username is already taken.")
            if existing_user.email == email:
                errors.append("Email is already registered.")

        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template("register.html", form_data=form_data), 400

        user = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            role=selected_role,
            is_active=True,
        )
        db.session.add(user)
        db.session.commit()

        record_auth_event(email, "REGISTER_SUCCESS")
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html", form_data=form_data)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("main.portal"))

    form_data = {"email": ""}

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        generic_error = "Invalid email or password."

        form_data["email"] = email

        if not _validate_login_captcha():
            record_auth_event(email, "CAPTCHA_FAILED")
            flash("CAPTCHA validation failed. Please complete CAPTCHA and try again.", "danger")
            return _render_login(form_data, 400)

        user = User.query.filter_by(email=email).first()
        now = datetime.utcnow()

        if user and not user.is_active:
            record_auth_event(email, "INACTIVE_USER")
            flash("Invalid email or password.", "danger")
            return _render_login(form_data, 401)

        if user and user.is_locked(now):
            record_auth_event(email, "ACCOUNT_LOCKED")
            flash("Account temporarily locked. Please try again later.", "danger")
            return _render_login(form_data, 423)

        if not user or not verify_password(password, user.password_hash):
            if user:
                user.failed_attempts += 1
                if user.failed_attempts >= current_app.config["MAX_FAILED_ATTEMPTS"]:
                    user.lockout_until = now + timedelta(minutes=current_app.config["LOCKOUT_MINUTES"])
                    user.failed_attempts = 0
                    db.session.commit()
                    record_auth_event(email, "LOCKOUT_TRIGGERED")
                    flash("Account temporarily locked. Please try again later.", "danger")
                    return _render_login(form_data, 423)
                db.session.commit()

            record_auth_event(email, "LOGIN_FAILED")
            flash(generic_error, "danger")
            return _render_login(form_data, 401)

        user.failed_attempts = 0
        user.lockout_until = None
        db.session.commit()

        now_iso = now.isoformat()
        session.clear()
        session.permanent = True
        session["user_id"] = user.id
        session["role"] = user.role
        session["login_time"] = now_iso
        session["last_activity"] = now_iso

        record_auth_event(email, "LOGIN_SUCCESS")
        flash("Welcome back.", "success")

        if user.role == "admin":
            return redirect(url_for("admin.users"))
        return redirect(url_for("main.dashboard"))

    return _render_login(form_data)


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if session.get("user_id"):
        return redirect(url_for("main.portal"))

    form_data = {"email": ""}

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        captcha_token = request.form.get("cf-turnstile-response", "")
        form_data["email"] = email

        if not verify_turnstile_token(captcha_token, request.remote_addr):
            flash("CAPTCHA validation failed. Please complete CAPTCHA and try again.", "danger")
            return render_template("forgot_password.html", form_data=form_data), 400

        errors = validate_email(email)
        if errors:
            flash("Please provide a valid email address.", "danger")
            return render_template("forgot_password.html", form_data=form_data), 400

        user = User.query.filter_by(email=email, is_active=True).first()
        if user:
            raw_token = secrets.token_urlsafe(32)
            user.reset_token_hash = hash_token(raw_token)
            user.reset_token_expires_at = datetime.utcnow() + timedelta(
                minutes=current_app.config["PASSWORD_RESET_TOKEN_MINUTES"]
            )
            db.session.commit()
            record_auth_event(email, "PASSWORD_RESET_REQUESTED")

            # For internship/demo environments, surface reset link directly.
            reset_link = url_for("auth.reset_password", token=raw_token, _external=True)
            flash(f"Password reset link: {reset_link}", "warning")
        else:
            record_auth_event(email, "PASSWORD_RESET_UNKNOWN_EMAIL")

        flash("If this email exists, password reset instructions are ready.", "success")
        return redirect(url_for("auth.forgot_password"))

    return render_template("forgot_password.html", form_data=form_data)


@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token: str):
    if session.get("user_id"):
        return redirect(url_for("main.portal"))

    now = datetime.utcnow()
    user = User.query.filter(
        and_(
            User.reset_token_hash == hash_token(token),
            User.reset_token_expires_at.is_not(None),
            User.reset_token_expires_at > now,
            User.is_active.is_(True),
        )
    ).first()

    if not user:
        flash("Reset link is invalid or expired. Please request a new one.", "danger")
        return redirect(url_for("auth.forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        errors: list[str] = []
        errors.extend(validate_password_strength(password))
        if password != confirm_password:
            errors.append("Password and confirm password do not match.")

        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template("reset_password.html")

        user.password_hash = hash_password(password)
        user.failed_attempts = 0
        user.lockout_until = None
        user.reset_token_hash = None
        user.reset_token_expires_at = None
        db.session.commit()

        record_auth_event(user.email, "PASSWORD_RESET_COMPLETED")
        flash("Password updated successfully. Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("reset_password.html")


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    email = ""
    user = db.session.get(User, session.get("user_id"))
    if user:
        email = user.email

    session.clear()
    record_auth_event(email, "LOGOUT")
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))
