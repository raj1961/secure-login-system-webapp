from pathlib import Path
from uuid import uuid4

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from sqlalchemy import or_
from werkzeug.utils import secure_filename

from app.extensions import db
from app.models import Achievement, TeamMember, User
from app.security import (
    get_current_user,
    hash_password,
    login_required,
    record_auth_event,
    validate_password_strength,
    verify_password,
)


main_bp = Blueprint("main", __name__)
ACHIEVEMENT_CATEGORIES = ("Bug Bounty Reward", "Hall of Fame", "Certificate")


def _is_allowed_achievement_file(filename: str) -> bool:
    if "." not in filename:
        return False
    extension = filename.rsplit(".", 1)[1].lower()
    allowed = current_app.config.get("ALLOWED_ACHIEVEMENT_EXTENSIONS", set())
    return extension in allowed


def _achievement_upload_dir() -> Path:
    upload_dir = Path(current_app.config["ACHIEVEMENTS_UPLOAD_DIR"])
    if not upload_dir.is_absolute():
        upload_dir = Path(current_app.root_path).parent / upload_dir
    upload_dir.mkdir(parents=True, exist_ok=True)
    return upload_dir


@main_bp.route("/")
def index():
    return render_template("home.html", user=get_current_user())


@main_bp.route("/about")
def about():
    return render_template("about.html", user=get_current_user())


@main_bp.route("/achievements")
def achievements():
    records = Achievement.query.order_by(Achievement.created_at.desc()).all()
    return render_template(
        "achievements.html",
        user=get_current_user(),
        achievements=records,
        achievement_categories=ACHIEVEMENT_CATEGORIES,
    )


@main_bp.route("/achievements/upload", methods=["POST"])
@login_required
def upload_achievement():
    user = get_current_user()
    title = request.form.get("title", "").strip()
    category = request.form.get("category", "").strip()
    description = request.form.get("description", "").strip()
    screenshot = request.files.get("screenshot")

    if not title:
        flash("Achievement title is required.", "danger")
        return redirect(url_for("main.achievements"))
    if len(title) > 120:
        flash("Achievement title must be at most 120 characters.", "danger")
        return redirect(url_for("main.achievements"))
    if category not in ACHIEVEMENT_CATEGORIES:
        flash("Please select a valid achievement category.", "danger")
        return redirect(url_for("main.achievements"))
    if description and len(description) > 300:
        flash("Description must be at most 300 characters.", "danger")
        return redirect(url_for("main.achievements"))
    if not screenshot or not screenshot.filename:
        flash("Screenshot file is required.", "danger")
        return redirect(url_for("main.achievements"))
    if not _is_allowed_achievement_file(screenshot.filename):
        flash("Only PNG, JPG, JPEG, and WEBP files are allowed.", "danger")
        return redirect(url_for("main.achievements"))

    sanitized_name = secure_filename(screenshot.filename)
    extension = sanitized_name.rsplit(".", 1)[1].lower()
    generated_filename = f"{uuid4().hex}.{extension}"

    save_path = _achievement_upload_dir() / generated_filename
    screenshot.save(save_path)

    achievement = Achievement(
        owner_id=user.id,
        title=title,
        category=category,
        description=description or None,
        image_filename=generated_filename,
    )
    db.session.add(achievement)
    db.session.commit()
    flash("Achievement uploaded successfully.", "success")
    return redirect(url_for("main.achievements"))


@main_bp.route("/achievements/<int:achievement_id>/delete", methods=["POST"])
@login_required
def delete_achievement(achievement_id: int):
    user = get_current_user()
    achievement = db.session.get(Achievement, achievement_id)
    if not achievement:
        flash("Achievement not found.", "danger")
        return redirect(url_for("main.achievements"))

    if achievement.owner_id != user.id and user.role != "admin":
        flash("You are not allowed to delete this achievement.", "danger")
        return redirect(url_for("main.achievements"))

    filename = achievement.image_filename
    db.session.delete(achievement)
    db.session.commit()

    file_path = _achievement_upload_dir() / filename
    if file_path.exists():
        file_path.unlink()

    flash("Achievement deleted.", "success")
    return redirect(url_for("main.achievements"))


@main_bp.route("/portal")
def portal():
    if not session.get("user_id"):
        return redirect(url_for("auth.login"))

    role = session.get("role", "user")
    if role == "admin":
        return redirect(url_for("admin.users"))
    return redirect(url_for("main.dashboard"))


@main_bp.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()
    search_query = request.args.get("q", "").strip()

    members_query = TeamMember.query.filter(TeamMember.owner_id == user.id)
    if search_query:
        pattern = f"%{search_query}%"
        members_query = members_query.filter(
            or_(
                TeamMember.name.ilike(pattern),
                TeamMember.email.ilike(pattern),
                TeamMember.role.ilike(pattern),
            )
        )

    members = members_query.order_by(TeamMember.created_at.desc()).all()
    return render_template(
        "dashboard.html",
        user=user,
        members=members,
        search_query=search_query,
    )


@main_bp.route("/dashboard/settings")
@login_required
def settings():
    return render_template("settings.html", user=get_current_user())


@main_bp.route("/dashboard/settings/change-password", methods=["POST"])
@login_required
def change_password():
    user = get_current_user()
    if not user:
        return redirect(url_for("auth.login"))

    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not verify_password(current_password, user.password_hash):
        flash("Current password is incorrect.", "danger")
        return redirect(url_for("main.settings"))

    if new_password != confirm_password:
        flash("New password and confirm password do not match.", "danger")
        return redirect(url_for("main.settings"))

    if current_password == new_password:
        flash("New password must be different from current password.", "danger")
        return redirect(url_for("main.settings"))

    errors = validate_password_strength(new_password)
    if errors:
        for error in errors:
            flash(error, "danger")
        return redirect(url_for("main.settings"))

    user.password_hash = hash_password(new_password)
    user.failed_attempts = 0
    user.lockout_until = None
    db.session.commit()

    record_auth_event(user.email, "PASSWORD_CHANGED")
    flash("Password changed successfully.", "success")
    return redirect(url_for("main.settings"))


@main_bp.route("/dashboard/team-members", methods=["POST"])
@login_required
def add_team_member():
    user = get_current_user()
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    role = request.form.get("role", "").strip() or "Member"
    allowed_team_roles = {"Member", "Admin"}

    if not name:
        flash("Team member name is required.", "danger")
        return redirect(url_for("main.dashboard"))
    if len(name) > 100:
        flash("Team member name is too long.", "danger")
        return redirect(url_for("main.dashboard"))
    if not email or "@" not in email:
        flash("Valid team member email is required.", "danger")
        return redirect(url_for("main.dashboard"))
    if role not in allowed_team_roles:
        flash("Team member role must be either Member or Admin.", "danger")
        return redirect(url_for("main.dashboard"))

    existing = TeamMember.query.filter_by(owner_id=user.id, email=email).first()
    if existing:
        flash("This team member email already exists in your dashboard.", "warning")
        return redirect(url_for("main.dashboard"))

    member = TeamMember(
        owner_id=user.id,
        name=name,
        email=email,
        role=role,
    )
    db.session.add(member)
    db.session.commit()
    flash("Team member added successfully.", "success")
    return redirect(url_for("main.dashboard"))


@main_bp.route("/dashboard/team-members/<int:member_id>/delete", methods=["POST"])
@login_required
def delete_team_member(member_id: int):
    user = get_current_user()
    member = TeamMember.query.filter_by(id=member_id, owner_id=user.id).first()
    if not member:
        flash("Team member not found.", "danger")
        return redirect(url_for("main.dashboard"))

    db.session.delete(member)
    db.session.commit()
    flash("Team member deleted.", "success")
    return redirect(url_for("main.dashboard"))


@main_bp.route("/dashboard/settings/delete-account", methods=["POST"])
@login_required
def delete_account():
    user = get_current_user()
    if not user:
        return redirect(url_for("auth.login"))

    current_password = request.form.get("current_password", "")
    confirm_text = request.form.get("confirm_text", "")

    if not verify_password(current_password, user.password_hash):
        flash("Current password is incorrect.", "danger")
        return redirect(url_for("main.settings"))

    if confirm_text != "CONFIRM":
        flash("Type CONFIRM exactly to delete your account.", "danger")
        return redirect(url_for("main.settings"))

    if user.role == "admin":
        active_admin_count = User.query.filter_by(role="admin", is_active=True).count()
        if active_admin_count <= 1:
            flash("Cannot delete account. At least one active admin must remain.", "danger")
            return redirect(url_for("main.settings"))

    user.is_active = False
    user.failed_attempts = 0
    user.lockout_until = None
    user.reset_token_hash = None
    user.reset_token_expires_at = None
    db.session.commit()

    record_auth_event(user.email, "ACCOUNT_SELF_DELETED")
    session.clear()
    flash("Your account has been deleted successfully.", "success")
    return redirect(url_for("auth.login"))
