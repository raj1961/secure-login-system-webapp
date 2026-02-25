from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from app.extensions import db
from app.models import User
from app.security import get_current_user, record_auth_event, role_required


admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/users", methods=["GET"])
@role_required("admin")
def users():
    all_users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin_users.html", users=all_users)


@admin_bp.route("/users/<int:user_id>/role", methods=["POST"])
@role_required("admin")
def change_role(user_id: int):
    actor = get_current_user()
    target_user = db.session.get(User, user_id)
    if not target_user:
        flash("Target user not found.", "danger")
        return redirect(url_for("admin.users"))

    new_role = request.form.get("role", "user").strip().lower()
    if new_role not in {"admin", "user", "member"}:
        flash("Invalid role provided.", "danger")
        return redirect(url_for("admin.users"))

    if actor and actor.id == target_user.id and new_role != "admin":
        flash("You cannot remove your own admin role.", "warning")
        return redirect(url_for("admin.users"))

    target_user.role = new_role
    db.session.commit()
    record_auth_event(target_user.email, f"ROLE_CHANGED_TO_{new_role.upper()}")
    flash("User role updated.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/disable", methods=["POST"])
@role_required("admin")
def disable_user(user_id: int):
    actor = get_current_user()
    target_user = db.session.get(User, user_id)
    if not target_user:
        flash("Target user not found.", "danger")
        return redirect(url_for("admin.users"))

    if actor and actor.id == target_user.id:
        flash("You cannot disable your own account.", "warning")
        return redirect(url_for("admin.users"))

    target_user.is_active = False
    target_user.failed_attempts = 0
    target_user.lockout_until = None
    db.session.commit()

    if session.get("user_id") == target_user.id:
        session.clear()

    record_auth_event(target_user.email, "ACCOUNT_DISABLED")
    flash("User account disabled.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@role_required("admin")
def delete_user(user_id: int):
    actor = get_current_user()
    target_user = db.session.get(User, user_id)
    if not target_user:
        flash("Target user not found.", "danger")
        return redirect(url_for("admin.users"))

    if actor and actor.id == target_user.id:
        flash("You cannot delete your own account.", "warning")
        return redirect(url_for("admin.users"))

    if target_user.role == "admin":
        flash("Admin accounts cannot be deleted from this action.", "warning")
        return redirect(url_for("admin.users"))

    target_email = target_user.email
    db.session.delete(target_user)
    db.session.commit()

    record_auth_event(target_email, "ACCOUNT_DELETED_BY_ADMIN")
    flash("User account deleted.", "success")
    return redirect(url_for("admin.users"))
