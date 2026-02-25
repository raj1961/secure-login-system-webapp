import os
from datetime import datetime, timedelta
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, session, url_for

from app.admin import admin_bp
from app.auth import auth_bp
from app.cli import register_commands
from app.config import config_by_name
from app.extensions import csrf, db, migrate
from app.main import main_bp
from app.security import get_current_user

load_dotenv()


def create_app(config_name: str | None = None, test_config: dict | None = None) -> Flask:
    project_root = Path(__file__).resolve().parent.parent
    app = Flask(
        __name__,
        instance_relative_config=True,
        template_folder=str(project_root / "templates"),
        static_folder=str(project_root / "static"),
        static_url_path="/static",
    )

    if test_config is not None:
        app.config.from_object(config_by_name["testing"])
        app.config.update(test_config)
    else:
        env_name = config_name or os.getenv("APP_ENV", "development")
        app.config.from_object(config_by_name.get(env_name, config_by_name["development"]))

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)

    register_commands(app)

    @app.before_request
    def enforce_idle_session_timeout():
        user_id = session.get("user_id")
        if not user_id:
            return None

        now = datetime.utcnow()
        last_activity_value = session.get("last_activity")
        if not last_activity_value:
            session["last_activity"] = now.isoformat()
            return None

        try:
            last_activity = datetime.fromisoformat(last_activity_value)
        except ValueError:
            session.clear()
            flash("Session state was invalid. Please log in again.", "warning")
            return redirect(url_for("auth.login"))

        idle_limit = timedelta(minutes=app.config["SESSION_IDLE_MINUTES"])
        if now - last_activity > idle_limit:
            session.clear()
            flash("Session expired due to inactivity. Please log in again.", "warning")
            return redirect(url_for("auth.login"))

        session["last_activity"] = now.isoformat()
        return None

    @app.context_processor
    def inject_template_globals():
        return {
            "current_user": get_current_user(),
            "turnstile_enabled": app.config["TURNSTILE_ENABLED"],
            "turnstile_site_key": app.config["TURNSTILE_SITE_KEY"],
        }

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("403.html"), 403

    @app.errorhandler(400)
    def bad_request(_error):
        return render_template("400.html"), 400

    return app
