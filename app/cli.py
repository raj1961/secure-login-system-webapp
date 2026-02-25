import os

import click
from flask.cli import with_appcontext

from app.extensions import db
from app.models import User
from app.security import hash_password, validate_email, validate_password_strength, validate_username


@click.command("init-db")
@with_appcontext
def init_db_command() -> None:
    db.create_all()
    click.echo("Database tables created.")


@click.command("seed-admin")
@click.option("--username", default=lambda: os.getenv("SEED_ADMIN_USERNAME", "admin"), show_default=True)
@click.option("--email", default=lambda: os.getenv("SEED_ADMIN_EMAIL", "admin@example.com"), show_default=True)
@click.option("--password", default=lambda: os.getenv("SEED_ADMIN_PASSWORD", ""), show_default=False)
@with_appcontext
def seed_admin_command(username: str, email: str, password: str) -> None:
    errors = []
    errors.extend(validate_username(username))
    errors.extend(validate_email(email))

    if not password:
        errors.append("Admin password is required. Set SEED_ADMIN_PASSWORD or pass --password.")
    else:
        errors.extend(validate_password_strength(password))

    if errors:
        raise click.ClickException(" | ".join(errors))

    email = email.lower()
    existing_user = User.query.filter((User.email == email) | (User.username == username)).first()
    if existing_user:
        existing_user.role = "admin"
        existing_user.password_hash = hash_password(password)
        existing_user.is_active = True
        existing_user.failed_attempts = 0
        existing_user.lockout_until = None
        db.session.commit()
        click.echo(f"Updated existing user '{existing_user.username}' as admin.")
        return

    admin_user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role="admin",
        is_active=True,
    )
    db.session.add(admin_user)
    db.session.commit()
    click.echo(f"Admin user '{username}' created.")


def register_commands(app) -> None:
    app.cli.add_command(init_db_command)
    app.cli.add_command(seed_admin_command)
