from datetime import datetime

from app.extensions import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False, index=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user")

    failed_attempts = db.Column(db.Integer, nullable=False, default=0)
    lockout_until = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    reset_token_hash = db.Column(db.String(128), nullable=True, index=True)
    reset_token_expires_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )
    team_members = db.relationship(
        "TeamMember",
        backref="owner",
        lazy=True,
        cascade="all, delete-orphan",
    )
    achievements = db.relationship(
        "Achievement",
        backref="owner",
        lazy=True,
        cascade="all, delete-orphan",
    )

    def is_locked(self, now: datetime | None = None) -> bool:
        current_time = now or datetime.utcnow()
        return self.lockout_until is not None and self.lockout_until > current_time


class AuthLog(db.Model):
    __tablename__ = "auth_logs"

    id = db.Column(db.Integer, primary_key=True)
    email_attempted = db.Column(db.String(254), nullable=False)
    ip_address = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(512), nullable=True)
    status = db.Column(db.String(40), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class TeamMember(db.Model):
    __tablename__ = "team_members"
    __table_args__ = (
        db.UniqueConstraint("owner_id", "email", name="uq_team_member_owner_email"),
    )

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(254), nullable=False)
    role = db.Column(db.String(50), nullable=False, default="Member")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class Achievement(db.Model):
    __tablename__ = "achievements"

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    title = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(40), nullable=False)
    description = db.Column(db.String(300), nullable=True)
    image_filename = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
