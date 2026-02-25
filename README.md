# Secure Login System with Role-Based Access Control

This repository implements a secure Flask web application for user registration, login, session management, and role-based access control (RBAC) with Admin/User roles.

## Features

- User registration with server-side validation
- Argon2id password hashing
- Secure login with session cookies (`HttpOnly`, `SameSite=Lax`, optional `Secure`)
- Cloudflare Turnstile CAPTCHA validation on login and password-reset request
- Account lockout after 5 failed attempts for 15 minutes
- Forgot password with time-limited secure reset token
- Public home page (`/`) with quick navigation
- Achievement gallery with screenshot upload (Bug Bounty Reward, Hall of Fame, Certificate)
- Dedicated dashboard settings page
- Light/Dark/System theme toggle (browser localStorage + system default fallback)
- RBAC-protected admin dashboard
- Admin user management (view users, change roles, disable accounts)
- Team member management inside dashboard (add/show/delete)
- CSRF protection for all form submissions
- Authentication event logging
- Automated tests with `pytest`

## Tech Stack

- Backend: Flask
- Database: SQLite (documented path to migrate to MySQL below)
- ORM: Flask-SQLAlchemy
- Migrations: Flask-Migrate
- Password Hashing: Passlib Argon2id
- Testing: Pytest + Flask test client

## Project Structure

```text
app/
  admin/
  auth/
  main/
  __init__.py
  cli.py
  config.py
  extensions.py
  models.py
  security.py
templates/
static/css/
tests/
instance/
run.py
requirements.txt
.env.example
REPORT.md
```

## Setup Instructions (Windows PowerShell)

1. Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. Install dependencies:

```powershell
pip install -r requirements.txt
```

3. Configure environment variables:

```powershell
Copy-Item .env.example .env
# Edit .env and set SECRET_KEY and optional Turnstile keys
```

4. Initialize database:

```powershell
$env:FLASK_APP='run.py'
flask init-db
```

5. Seed admin account:

```powershell
$env:SEED_ADMIN_PASSWORD='YourStrongAdminPass123!'
flask seed-admin
```

6. Run the app:

```powershell
python run.py
```

Open: `http://127.0.0.1:5000`

## Security Controls Implemented

- Password policy enforcement (length and complexity)
- Password hashing with Argon2id
- Generic login error responses for invalid credentials
- Login lockout policy after repeated failures
- CSRF protection via Flask-WTF
- ORM-based queries to reduce SQL injection risk
- CAPTCHA gate on login (when enabled)
- Admin route protection with explicit role checks
- Disabled-account login denial
- Self account deletion with password + `CONFIRM` safeguard
- Last-admin deletion protection

## Routes

- `GET /` - public home page
- `GET /portal` - role-aware redirect (login/admin/dashboard)
- `GET /achievements` - public achievement gallery
- `POST /achievements/upload` - authenticated screenshot upload
- `POST /achievements/<id>/delete` - owner/admin delete uploaded achievement
- `GET /register` - registration form
- `POST /register` - create user (always role `user`)
- `GET /login` - login form
- `POST /login` - authenticate + CAPTCHA + lockout handling
- `GET /forgot-password` - forgot password form
- `POST /forgot-password` - generate time-limited reset link
- `GET /reset-password/<token>` - reset token validation page
- `POST /reset-password/<token>` - set new password
- `POST /logout` - clear session
- `GET /dashboard` - authenticated user page
- `GET /dashboard/settings` - authenticated settings page
- `POST /dashboard/settings/delete-account` - self account soft delete with safeguards
- `POST /dashboard/team-members` - add team member
- `POST /dashboard/team-members/<id>/delete` - delete team member
- `GET /admin/users` - admin-only user list
- `POST /admin/users/<id>/role` - admin-only role update
- `POST /admin/users/<id>/disable` - admin-only account disable
- `POST /admin/users/<id>/delete` - admin-only hard delete non-admin user

## Run Tests

```powershell
pytest -q
```

## Turnstile Configuration

Set in `.env`:

- `TURNSTILE_ENABLED=true`
- `TURNSTILE_SITE_KEY=<site-key>`
- `TURNSTILE_SECRET_KEY=<secret-key>`

For local testing without external CAPTCHA verification, keep:

- `TURNSTILE_ENABLED=false`

Achievement upload config (optional):

- `MAX_ACHIEVEMENT_IMAGE_MB=5`
- `ACHIEVEMENTS_UPLOAD_DIR=static/uploads/achievements`

## MySQL Migration Notes

If evaluator requires MySQL later:

1. Install MySQL Server locally.
2. Create database, for example `secure_login_db`.
3. Install driver:

```powershell
pip install pymysql
```

4. Update `DATABASE_URL` in `.env`:

```text
DATABASE_URL=mysql+pymysql://<user>:<password>@localhost:3306/secure_login_db
```

5. Re-run:

```powershell
flask init-db
```

## Submission Checklist

- Code pushed to GitHub repository
- README complete
- Screenshots added under `docs/screenshots/`
- `REPORT.md` completed
- Repository link submitted before **February 28, 2026**
- Proof PDFs emailed to `vaulttecconsultancy@gmail.com`
