# Internship Summary Report

## Project
Secure Login System with User Role Management (Flask + SQLite)

## Objective
Build a secure web login platform implementing authentication, authorization, and role-based access control while applying practical cybersecurity controls.

## Implemented Components

- Secure registration and login flows
- Argon2id password hashing
- Role model (`admin`, `user`) with admin-only management panel
- Session cookie protections and idle timeout
- CSRF protection for all forms
- CAPTCHA verification integration (Cloudflare Turnstile)
- Brute-force mitigation with account lockout (5 attempts / 15 minutes)
- Auth event logging table for traceability
- Automated tests for auth, RBAC, and security edge cases

## Challenges and Solutions

1. Challenge: Preventing privilege escalation at signup.
Solution: Registration always forces role to `user` on server side, regardless of submitted form value.

2. Challenge: Balancing usability and brute-force defense.
Solution: Implemented lockout threshold and cooldown with reset after successful login.

3. Challenge: CAPTCHA in local/offline testing.
Solution: Added environment flags to enable strict Turnstile in production and bypass mode for automated tests.

4. Challenge: Session security with simplicity.
Solution: Used server-side Flask sessions with secure cookie flags and idle timeout checks.

## Test Evidence

- Registration: valid, duplicate, weak password, tampered role
- Login: valid/invalid user flows, lockout behavior
- RBAC: admin allowed, user denied
- Security: CSRF rejection, SQL injection payload check, CAPTCHA failure check, logout invalidation

## Screenshots

Add screenshots under `docs/screenshots/`:

- Register page
- Login page (error and success)
- User dashboard
- Admin dashboard
- Lockout error state

## Final Notes

The project is implementation-complete for internship submission using SQLite, with documented migration path to MySQL if requested by evaluator.
