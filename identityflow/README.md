# IdentityFlow — Enterprise IAM Lifecycle Simulator

**Portfolio application:** a working Python + JavaScript simulator for authentication, account recovery, MFA, access control, session lifecycle, and audit trails.

> **Training / portfolio use only. NOT a production identity provider, not Okta, not OAuth 2.0 or OpenID Connect.** All identities are fictional, data lives in process memory, the app deliberately displays recovery tokens and MFA codes to facilitate evaluation, and it does not send email or SMS. Never use real credentials or customer data.

## Features

| Capability | Behavior | Engineering concepts |
| --- | --- | --- |
| Password authentication | Demo username/password, per-account salted PBKDF2 hashes | Hashing, password verification, generic failure errors |
| Lockout | Five failed attempts triggers five-minute lock | Brute-force protection demo |
| Forgot username | Email lookup and simulated private delivery | Enumeration-safe public message (but intentionally visible demo delivery) |
| Forgot password | Random single-use reset token, 10-minute expiry | Token hashing, expiration, replay prevention |
| Password policy | At least 12 chars, upper/lowercase, digit, symbol; reject previous three | Policy enforcement, history |
| MFA | A randomly generated verification code for each login, three-minute expiry | Two-step login, challenge lifecycle |
| MFA recovery | Three single-use recovery codes on enrollment | Backup factors, replay prevention |
| RBAC | Viewer / Editor / Admin and protected API endpoints | Least privilege, HTTP 401 vs 403 |
| Sessions | Random opaque cookie, 20-minute lifetime, logout/revocation | HttpOnly cookies, expiry, invalidation |
| Audit | Bounded event log, admin-only view | Allow/deny events without credential logging |
| CI | Python unit tests on push/PR | Quality gates, regression |

### Important simulator limitations

- MFA codes and password-reset tokens are displayed in the browser; **real implementations must deliver these privately**. The MFA flow is **not TOTP** and has no authenticator-app integration.
- The account-recovery response includes fictional demo usernames for visibility. A production endpoint must not return this information.
- The app is not persistent and will reset all accounts after a server restart; cloud hosting may start multiple instances with divergent state.
- A custom request header provides one basic cross-site-request safeguard but is **not a complete CSRF strategy**. Session handling, TLS termination, rate limiting at IP level, secure recovery delivery, anti-automation, monitoring, token storage and production-grade identity workflows require a dedicated IdP and further hardening.
- For demo clarity, password hashes use PBKDF2. A production IAM system should follow current platform/IdP guidance for storage and account recovery.
- **Do not deploy for real user authentication** or expose the simulator as a secure login service.

## Local run

Python 3.10+; no third-party dependencies.

```bash
python -m app.server
```

Open **http://127.0.0.1:8000**.

### Fictional demonstration accounts

- `alex.viewer` — Viewer
- `sam.editor` — Editor
- `jordan.admin` — Admin

All initial demo passwords: `DemoPass!2026`.

Fictional email format: `<username>@example.test` (e.g. `alex.viewer@example.test`). **These are not real mailboxes.**

### Test

```bash
python -m unittest discover -s tests -v
```

## End-to-end exercise

1. Sign in as Viewer and try reading projects (200), creating a project (403), and reading audit history (403).
2. Log out, then query a protected endpoint (401).
3. Sign in as Editor and create a project (201).
4. Request a password reset using `sam.editor@example.test`, copy the demo token, set a compliant new password, and confirm an old password fails.
5. Sign in and enable MFA. Save the displayed demo recovery codes; log out and sign in again. Confirm that a verification step is required.
6. Try an invalid MFA code, then the displayed code. Check expiration and replay protections in unit tests.
7. Sign in as Admin to see the audit trail.
8. Run tests locally or on GitHub Actions.

## Architecture

```text
Browser UI (web/index.html)
      |
      | JSON HTTP requests / session cookie
      v
Python API (app/server.py)
      |
      v
IAM service (app/security.py)
      |-- in-memory demo users and hashed passwords
      |-- lockout and password reset token registry
      |-- MFA challenges and recovery codes
      |-- role permissions, sessions and audit events
      v
Unit tests (tests/test_security.py)
```

## Render deployment

New Web Service → GitHub repository → Python 3 → root directory repository root → build command `python -m unittest discover -s tests -v` → start command `python -m app.server` → Free instance for demo purposes. The app binds to Render's `PORT` and `0.0.0.0`.

**Do not configure real emails, API secrets, or production identities for this simulator.**

## Future separate project

A reusable **IAM QA Automation Framework** with Selenium / pytest / API test coverage is planned as a **different repository**. IdentityFlow is the application-under-test candidate, not the automation framework itself.
