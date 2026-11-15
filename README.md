# DORIA Messenger — API starter

DORIA is an early-stage messaging project. The current repository contains a Python FastAPI backend, not an Android app or a production-ready public messenger.

## Current features
- Account registration and login
- Password hashing and signed bearer tokens
- User directory
- One-to-one text messages
- Basic groups and group text messages
- User blocking and reporting endpoints
- Health check and interactive API docs
- Basic request throttling for login, registration and reports
- Automated API tests and GitHub Actions test workflow

## Run locally
1. Install Python 3.10 or newer.
2. Install packages: pip install -r requirements.txt
3. Set a private random DORIA_SECRET_KEY (at least 32 characters for production).
4. Run: python main.py
5. Open http://127.0.0.1:8000/docs.

For local development only, if no secret is configured, the app creates a temporary secret at startup. Sessions will not survive a restart. Production mode refuses to start without a strong secret and explicit allowed origins.

## Run tests
Run: pytest -q

The tests use FastAPI TestClient and HTTPX.

## Important limitations before public launch
- SQLite is for development/testing; production needs PostgreSQL, migrations, backups and persistent storage.
- The current rate limiter is per-process and is not sufficient for multiple server workers; use a shared limiter such as Redis in production.
- Admin roles and a real moderation dashboard are not implemented; the admin reports route remains disabled.
- Public group discovery, channels, media uploads, voice/video calls, push notifications, account recovery, device/session management and an Android client are not implemented.
- Messages are not end-to-end encrypted. Do not use this starter for sensitive or real personal conversations.
- Before public use, arrange an independent security review, HTTPS, monitoring, abuse response, privacy policy, data deletion/export procedures and reliable backups.
- Never commit real API keys, passwords, signing secrets, database files or user data.

## Environment
Use .env.example as a template for hosting environment settings; do not commit a real .env file. Use a unique secret per environment.
