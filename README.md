# DORIA Messenger

DORIA is an early-stage Persian messaging web app. The repository now contains a FastAPI backend and a responsive Persian web client served from the same origin.

## Included in this starter
- Email-address + password registration and login
- Password hashing with PBKDF2-HMAC-SHA256
- Signed expiring bearer sessions
- User directory and private text messages
- Basic group creation, membership and group text messages
- Basic block and report endpoints
- Health endpoint and FastAPI API docs at /docs
- Basic in-process throttling for registration, login and reports
- GitHub Actions test workflow

## Local run
Python 3.10+:
1. pip install -r requirements.txt
2. Set DORIA_SECRET_KEY to a private random string of at least 32 characters (recommended).
3. python main.py
4. Open http://127.0.0.1:8000

Tests: pytest -q

## Hosting
The Render Blueprint is configured for a free demonstration deployment. Connect the repository to Render and create the service from the Blueprint. Free instances sleep after inactivity and their local files are ephemeral; therefore the SQLite database can be lost after restarts, redeploys or sleep. This is a test deployment only, not a durable public messenger. A reliable public launch needs a persistent PostgreSQL database or paid persistent storage, backups and monitoring.

## Important limitations
- Email is currently the login identifier; the app does NOT send email verification or password-reset messages yet. Do not claim an address has been verified.
- Messages are not end-to-end encrypted. Do not use this app for private or sensitive conversations.
- No media upload, voice/video calling, push notifications, contact sync, public group discovery, admin dashboard or Android APK yet.
- The current SQLite database and in-memory rate limiter are suitable only for a small prototype. Production requires PostgreSQL, migrations, shared rate limiting, backups, monitoring and a security review.
- Add a real email provider only through server-side environment secrets; never commit credentials or expose private keys in frontend code.
- Never commit real passwords, tokens, database files or personal user data.
