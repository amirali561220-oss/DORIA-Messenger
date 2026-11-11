# DORIA Messenger — API starter

This repository currently contains an **early backend starter**, not a complete production messenger or Android APK.

## Included in this milestone
- FastAPI HTTP API
- SQLite database for local testing
- Account registration and login with password hashing
- JWT bearer authentication
- User listing and one-to-one text messages
- Basic groups and group text messages
- User reporting endpoint
- Health check and API documentation

## Run locally (Android / Pydroid 3 or a computer)
1. Install the packages: `pip install -r requirements.txt`
2. Set a strong secret in the environment variable `DORIA_SECRET_KEY`. Never publish a real secret.
3. Run: `python main.py`
4. Open `http://127.0.0.1:8000/docs` in your browser.

## Important limitations
- SQLite is for development/testing; use PostgreSQL and persistent storage for a hosted deployment.
- The admin panel, channels, media uploads, voice/video calls, push notifications, end-to-end encryption, and Android app are **not implemented yet**.
- There is no production admin-role system, rate limiting, account recovery, or moderation workflow yet.
- Do not expose this starter publicly or use real personal conversations until security review, HTTPS, access controls, backups, and deployment configuration are completed.
- Change the example JWT secret before any deployment. Keep secrets out of GitHub.

## Next milestones
1. Harden authentication and authorization, add rate limiting and tests.
2. Add PostgreSQL migrations and persistent media storage.
3. Add admin roles, channels, privacy controls, and moderation/appeals.
4. Build the Android client and connect it to the hosted API.
5. Add push notifications and calling only after the core app is stable.
