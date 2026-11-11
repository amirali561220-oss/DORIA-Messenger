import os
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

APP_NAME = "DORIA Messenger API"
DB_PATH = os.getenv("DORIA_DB_PATH", "doria.db")
SECRET_KEY = os.getenv("DORIA_SECRET_KEY", "CHANGE_THIS_BEFORE_PUBLIC_DEPLOYMENT")
TOKEN_HOURS = int(os.getenv("DORIA_TOKEN_HOURS", "72"))

app = FastAPI(title=APP_NAME, version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("DORIA_ALLOWED_ORIGINS", "*").split(","),
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
bearer = HTTPBearer(auto_error=False)


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as c:
        c.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            rules_accepted INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(sender_id) REFERENCES users(id),
            FOREIGN KEY(receiver_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS groups_table (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS group_members (
            group_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            UNIQUE(group_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS group_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reporter_id INTEGER NOT NULL,
            reported_user_id INTEGER NOT NULL,
            reason TEXT NOT NULL,
            details TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending'
        );
        """)


init_db()


def now():
    return datetime.now(timezone.utc).isoformat()


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000)
    return salt.hex() + ":" + digest.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split(":", 1)
        return secrets.compare_digest(
            hash_password(password, bytes.fromhex(salt_hex)).split(":", 1)[1],
            digest_hex,
        )
    except Exception:
        return False


def create_token(user_id: int):
    payload = {
        "sub": str(user_id),
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=TOKEN_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    if credentials is None:
        raise HTTPException(status_code=401, detail="لطفاً وارد حساب شوید")
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=["HS256"])
        user_id = int(payload["sub"])
    except Exception:
        raise HTTPException(status_code=401, detail="نشست نامعتبر یا منقضی شده است")
    with db() as c:
        user = c.execute(
            "SELECT id, username, display_name, created_at FROM users WHERE id=?",
            (user_id,),
        ).fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="حساب پیدا نشد")
    return dict(user)


class RegisterInput(BaseModel):
    username: str = Field(min_length=3, max_length=24, pattern=r"^[a-zA-Z0-9_]+$")
    display_name: str = Field(min_length=1, max_length=40)
    password: str = Field(min_length=8, max_length=128)
    accept_rules: bool


class LoginInput(BaseModel):
    username: str
    password: str


class MessageInput(BaseModel):
    receiver_id: int
    body: str = Field(min_length=1, max_length=5000)


class GroupInput(BaseModel):
    name: str = Field(min_length=2, max_length=60)


class GroupMessageInput(BaseModel):
    body: str = Field(min_length=1, max_length=5000)


class ReportInput(BaseModel):
    reported_user_id: int
    reason: str = Field(min_length=3, max_length=80)
    details: str = Field(default="", max_length=1000)


@app.get("/")
def home():
    return {"app": "DORIA", "version": "0.1.0", "status": "running"}


@app.get("/health")
def health():
    return {"ok": True, "time": now()}


@app.get("/rules")
def rules():
    return {
        "rules": [
            "به دیگران احترام بگذارید.",
            "تهدید، آزار، فریب و انتشار اطلاعات خصوصی دیگران ممنوع است.",
            "محتوای غیرقانونی یا آسیب‌زا منتشر نکنید.",
            "گزارش‌ها بررسی می‌شوند و امکان اعتراض به تصمیم مدیر وجود دارد.",
        ]
    }


@app.post("/register", status_code=201)
def register(data: RegisterInput):
    if not data.accept_rules:
        raise HTTPException(status_code=400, detail="برای ساخت حساب باید قوانین را بپذیرید")
    with db() as c:
        try:
            cur = c.execute(
                "INSERT INTO users(username, display_name, password_hash, rules_accepted, created_at) VALUES(?,?,?,?,?)",
                (data.username.lower(), data.display_name, hash_password(data.password), 1, now()),
            )
            user_id = cur.lastrowid
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="این نام کاربری قبلاً ثبت شده است")
    return {"message": "حساب ساخته شد", "user_id": user_id}


@app.post("/login")
def login(data: LoginInput):
    with db() as c:
        user = c.execute(
            "SELECT id, password_hash FROM users WHERE username=?",
            (data.username.lower(),),
        ).fetchone()
    if not user or not verify_password(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="نام کاربری یا رمز عبور اشتباه است")
    return {"access_token": create_token(user["id"]), "token_type": "bearer"}


@app.get("/me")
def me(user=Depends(current_user)):
    return user


@app.get("/users")
def users(user=Depends(current_user)):
    with db() as c:
        rows = c.execute(
            "SELECT id, username, display_name FROM users WHERE id<>? ORDER BY id DESC LIMIT 100",
            (user["id"],),
        ).fetchall()
    return [dict(row) for row in rows]


@app.post("/messages", status_code=201)
def send_message(data: MessageInput, user=Depends(current_user)):
    if data.receiver_id == user["id"]:
        raise HTTPException(status_code=400, detail="ارسال پیام به خودتان ممکن نیست")
    with db() as c:
        exists = c.execute("SELECT id FROM users WHERE id=?", (data.receiver_id,)).fetchone()
        if not exists:
            raise HTTPException(status_code=404, detail="کاربر پیدا نشد")
        cur = c.execute(
            "INSERT INTO messages(sender_id, receiver_id, body, created_at) VALUES(?,?,?,?)",
            (user["id"], data.receiver_id, data.body, now()),
        )
        return {"id": cur.lastrowid, "sent": True}


@app.get("/messages/{other_user_id}")
def conversation(other_user_id: int, user=Depends(current_user)):
    with db() as c:
        rows = c.execute(
            """SELECT id, sender_id, receiver_id, body, created_at FROM messages
            WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)
            ORDER BY id DESC LIMIT 200""",
            (user["id"], other_user_id, other_user_id, user["id"]),
        ).fetchall()
    return [dict(row) for row in reversed(rows)]


@app.post("/groups", status_code=201)
def create_group(data: GroupInput, user=Depends(current_user)):
    with db() as c:
        cur = c.execute(
            "INSERT INTO groups_table(name, owner_id, created_at) VALUES(?,?,?)",
            (data.name, user["id"], now()),
        )
        group_id = cur.lastrowid
        c.execute("INSERT INTO group_members(group_id, user_id) VALUES(?,?)", (group_id, user["id"]))
    return {"group_id": group_id, "name": data.name}


@app.get("/groups")
def list_groups(user=Depends(current_user)):
    with db() as c:
        rows = c.execute(
            """SELECT g.id, g.name, g.owner_id FROM groups_table g
            JOIN group_members m ON m.group_id=g.id WHERE m.user_id=? ORDER BY g.id DESC""",
            (user["id"],),
        ).fetchall()
    return [dict(row) for row in rows]


@app.post("/groups/{group_id}/join")
def join_group(group_id: int, user=Depends(current_user)):
    with db() as c:
        exists = c.execute("SELECT id FROM groups_table WHERE id=?", (group_id,)).fetchone()
        if not exists:
            raise HTTPException(status_code=404, detail="گروه پیدا نشد")
        c.execute("INSERT OR IGNORE INTO group_members(group_id, user_id) VALUES(?,?)", (group_id, user["id"]))
    return {"joined": True}


@app.post("/groups/{group_id}/messages", status_code=201)
def send_group_message(group_id: int, data: GroupMessageInput, user=Depends(current_user)):
    with db() as c:
        member = c.execute(
            "SELECT 1 FROM group_members WHERE group_id=? AND user_id=?",
            (group_id, user["id"]),
        ).fetchone()
        if not member:
            raise HTTPException(status_code=403, detail="عضو این گروه نیستید")
        cur = c.execute(
            "INSERT INTO group_messages(group_id, sender_id, body, created_at) VALUES(?,?,?,?)",
            (group_id, user["id"], data.body, now()),
        )
    return {"id": cur.lastrowid, "sent": True}


@app.get("/groups/{group_id}/messages")
def get_group_messages(group_id: int, user=Depends(current_user)):
    with db() as c:
        member = c.execute(
            "SELECT 1 FROM group_members WHERE group_id=? AND user_id=?",
            (group_id, user["id"]),
        ).fetchone()
        if not member:
            raise HTTPException(status_code=403, detail="عضو این گروه نیستید")
        rows = c.execute(
            """SELECT id, sender_id, body, created_at FROM group_messages
            WHERE group_id=? ORDER BY id DESC LIMIT 200""",
            (group_id,),
        ).fetchall()
    return [dict(row) for row in reversed(rows)]


@app.post("/reports", status_code=201)
def report_user(data: ReportInput, user=Depends(current_user)):
    if data.reported_user_id == user["id"]:
        raise HTTPException(status_code=400, detail="نمی‌توانید خودتان را گزارش کنید")
    with db() as c:
        target = c.execute("SELECT id FROM users WHERE id=?", (data.reported_user_id,)).fetchone()
        if not target:
            raise HTTPException(status_code=404, detail="کاربر پیدا نشد")
        cur = c.execute(
            "INSERT INTO reports(reporter_id, reported_user_id, reason, details, created_at) VALUES(?,?,?,?,?)",
            (user["id"], data.reported_user_id, data.reason, data.details, now()),
        )
    return {"report_id": cur.lastrowid, "status": "pending"}


@app.get("/admin/reports")
def admin_reports(user=Depends(current_user)):
    # Admin roles and moderation dashboard must be configured before public launch.
    raise HTTPException(status_code=403, detail="پنل مدیر هنوز پیکربندی نشده است")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
