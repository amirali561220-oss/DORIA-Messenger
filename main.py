import os,re,sqlite3,hashlib,secrets,time
from pathlib import Path
from collections import defaultdict,deque
from datetime import datetime,timedelta,timezone
import jwt
from fastapi import FastAPI,Depends,HTTPException,Request
from fastapi.security import HTTPBearer,HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel,Field,field_validator

ROOT=Path(__file__).resolve().parent
WEB=ROOT/"web"
DB=os.getenv("DORIA_DB_PATH",str(ROOT/"doria.db"))
SECRET=os.getenv("DORIA_SECRET_KEY","").strip()
if not SECRET:
    if os.getenv("DORIA_ENV")=="production": raise RuntimeError("DORIA_SECRET_KEY is required.")
    SECRET=secrets.token_urlsafe(48)
    print("Development secret generated; sessions reset after restart.")
if len(SECRET)<32: raise RuntimeError("DORIA_SECRET_KEY must be at least 32 characters.")
app=FastAPI(title="DORIA Messenger",version="1.0.0")
auth=HTTPBearer(auto_error=False)
rate=defaultdict(deque)
@app.middleware("http")
async def headers_and_limits(req:Request,call_next):
    rules={"/login":(10,300),"/register":(5,3600),"/reports":(5,3600)}
    rule=rules.get(req.url.path)
    if rule and req.method=="POST":
        maxn,window=rule; ip=req.client.host if req.client else "unknown"; key=(req.url.path,ip); now=time.monotonic()
        while rate[key] and now-rate[key][0]>window: rate[key].popleft()
        if len(rate[key])>=maxn: return JSONResponse(status_code=429,content={"detail":"درخواست زیاد است؛ کمی بعد تلاش کنید."})
        rate[key].append(now)
    res=await call_next(req)
    res.headers["X-Content-Type-Options"]="nosniff"; res.headers["X-Frame-Options"]="DENY"; res.headers["Referrer-Policy"]="no-referrer"
    if req.url.path.startswith(("/me","/users","/messages","/groups")): res.headers["Cache-Control"]="no-store"
    return res

def db():
    Path(DB).parent.mkdir(parents=True,exist_ok=True)
    c=sqlite3.connect(DB,timeout=20); c.row_factory=sqlite3.Row; c.execute("PRAGMA foreign_keys=ON"); c.execute("PRAGMA busy_timeout=20000"); return c
def now(): return datetime.now(timezone.utc).isoformat()
def init():
    with db() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE,display_name TEXT NOT NULL,password_hash TEXT NOT NULL,created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY,sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,receiver_id INTEGER REFERENCES users(id) ON DELETE CASCADE,body TEXT NOT NULL,created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS groups_table(id INTEGER PRIMARY KEY,name TEXT NOT NULL,owner_id INTEGER REFERENCES users(id),created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS group_members(group_id INTEGER REFERENCES groups_table(id) ON DELETE CASCADE,user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,UNIQUE(group_id,user_id));
        CREATE TABLE IF NOT EXISTS group_messages(id INTEGER PRIMARY KEY,group_id INTEGER REFERENCES groups_table(id) ON DELETE CASCADE,sender_id INTEGER REFERENCES users(id),body TEXT NOT NULL,created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS blocks(blocker_id INTEGER REFERENCES users(id),blocked_id INTEGER REFERENCES users(id),created_at TEXT,PRIMARY KEY(blocker_id,blocked_id));
        CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY,reporter_id INTEGER REFERENCES users(id),reported_user_id INTEGER REFERENCES users(id),reason TEXT,details TEXT,created_at TEXT);
        CREATE INDEX IF NOT EXISTS idx_msg_pair ON messages(sender_id,receiver_id,id);
        CREATE INDEX IF NOT EXISTS idx_group_msg ON group_messages(group_id,id);
        """)
        cols={x["name"] for x in c.execute("PRAGMA table_info(users)")}
        if "email" not in cols: c.execute("ALTER TABLE users ADD COLUMN email TEXT")
init()
def hashpw(p,s=None):
    s=s or secrets.token_bytes(16); d=hashlib.pbkdf2_hmac("sha256",p.encode(),s,310000); return s.hex()+":"+d.hex()
def checkpw(p,stored):
    try:
        s,d=stored.split(":",1); return secrets.compare_digest(hashpw(p,bytes.fromhex(s)).split(":",1)[1],d)
    except Exception: return False
def token(uid):
    t=datetime.now(timezone.utc); return jwt.encode({"sub":str(uid),"iat":t,"exp":t+timedelta(hours=48)},SECRET,algorithm="HS256")
def me(credentials:HTTPAuthorizationCredentials=Depends(auth)):
    if not credentials: raise HTTPException(401,"ابتدا وارد حساب شوید.")
    try: uid=int(jwt.decode(credentials.credentials,SECRET,algorithms=["HS256"])["sub"])
    except Exception: raise HTTPException(401,"نشست نامعتبر یا منقضی شده است.")
    with db() as c: row=c.execute("SELECT id,email,display_name,created_at FROM users WHERE id=?",(uid,)).fetchone()
    if not row: raise HTTPException(401,"حساب پیدا نشد.")
    return dict(row)
def isblocked(c,a,b):
    return c.execute("SELECT 1 FROM blocks WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)",(a,b,b,a)).fetchone() is not None

class Register(BaseModel):
    email:str=Field(min_length=5,max_length=254)
    display_name:str=Field(min_length=1,max_length=40)
    password:str=Field(min_length=10,max_length=128)
    @field_validator("email")
    @classmethod
    def email_ok(cls,v):
        v=v.strip().lower()
        if not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_{|}~-]+@[A-Za-z0-9.-]+[.][A-Za-z]{2,}",v): raise ValueError("ایمیل معتبر نیست.")
        return v
    @field_validator("display_name")
    @classmethod
    def name_ok(cls,v):
        if not v.strip(): raise ValueError("نام نمایشی را وارد کنید.")
        return v.strip()
class Login(BaseModel):
    email:str
    password:str
    @field_validator("email")
    @classmethod
    def norm(cls,v): return v.strip().lower()
class Msg(BaseModel):
    body:str=Field(min_length=1,max_length=4000)
    @field_validator("body")
    @classmethod
    def clean(cls,v):
        if not v.strip(): raise ValueError("پیام خالی است.")
        return v.strip()
class DirectMsg(Msg): receiver_id:int=Field(gt=0)
class Group(BaseModel):
    name:str=Field(min_length=2,max_length=60)
    @field_validator("name")
    @classmethod
    def group_name(cls,v): return v.strip()
class Report(BaseModel):
    reported_user_id:int=Field(gt=0)
    reason:str=Field(min_length=3,max_length=80)
    details:str=Field(default="",max_length=1000)

@app.get("/health")
def health():
    with db() as c: c.execute("SELECT 1")
    return {"ok":True,"app":"DORIA","version":"1.0.0","time":now()}
@app.post("/register",status_code=201)
def register(x:Register):
    with db() as c:
        try:
            cols={z["name"] for z in c.execute("PRAGMA table_info(users)")}
            if "username" in cols:
                legacy_username=x.email.split("@")[0][:18]+"_"+secrets.token_hex(3)
                uid=c.execute("INSERT INTO users(email,username,display_name,password_hash,created_at) VALUES(?,?,?,?,?)",(x.email,legacy_username,x.display_name,hashpw(x.password),now())).lastrowid
            else:
                uid=c.execute("INSERT INTO users(email,display_name,password_hash,created_at) VALUES(?,?,?,?)",(x.email,x.display_name,hashpw(x.password),now())).lastrowid
        except sqlite3.IntegrityError: raise HTTPException(409,"این ایمیل قبلاً ثبت شده است.")
    return {"access_token":token(uid),"user_id":uid}
@app.post("/login")
def login(x:Login):
    with db() as c: u=c.execute("SELECT id,password_hash FROM users WHERE email=?",(x.email,)).fetchone()
    if not u or not checkpw(x.password,u["password_hash"]): raise HTTPException(401,"ایمیل یا رمز عبور اشتباه است.")
    return {"access_token":token(u["id"]),"token_type":"bearer"}
@app.get("/me")
def profile(u=Depends(me)): return u
@app.get("/users")
def users(u=Depends(me)):
    with db() as c:
        rows=c.execute("""SELECT id,email,display_name FROM users WHERE id<>? AND id NOT IN(SELECT blocked_id FROM blocks WHERE blocker_id=?) AND id NOT IN(SELECT blocker_id FROM blocks WHERE blocked_id=?) ORDER BY id DESC LIMIT 200""",(u["id"],u["id"],u["id"])).fetchall()
    return [dict(x) for x in rows]
@app.get("/messages/{other}")
def messages(other:int,u=Depends(me)):
    with db() as c:
        if isblocked(c,u["id"],other): raise HTTPException(403,"این گفتگو در دسترس نیست.")
        rows=c.execute("""SELECT id,sender_id,receiver_id,body,created_at FROM messages WHERE(sender_id=? AND receiver_id=?) OR(sender_id=? AND receiver_id=?) ORDER BY id DESC LIMIT 100""",(u["id"],other,other,u["id"])).fetchall()
    return [dict(x) for x in reversed(rows)]
@app.post("/messages",status_code=201)
def send(x:DirectMsg,u=Depends(me)):
    if x.receiver_id==u["id"]: raise HTTPException(400,"نمی‌توانید به خودتان پیام بدهید.")
    with db() as c:
        if not c.execute("SELECT id FROM users WHERE id=?",(x.receiver_id,)).fetchone(): raise HTTPException(404,"کاربر پیدا نشد.")
        if isblocked(c,u["id"],x.receiver_id): raise HTTPException(403,"ارسال پیام ممکن نیست.")
        mid=c.execute("INSERT INTO messages(sender_id,receiver_id,body,created_at) VALUES(?,?,?,?)",(u["id"],x.receiver_id,x.body,now())).lastrowid
    return {"id":mid,"sent":True}
@app.post("/groups",status_code=201)
def make_group(x:Group,u=Depends(me)):
    with db() as c:
        gid=c.execute("INSERT INTO groups_table(name,owner_id,created_at) VALUES(?,?,?)",(x.name,u["id"],now())).lastrowid
        c.execute("INSERT INTO group_members(group_id,user_id) VALUES(?,?)",(gid,u["id"]))
    return {"id":gid,"name":x.name}
@app.get("/groups")
def groups(u=Depends(me)):
    with db() as c: rows=c.execute("SELECT g.id,g.name,g.owner_id FROM groups_table g JOIN group_members m ON m.group_id=g.id WHERE m.user_id=? ORDER BY g.id DESC",(u["id"],)).fetchall()
    return [dict(x) for x in rows]
@app.post("/groups/{gid}/join")
def join(gid:int,u=Depends(me)):
    with db() as c:
        if not c.execute("SELECT id FROM groups_table WHERE id=?",(gid,)).fetchone(): raise HTTPException(404,"گروه پیدا نشد.")
        c.execute("INSERT OR IGNORE INTO group_members(group_id,user_id) VALUES(?,?)",(gid,u["id"]))
    return {"joined":True}
@app.get("/groups/{gid}/messages")
def group_messages(gid:int,u=Depends(me)):
    with db() as c:
        if not c.execute("SELECT 1 FROM group_members WHERE group_id=? AND user_id=?",(gid,u["id"])).fetchone(): raise HTTPException(403,"عضو این گروه نیستید.")
        rows=c.execute("SELECT id,sender_id,body,created_at FROM group_messages WHERE group_id=? ORDER BY id DESC LIMIT 100",(gid,)).fetchall()
    return [dict(x) for x in reversed(rows)]
@app.post("/groups/{gid}/messages",status_code=201)
def group_send(gid:int,x:Msg,u=Depends(me)):
    with db() as c:
        if not c.execute("SELECT 1 FROM group_members WHERE group_id=? AND user_id=?",(gid,u["id"])).fetchone(): raise HTTPException(403,"عضو این گروه نیستید.")
        mid=c.execute("INSERT INTO group_messages(group_id,sender_id,body,created_at) VALUES(?,?,?,?)",(gid,u["id"],x.body,now())).lastrowid
    return {"id":mid,"sent":True}
@app.post("/blocks/{target}",status_code=201)
def block(target:int,u=Depends(me)):
    if target==u["id"]: raise HTTPException(400,"شناسه نامعتبر است.")
    with db() as c: c.execute("INSERT OR IGNORE INTO blocks(blocker_id,blocked_id,created_at) VALUES(?,?,?)",(u["id"],target,now()))
    return {"blocked":True}
@app.post("/reports",status_code=201)
def report(x:Report,u=Depends(me)):
    with db() as c: rid=c.execute("INSERT INTO reports(reporter_id,reported_user_id,reason,details,created_at) VALUES(?,?,?,?,?)",(u["id"],x.reported_user_id,x.reason,x.details,now())).lastrowid
    return {"report_id":rid,"status":"pending"}
if WEB.exists(): app.mount("/",StaticFiles(directory=str(WEB),html=True),name="web")
if __name__=="__main__":
    import uvicorn
    uvicorn.run("main:app",host="0.0.0.0",port=int(os.getenv("PORT","8000")))
