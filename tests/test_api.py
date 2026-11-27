import os
import tempfile

_test_dir = tempfile.TemporaryDirectory()
os.environ["DORIA_DB_PATH"] = os.path.join(_test_dir.name, "doria_test.db")
os.environ["DORIA_SECRET_KEY"] = "ci-test-secret-key-longer-than-32-characters"
os.environ["DORIA_ENV"] = "test"

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def register(email):
    r=client.post("/register",json={"email":email,"display_name":email.split("@")[0],"password":"strong-test-pass-123"})
    assert r.status_code==201,r.text
    return r.json()["user_id"],{"Authorization":"Bearer "+r.json()["access_token"]}

def test_health_and_frontend():
    assert client.get("/health").json()["ok"] is True
    page=client.get("/")
    assert page.status_code==200
    assert "دوریا" in page.text

def test_email_register_login_and_private_chat():
    uid1,h1=register("one@example.com")
    uid2,h2=register("two@example.com")
    login=client.post("/login",json={"email":"ONE@example.com","password":"strong-test-pass-123","device_id":"device-one-example.com"})
    assert login.status_code==200
    sent=client.post("/messages",headers=h1,json={"receiver_id":uid2,"body":"سلام دوریا"})
    assert sent.status_code==201
    rows=client.get(f"/messages/{uid1}",headers=h2)
    assert rows.status_code==200 and rows.json()[0]["body"]=="سلام دوریا"

def test_duplicate_and_invalid_registration():
    register("duplicate@example.com")
    duplicate=client.post("/register",json={"email":"duplicate@example.com","display_name":"Again","password":"strong-test-pass-123"})
    assert duplicate.status_code==409
    invalid=client.post("/register",json={"email":"not-an-email","display_name":"Bad","password":"strong-test-pass-123"})
    assert invalid.status_code==422

def test_auth_and_blocking():
    _,h1=register("blocker@example.com")
    uid2,_=register("target@example.com")
    assert client.get("/me").status_code==401
    assert client.post(f"/blocks/{uid2}",headers=h1).status_code==201
    denied=client.post("/messages",headers=h1,json={"receiver_id":uid2,"body":"test"})
    assert denied.status_code==403

def test_group_chat():
    _,headers=register("group@example.com")
    created=client.post("/groups",headers=headers,json={"name":"گروه آزمایشی"})
    assert created.status_code==201
    gid=created.json()["id"]
    sent=client.post(f"/groups/{gid}/messages",headers=headers,json={"body":"پیام گروهی"})
    assert sent.status_code==201
    received=client.get(f"/groups/{gid}/messages",headers=headers)
    assert received.status_code==200 and received.json()[0]["body"]=="پیام گروهی"

def test_rejects_blank_group_name_and_report_reason():
    _,headers=register("validation@example.com")
    bad_group=client.post("/groups",headers=headers,json={"name":"   "})
    assert bad_group.status_code==422
    _,target_headers=register("reported@example.com")
    target=client.get("/me",headers=target_headers).json()["id"]
    bad_report=client.post("/reports",headers=headers,json={"reported_user_id":target,"reason":"   "})
    assert bad_report.status_code==422


def test_authenticated_media_upload_and_retrieval():
    _,headers=register("media@example.com")
    denied=client.post("/uploads",files={"file":("pic.png",b"fake","image/png")})
    assert denied.status_code==401
    uploaded=client.post("/uploads",headers=headers,files={"file":("pic.png",b"\x89PNG\r\n\x1a\nmedia-test","image/png")})
    assert uploaded.status_code==201,uploaded.text
    data=uploaded.json()
    assert data["kind"]=="image" and data["url"].startswith("/media/")
    fetched=client.get(data["url"])
    assert fetched.status_code==200

def test_media_rejects_unsupported_file_type():
    _,headers=register("badmedia@example.com")
    result=client.post("/uploads",headers=headers,files={"file":("x.txt",b"hello","text/plain")})
    assert result.status_code==415


def test_one_account_per_device_session():
    first_id, first_headers = register("phone-first@example.com")
    second = client.post("/login",json={"email":"phone-second@example.com","password":"strong-test-pass-123","device_id":"phone-shared-device-123456"})
    assert second.status_code==401
    register("phone-second@example.com")
    second_login=client.post("/login",json={"email":"phone-second@example.com","password":"strong-test-pass-123","device_id":"device-phone-second-example.com"})
    assert second_login.status_code==200
    # Reusing a device identifier for a different account invalidates its previous session.
    first_login=client.post("/login",json={"email":"phone-first@example.com","password":"strong-test-pass-123","device_id":"same-device-identifier-123456"})
    assert first_login.status_code==200
    old=client.post("/login",json={"email":"phone-second@example.com","password":"strong-test-pass-123","device_id":"same-device-identifier-123456"})
    assert old.status_code==200
    assert client.get("/me",headers={"Authorization":"Bearer "+first_login.json()["access_token"]}).status_code==401
