"""DORIA HOST - launcher for running DORIA on Android/Pydroid 3.

This runs the existing FastAPI application on the phone. It is not a cloud
provider: the phone must remain powered on, connected, and running this script.
"""
import os
import secrets
import socket
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def choose_data_dir():
    candidates = [
        Path("/storage/emulated/0/DORIA_DATA"),
        Path.home() / "DORIA_DATA",
        ROOT / "DORIA_DATA",
    ]
    for path in candidates:
        try:
            path.mkdir(parents=True, exist_ok=True)
            probe = path / ".write_test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            return path
        except OSError:
            continue
    raise RuntimeError("فضای ذخیره‌سازی قابل نوشتن پیدا نشد.")

DATA = choose_data_dir()
secret_file = DATA / "secret.key"
if secret_file.exists():
    secret = secret_file.read_text(encoding="utf-8").strip()
else:
    secret = secrets.token_urlsafe(48)
    secret_file.write_text(secret, encoding="utf-8")
    try:
        secret_file.chmod(0o600)
    except OSError:
        pass

os.environ["DORIA_ENV"] = "production"
os.environ["DORIA_SECRET_KEY"] = secret
os.environ["DORIA_DB_PATH"] = str(DATA / "doria.db")
os.environ["DORIA_UPLOAD_DIR"] = str(DATA / "uploads")
os.environ.setdefault("PORT", "8000")

def local_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("1.1.1.1", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()

if __name__ == "__main__":
    try:
        import uvicorn
        import main  # noqa: F401 - initializes the existing DORIA app
    except ImportError as exc:
        print("\nکتابخانه‌ای نصب نیست:", exc)
        print("در ترمینال Pydroid اجرا کن:")
        print("pip install -r requirements.txt")
        raise SystemExit(1)

    port = int(os.environ["PORT"])
    print("\n===================================")
    print("       DORIA HOST آماده اجراست")
    print("===================================")
    print("روی همین گوشی: http://127.0.0.1:" + str(port))
    print("در وای‌فای یکسان: http://" + local_ip() + ":" + str(port))
    print("محل ذخیره اطلاعات:", DATA)
    print("برای توقف سرور دکمه Stop را بزن.")
    print("\nنکته: برای دسترسی اینترنتی از بیرون خانه، این آدرس محلی کافی نیست.")
    uvicorn.run("main:app", host="0.0.0.0", port=port, log_level="info")
