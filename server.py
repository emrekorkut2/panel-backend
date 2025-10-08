# server.py
import os
import sqlite3
import mimetypes
import secrets
import uuid
import hashlib
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import Response
from passlib.context import CryptContext

# ================== Paths & Config ==================
BASE_DIR = Path(__file__).resolve().parent
DB_PATH    = Path(os.environ.get("DB_PATH",    str(BASE_DIR / "app.db")))
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", str(BASE_DIR / "uploads")))
TEMPLATE_DIR = BASE_DIR / "templates"
UPLOAD_DIR.mkdir(exist_ok=True)
TEMPLATE_DIR.mkdir(exist_ok=True)

SECRET_KEY    = os.environ.get("APP_SECRET", secrets.token_hex(32))
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "200"))

# SMTP (e-posta) — zorunlu (onboarding & reset için)
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "")
SMTP_STARTTLS = os.environ.get("SMTP_STARTTLS", "1") == "1"

# Dev/test: sabit token (opsiyonel)
DEV_GLOBAL_MEDIA_TOKEN = os.environ.get("MEDIA_TOKEN", "")

# ================== App & Security ==================
app = FastAPI(title="Media Panel — Single Tenant")
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie="mediacast_sid",
    same_site="lax",      # iframe kullanıyorsan "none" yap + https_only True kalsın
    https_only=True,      # Railway/HTTPS’te zorunlu
    max_age=60*60*24*30,  # 30 gün
    path="/",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

templates = Jinja2Templates(directory=str(TEMPLATE_DIR))

PWD_CTX = CryptContext(
    schemes=["argon2", "bcrypt_sha256", "pbkdf2_sha256", "bcrypt"],
    deprecated="auto",
)

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".bmp", ".gif", ".webp"}
VIDEO_EXTS = {".mp4", ".mov", ".m4v", ".avi", ".mkv", ".webm"}

def guess_media_type(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    if ext in IMAGE_EXTS: return "image"
    if ext in VIDEO_EXTS: return "video"
    mt, _ = mimetypes.guess_type(filename)
    if mt and mt.startswith("image/"): return "image"
    if mt and mt.startswith("video/"): return "video"
    return "image"

# ================== Email ==================
def send_email(to_addr: str, subject: str, body: str):
    if not (SMTP_HOST and SMTP_FROM and to_addr):
        raise RuntimeError("SMTP env vars missing")
    msg = EmailMessage()
    msg["From"] = SMTP_FROM
    msg["To"]   = to_addr
    msg["Subject"] = subject
    msg.set_content(body)
    if SMTP_STARTTLS:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.ehlo(); s.starttls(); s.login(SMTP_USER, SMTP_PASS); s.send_message(msg)
    else:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as s:
            s.login(SMTP_USER, SMTP_PASS); s.send_message(msg)

# ================== DB ==================
def db_conn():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def column_exists(cur, table: str, col: str) -> bool:
    cur.execute(f"PRAGMA table_info({table})")
    return any(r["name"] == col for r in cur.fetchall())

def init_db():
    con = db_conn(); cur = con.cursor()

    # Users
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            first_name TEXT,
            last_name  TEXT,
            country    TEXT,
            email      TEXT,
            email_verified INTEGER NOT NULL DEFAULT 0,
            first_login_completed INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
    """)
    for t, cols in {"users": ["first_name","last_name","country","email","email_verified","first_login_completed"]}.items():
        for c in cols:
            if not column_exists(cur, t, c):
                if c in ("email_verified","first_login_completed"):
                    cur.execute(f"ALTER TABLE {t} ADD COLUMN {c} INTEGER NOT NULL DEFAULT 0;")
                else:
                    cur.execute(f"ALTER TABLE {t} ADD COLUMN {c} TEXT;")

    # Verify/reset codes
    cur.execute("""
        CREATE TABLE IF NOT EXISTS user_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL,
            purpose  TEXT NOT NULL,  -- 'verify' | 'reset'
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    """)

    # Config
    cur.execute("""
        CREATE TABLE IF NOT EXISTS config (
            user_id INTEGER PRIMARY KEY,
            loop_all INTEGER NOT NULL DEFAULT 1,
            shuffle INTEGER NOT NULL DEFAULT 0,
            image_duration INTEGER NOT NULL DEFAULT 10,
            video_repeats INTEGER NOT NULL DEFAULT 2,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    """)

    # Media
    cur.execute("""
        CREATE TABLE IF NOT EXISTS media (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            original_name TEXT NOT NULL,
            media_type TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    """)

    # Device token (one per user)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_used_at TEXT
        );
    """)

    # Seed: 10 users + token
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        creds = []
        for i in range(1, 11):
            uname = f"user{i:02d}"
            alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
            pwd = "".join(secrets.choice(alphabet) for _ in range(10))
            pwd_hash = PWD_CTX.hash(pwd)
            cur.execute("INSERT INTO users(username, password_hash, created_at) VALUES (?,?,?)",
                        (uname, pwd_hash, datetime.utcnow().isoformat()))
            uid = cur.lastrowid
            cur.execute("INSERT OR IGNORE INTO config(user_id) VALUES (?)", (uid,))
            token_plain = secrets.token_urlsafe(24)
            token_hash  = hashlib.sha256(token_plain.encode()).hexdigest()
            cur.execute("""INSERT INTO api_tokens(user_id, name, token_hash, created_at)
                           VALUES (?,?,?,?)""",
                        (uid, "default-device", token_hash, datetime.utcnow().isoformat()))
            creds.append((uname, pwd, token_plain))

        print("\n[BOOT INFO] 10 kullanıcı + cihaz tokenları (yalnızca bu logda görünür):")
        for u, p, t in creds:
            print(f"  - {u}  |  password: {p}  |  device-token: {t}")
        print("İlk girişte onboarding → e-posta doğrulama yapılır.\n")

    con.commit(); con.close()

init_db()

# ================== Helpers ==================
def current_user(request: Request) -> Optional[sqlite3.Row]:
    uid = request.session.get("user_id")
    if not uid: return None
    con = db_conn(); cur = con.cursor()
    cur.execute("SELECT id, username, role, first_login_completed, email_verified FROM users WHERE id=?", (uid,))
    row = cur.fetchone(); con.close()
    return row

def require_login(request: Request) -> sqlite3.Row:
    u = current_user(request)
    if not u: raise HTTPException(status_code=302, detail="login required")
    return u

def ensure_csrf(request: Request, csrf_form_value: str):
    tok = request.session.get("csrf_token")
    if not tok or tok != csrf_form_value:
        raise HTTPException(status_code=400, detail="CSRF token invalid")

def get_or_set_csrf(request: Request) -> str:
    tok = request.session.get("csrf_token")
    if not tok:
        tok = secrets.token_urlsafe(16)
        request.session["csrf_token"] = tok
    return tok

def token_to_user_id(bearer: str) -> Optional[int]:
    if DEV_GLOBAL_MEDIA_TOKEN and bearer == DEV_GLOBAL_MEDIA_TOKEN:
        con = db_conn(); cur = con.cursor()
        cur.execute("SELECT id FROM users ORDER BY id ASC LIMIT 1")
        row = cur.fetchone(); con.close()
        return int(row["id"]) if row else None
    th = hashlib.sha256(bearer.encode()).hexdigest()
    con = db_conn(); cur = con.cursor()
    cur.execute("SELECT user_id FROM api_tokens WHERE token_hash=?", (th,))
    row = cur.fetchone(); con.close()
    return int(row["user_id"]) if row else None

def new_code(user_id: int, purpose: str, minutes: int = 15) -> str:
    code = f"{secrets.randbelow(10**6):06d}"
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    con = db_conn(); cur = con.cursor()
    cur.execute("DELETE FROM user_codes WHERE user_id=? AND purpose=?", (user_id, purpose))
    cur.execute("""INSERT INTO user_codes(user_id, code_hash, purpose, expires_at, created_at)
                   VALUES (?,?,?,?,?)""",
                (user_id, code_hash, purpose,
                 (datetime.utcnow()+timedelta(minutes=minutes)).isoformat(),
                 datetime.utcnow().isoformat()))
    con.commit(); con.close()
    return code

def verify_code(user_id: int, purpose: str, code: str) -> bool:
    con = db_conn(); cur = con.cursor()
    cur.execute("""SELECT id, code_hash, expires_at FROM user_codes
                   WHERE user_id=? AND purpose=? ORDER BY id DESC LIMIT 1""",
                (user_id, purpose))
    row = cur.fetchone()
    ok = False
    if row:
        if datetime.utcnow() <= datetime.fromisoformat(row["expires_at"]):
            ok = hashlib.sha256(code.encode()).hexdigest() == row["code_hash"]
        cur.execute("DELETE FROM user_codes WHERE id=?", (row["id"],))  # tek kullanımlık
        con.commit()
    con.close()
    return ok

# ================== Templates (ilk çalıştırmada yaz) ==================
LAYOUT_HTML = """
<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{{ title or 'Control Panel' }}</title>
<style>
:root{--bg:#0b1020;--fg:#e6edf3;--mut:#9aa4b2;--card:#0f172a;--line:#1f2a44;--soft:#0d1b2a;--acc:#22d3ee}
html,body{margin:0;background:var(--bg);color:var(--fg);font-family:ui-sans-serif,system-ui,Segoe UI,Roboto,Ubuntu,"Helvetica Neue",Arial}
.wrap{max-width:1000px;margin:0 auto;padding:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px;margin:14px 0;box-shadow:0 10px 20px rgba(0,0,0,.25)}
.row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
input,select,button{border-radius:12px;border:1px solid var(--line);background:var(--soft);color:var(--fg);padding:10px 12px}
button{cursor:pointer}
a{color:var(--acc);text-decoration:none}
table{width:100%;border-collapse:collapse}
th,td{border-bottom:1px solid var(--line);padding:10px;text-align:left}
.mut{color:var(--mut)}
.right{margin-left:auto}
</style></head><body><div class="wrap">
<h2 style="margin:0 0 12px">{{ title or 'Control Panel' }}</h2>
{% block content %}{% endblock %}
</div></body></html>
"""

LOGIN_HTML = """
{% extends 'layout.html' %}{% block content %}
<div class="card">
  <h3>Sign in</h3>
  <form method="post" action="/login" class="row">
    <div><div>Username</div><input name="username" required /></div>
    <div><div>Password</div><input type="password" name="password" required /></div>
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
    <div style="align-self:flex-end"><button>Sign in</button></div>
  </form>
  <p class="mut"><a href="/forgot">Forgot your password?</a></p>
</div>
{% endblock %}
"""

ONBOARD_HTML = """
{% extends 'layout.html' %}{% block content %}
<div class="card">
  <h3>Complete your profile (first time)</h3>
  <form method="post" action="/onboarding" class="row">
    <input type="text" name="first_name" placeholder="First name" required />
    <input type="text" name="last_name"  placeholder="Last name" required />
    <input type="text" name="country"    placeholder="Country" required />
    <input type="email" name="email"     placeholder="E-mail" required />
    <input type="password" name="new_password"  placeholder="New password" required />
    <input type="password" name="new_password2" placeholder="Confirm password" required />
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
    <button>Save & Send verification code</button>
  </form>
  <p class="mut">We sent a 6-digit code to your e-mail. Enter it on the next screen.</p>
</div>
{% endblock %}
"""

VERIFY_HTML = """
{% extends 'layout.html' %}{% block content %}
<div class="card">
  <h3>E-mail verification</h3>
  <form method="post" action="/verify" class="row">
    <input type="hidden" name="u" value="{{ username }}" />
    <input type="text" name="code" placeholder="6-digit code" pattern="\\d{6}" required />
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
    <button>Verify</button>
  </form>
  <form method="post" action="/verify/resend" class="row">
    <input type="hidden" name="u" value="{{ username }}" />
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
    <button>Resend code</button>
  </form>
</div>
{% endblock %}
"""

FORGOT_HTML = """
{% extends 'layout.html' %}{% block content %}
<div class="card">
  <h3>Reset password</h3>
  <form method="post" action="/forgot" class="row">
    <input type="text"  name="username" placeholder="Username" required />
    <input type="email" name="email"    placeholder="E-mail on file" required />
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
    <button>Send reset code</button>
  </form>
</div>
{% endblock %}
"""

RESET_HTML = """
{% extends 'layout.html' %}{% block content %}
<div class="card">
  <h3>Enter reset code</h3>
  <form method="post" action="/reset" class="row">
    <input type="hidden" name="u" value="{{ username }}" />
    <input type="text" name="code" placeholder="6-digit code" pattern="\\d{6}" required />
    <input type="password" name="new_password"  placeholder="New password" required />
    <input type="password" name="new_password2" placeholder="Confirm new password" required />
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
    <button>Change password</button>
  </form>
</div>
{% endblock %}
"""

INDEX_HTML = """
{% extends 'layout.html' %}{% block content %}
<div class="card" style="display:flex;justify-content:space-between;align-items:center">
  <div>Hello, <strong>{{ user.username }}</strong></div>
  <div class="row">
    <form method="post" action="/logout">
      <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
      <button>Logout</button>
    </form>
  </div>
</div>

<div class="card">
  <h3>Change Password</h3>
  <form method="post" action="/change_password" class="row">
    <input type="password" name="old_password" placeholder="Current password" required />
    <input type="password" name="new_password" placeholder="New password" required />
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
    <button>Update</button>
  </form>
</div>

<div class="card">
  <h3>Upload Media (Photo/Video)</h3>
  <form method="post" action="/upload" enctype="multipart/form-data" class="row">
    <input type="file" name="files" accept="image/*,video/*" multiple required />
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
    <button>Upload</button>
  </form>
  <p class="mut">Your device (token) will fetch only your own media.</p>
</div>

<div class="card">
  <h3>Playback Settings</h3>
  <form method="post" action="/config" class="row">
    <label>Loop all
      <select name="loop_all">
        <option value="1" {% if cfg.loop_all %}selected{% endif %}>On</option>
        <option value="0" {% if not cfg.loop_all %}selected{% endif %}>Off</option>
      </select>
    </label>
    <label>Shuffle
      <select name="shuffle">
        <option value="0" {% if not cfg.shuffle %}selected{% endif %}>Off</option>
        <option value="1" {% if cfg.shuffle %}selected{% endif %}>On</option>
      </select>
    </label>
    <label>Image seconds
      <input type="number" min="1" name="image_duration" value="{{ cfg.image_duration }}" />
    </label>
    <label>Video repeats
      <input type="number" min="1" name="video_repeats" value="{{ cfg.video_repeats }}" />
    </label>
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
    <button>Save</button>
  </form>
</div>

<div class="card">
  <h3>Device Token</h3>
  <form method="post" action="/token/reset" class="row">
    <span class="mut">Each user has exactly one device token.</span>
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}" />
    <button>Reset token (show once)</button>
  </form>
  <table>
    <thead><tr><th>Name</th><th>Created</th><th>Last used</th></tr></thead>
    <tbody>
      {% if token %}
      <tr><td>{{ token.name }}</td><td class="mut">{{ token.created_at }}</td><td class="mut">{{ token.last_used_at or '-' }}</td></tr>
      {% endif %}
    </tbody>
  </table>
</div>

<div class="card">
  <h3>Your Media</h3>
  <table>
    <thead><tr><th>ID</th><th>Preview</th><th>Type</th><th>Name</th><th>Date</th></tr></thead>
    <tbody>
    {% for m in media %}
      <tr>
        <td>{{ m.id }}</td>
        <td>
          {% if m.media_type == 'image' %}
            <img src="/panel/media/{{ m.filename }}" style="height:56px;border-radius:8px" />
          {% else %}
            <video src="/panel/media/{{ m.filename }}" style="height:56px;border-radius:8px" muted></video>
          {% endif %}
        </td>
        <td>{{ m.media_type }}</td>
        <td class="mut">{{ m.original_name }}</td>
        <td class="mut">{{ m.uploaded_at }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
{% endblock %}
"""

for name, content in {
    "layout.html": LAYOUT_HTML,
    "login.html": LOGIN_HTML,
    "index.html": INDEX_HTML,
    "onboard.html": ONBOARD_HTML,
    "verify.html": VERIFY_HTML,
    "forgot.html": FORGOT_HTML,
    "reset.html": RESET_HTML,
}.items():
    p = TEMPLATE_DIR / name
    if not p.exists():
        p.write_text(content, encoding="utf-8")

# ================== Security headers ==================
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    resp: Response = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
    return resp

# ================== Routes ==================
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    user = current_user(request)
    if not user:
        csrf_token = get_or_set_csrf(request)
        return templates.TemplateResponse("login.html", {"request": request, "title": "Sign in", "csrf_token": csrf_token})

    # onboarding/verify bitmeden panele alınmaz
    if not (user["first_login_completed"] and user["email_verified"]):
        return RedirectResponse(url="/onboarding", status_code=302)

    con = db_conn(); cur = con.cursor()
    cur.execute("SELECT id, filename, original_name, media_type, uploaded_at FROM media WHERE user_id=? ORDER BY uploaded_at DESC", (user["id"],))
    rows = cur.fetchall()
    cur.execute("SELECT loop_all, shuffle, image_duration, video_repeats FROM config WHERE user_id=?", (user["id"],))
    cfg_row = cur.fetchone()
    cur.execute("SELECT name, created_at, last_used_at FROM api_tokens WHERE user_id=?", (user["id"],))
    tok = cur.fetchone()
    con.close()

    media = [{"id": r["id"], "filename": r["filename"], "original_name": r["original_name"], "media_type": r["media_type"], "uploaded_at": r["uploaded_at"]} for r in rows]
    cfg = {"loop_all": bool(cfg_row[0]) if cfg_row else True,
           "shuffle": bool(cfg_row[1]) if cfg_row else False,
           "image_duration": int(cfg_row[2]) if cfg_row else 10,
           "video_repeats": int(cfg_row[3]) if cfg_row else 2}

    csrf_token = get_or_set_csrf(request)
    return templates.TemplateResponse("index.html", {"request": request, "user": user, "media": media, "cfg": cfg, "token": tok, "csrf_token": csrf_token, "title": "Control Panel"})

# ---- Debug: session kontrol
@app.get("/whoami")
def whoami(request: Request):
    return {"session": dict(request.session)}

# ---- Auth ----
@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...), csrf_token: str = Form("")):
    ensure_csrf(request, csrf_token)
    con = db_conn(); cur = con.cursor()
    cur.execute("SELECT id, username, role, password_hash FROM users WHERE username=?", (username.strip(),))
    row = cur.fetchone(); con.close()
    if row and PWD_CTX.verify(password, row["password_hash"]):
        request.session["user_id"] = int(row["id"])
        return RedirectResponse(url="/", status_code=302)
    return RedirectResponse(url="/", status_code=302)

@app.post("/logout")
async def logout(request: Request, csrf_token: str = Form("")):
    ensure_csrf(request, csrf_token)
    request.session.clear()
    return RedirectResponse(url="/", status_code=302)

# ---- First-time onboarding + verify ----
@app.get("/onboarding", response_class=HTMLResponse)
async def onboarding_get(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/", 302)
    csrf_token = get_or_set_csrf(request)
    return templates.TemplateResponse("onboard.html", {"request": request, "csrf_token": csrf_token, "title": "Onboarding"})

@app.post("/onboarding")
async def onboarding_post(request: Request,
                          first_name: str = Form(...), last_name: str = Form(...),
                          country: str = Form(...), email: str = Form(...),
                          new_password: str = Form(...), new_password2: str = Form(...),
                          csrf_token: str = Form("")):
    user = require_login(request); ensure_csrf(request, csrf_token)
    if new_password != new_password2:
        return RedirectResponse("/onboarding", 302)
    con = db_conn(); cur = con.cursor()
    cur.execute("""UPDATE users SET first_name=?, last_name=?, country=?, email=?,
                   password_hash=?, first_login_completed=1 WHERE id=?""",
                (first_name.strip(), last_name.strip(), country.strip(), email.strip(),
                 PWD_CTX.hash(new_password), user["id"]))
    con.commit(); con.close()

    code = new_code(user["id"], "verify", minutes=15)
    try:
        send_email(email.strip(), "Your verification code",
                   f"Your verification code is: {code}\nThis code expires in 15 minutes.")
    except Exception as e:
        print("EMAIL ERROR:", e)
    csrf = get_or_set_csrf(request)
    return templates.TemplateResponse("verify.html", {"request": request, "csrf_token": csrf, "username": user["username"], "title": "Verify"})

@app.post("/verify")
async def verify_post(request: Request, u: str = Form(...), code: str = Form(...), csrf_token: str = Form("")):
    user = require_login(request); ensure_csrf(request, csrf_token)
    if user["username"] != u:
        return RedirectResponse("/onboarding", 302)
    ok = verify_code(user["id"], "verify", code.strip())
    if ok:
        con = db_conn(); cur = con.cursor()
        cur.execute("UPDATE users SET email_verified=1 WHERE id=?", (user["id"],))
        con.commit(); con.close()
        return RedirectResponse("/", 302)
    return RedirectResponse("/onboarding", 302)

@app.post("/verify/resend")
async def verify_resend(request: Request, u: str = Form(...), csrf_token: str = Form("")):
    user = require_login(request); ensure_csrf(request, csrf_token)
    if user["username"] != u:
        return RedirectResponse("/onboarding", 302)
    con = db_conn(); cur = con.cursor()
    cur.execute("SELECT email FROM users WHERE id=?", (user["id"],))
    row = cur.fetchone(); con.close()
    email = row["email"] if row else None
    if not email:
        return RedirectResponse("/onboarding", 302)
    code = new_code(user["id"], "verify", minutes=15)
    try:
        send_email(email, "Your verification code",
                   f"Your verification code is: {code}\nThis code expires in 15 minutes.")
    except Exception as e:
        print("EMAIL ERROR:", e)
    return RedirectResponse("/onboarding", 302)

# ---- Forgot/reset password ----
@app.get("/forgot", response_class=HTMLResponse)
async def forgot_get(request: Request):
    csrf = get_or_set_csrf(request)
    return templates.TemplateResponse("forgot.html", {"request": request, "csrf_token": csrf, "title": "Forgot password"})

@app.post("/forgot")
async def forgot_post(request: Request, username: str = Form(...), email: str = Form(...), csrf_token: str = Form("")):
    ensure_csrf(request, csrf_token)
    con = db_conn(); cur = con.cursor()
    cur.execute("SELECT id, email FROM users WHERE username=?", (username.strip(),))
    row = cur.fetchone()
    if not row or not row["email"] or row["email"].strip().lower() != email.strip().lower():
        con.close();  return RedirectResponse("/forgot", 302)
    uid = int(row["id"])
    code = new_code(uid, "reset", minutes=15)
    try:
        send_email(email.strip(), "Password reset code",
                   f"Your reset code is: {code}\nThis code expires in 15 minutes.")
    except Exception as e:
        print("EMAIL ERROR:", e)
    con.close()
    csrf = get_or_set_csrf(request)
    return templates.TemplateResponse("reset.html", {"request": request, "csrf_token": csrf, "username": username.strip(), "title": "Reset"})

@app.post("/reset")
async def reset_post(request: Request, u: str = Form(...), code: str = Form(...),
                     new_password: str = Form(...), new_password2: str = Form(...),
                     csrf_token: str = Form("")):
    ensure_csrf(request, csrf_token)
    if new_password != new_password2:
        return RedirectResponse("/forgot", 302)
    con = db_conn(); cur = con.cursor()
    cur.execute("SELECT id FROM users WHERE username=?", (u.strip(),))
    row = cur.fetchone()
    if not row:
        con.close(); return RedirectResponse("/forgot", 302)
    uid = int(row["id"])
    if not verify_code(uid, "reset", code.strip()):
        return RedirectResponse("/forgot", 302)
    cur.execute("UPDATE users SET password_hash=? WHERE id=?", (PWD_CTX.hash(new_password), uid))
    con.commit(); con.close()
    return RedirectResponse("/", 302)

# ---- Panel işlemleri ----
@app.post("/change_password")
async def change_password(request: Request, old_password: str = Form(...), new_password: str = Form(...), csrf_token: str = Form("")):
    user = require_login(request); ensure_csrf(request, csrf_token)
    con = db_conn(); cur = con.cursor()
    cur.execute("SELECT password_hash FROM users WHERE id=?", (user["id"],))
    row = cur.fetchone()
    if not row or not PWD_CTX.verify(old_password, row["password_hash"]):
        con.close(); return RedirectResponse("/", 302)
    cur.execute("UPDATE users SET password_hash=? WHERE id=?", (PWD_CTX.hash(new_password), user["id"]))
    con.commit(); con.close()
    return RedirectResponse("/", 302)

@app.post("/upload")
async def upload(request: Request, files: list[UploadFile] = File(...), csrf_token: str = Form("")):
    user = require_login(request); ensure_csrf(request, csrf_token)
    con = db_conn(); cur = con.cursor()
    for f in files:
        ext = Path(f.filename).suffix.lower()
        if ext not in IMAGE_EXTS | VIDEO_EXTS:
            continue
        new_name = f"{uuid.uuid4().hex}{ext}"
        dest = UPLOAD_DIR / new_name
        written = 0
        with dest.open("wb") as out:
            while True:
                chunk = await f.read(1024 * 1024)
                if not chunk: break
                written += len(chunk)
                if written > MAX_UPLOAD_MB * 1024 * 1024:
                    out.close(); dest.unlink(missing_ok=True)
                    raise HTTPException(status_code=413, detail="File too large")
                out.write(chunk)
        media_type = guess_media_type(new_name)
        cur.execute("""INSERT INTO media(user_id, filename, original_name, media_type, uploaded_at)
                       VALUES (?,?,?,?,?)""",
                    (user["id"], new_name, f.filename, media_type, datetime.utcnow().isoformat()))
    con.commit(); con.close()
    return RedirectResponse(url="/", status_code=302)

@app.post("/config")
async def set_config(request: Request, loop_all: int = Form(1), shuffle: int = Form(0),
                     image_duration: int = Form(10), video_repeats: int = Form(2),
                     csrf_token: str = Form("")):
    user = require_login(request); ensure_csrf(request, csrf_token)
    con = db_conn(); cur = con.cursor()
    cur.execute("""
        INSERT INTO config(user_id, loop_all, shuffle, image_duration, video_repeats)
        VALUES (?,?,?,?,?)
        ON CONFLICT(user_id) DO UPDATE SET
          loop_all=excluded.loop_all,
          shuffle=excluded.shuffle,
          image_duration=excluded.image_duration,
          video_repeats=excluded.video_repeats
    """, (user["id"], int(loop_all), int(shuffle), int(image_duration), int(video_repeats)))
    con.commit(); con.close()
    return RedirectResponse(url="/", status_code=302)

@app.post("/token/reset")
async def reset_token(request: Request, csrf_token: str = Form("")):
    user = require_login(request); ensure_csrf(request, csrf_token)
    token_plain = secrets.token_urlsafe(24)
    token_hash  = hashlib.sha256(token_plain.encode()).hexdigest()
    con = db_conn(); cur = con.cursor()
    cur.execute("SELECT 1 FROM api_tokens WHERE user_id=?", (user["id"],))
    if cur.fetchone():
        cur.execute("UPDATE api_tokens SET token_hash=?, created_at=?, last_used_at=NULL WHERE user_id=?",
                    (token_hash, datetime.utcnow().isoformat(), user["id"]))
    else:
        cur.execute("""INSERT INTO api_tokens(user_id, name, token_hash, created_at)
                       VALUES (?,?,?,?)""",
                    (user["id"], "default-device", token_hash, datetime.utcnow().isoformat()))
    con.commit(); con.close()
    return PlainTextResponse(f"NEW DEVICE TOKEN (show once):\n{token_plain}")

# ---- Panel içi medya (login gerekli)
@app.get("/panel/media/{filename}")
async def panel_media(filename: str, request: Request):
    user = require_login(request)
    con = db_conn(); cur = con.cursor()
    cur.execute("SELECT 1 FROM media WHERE user_id=? AND filename=?", (user["id"], filename))
    ok = cur.fetchone(); con.close()
    if not ok: raise HTTPException(status_code=404)
    fp = UPLOAD_DIR / filename
    if not fp.exists(): raise HTTPException(status_code=404)
    return FileResponse(fp)

# ================== Device API ==================
def _auth_bearer(request: Request) -> int:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="token required")
    token = auth[7:].strip()
    uid = token_to_user_id(token)
    if not uid: raise HTTPException(status_code=401, detail="invalid token")
    return uid

@app.get("/api/playlist")
async def api_playlist(request: Request):
    user_id = _auth_bearer(request)
    con = db_conn(); cur = con.cursor()
    cur.execute("SELECT id, filename, media_type FROM media WHERE user_id=? ORDER BY uploaded_at ASC", (user_id,))
    rows = cur.fetchall()
    cur.execute("SELECT loop_all, shuffle, image_duration, video_repeats FROM config WHERE user_id=?", (user_id,))
    cfg_row = cur.fetchone()
    con.close()
    items = [{"id": r["id"], "url": f"/api/media/{r['filename']}", "media_type": r["media_type"], "filename": r["filename"]} for r in rows]
    cfg = {"loop_all": bool(cfg_row[0]) if cfg_row else True,
           "shuffle": bool(cfg_row[1]) if cfg_row else False,
           "image_duration": int(cfg_row[2]) if cfg_row else 10,
           "video_repeats": int(cfg_row[3]) if cfg_row else 2}
    return JSONResponse({"items": items, "config": cfg})

@app.get("/api/media/{filename}")
async def api_media(filename: str, request: Request):
    user_id = _auth_bearer(request)
    con = db_conn(); cur = con.cursor()
    cur.execute("SELECT 1 FROM media WHERE user_id=? AND filename=?", (user_id, filename))
    ok = cur.fetchone()
    if ok:
        cur.execute("UPDATE api_tokens SET last_used_at=? WHERE user_id=?",
                    (datetime.utcnow().isoformat(), user_id))
    con.commit(); con.close()
    if not ok: raise HTTPException(status_code=404)
    fp = UPLOAD_DIR / filename
    if not fp.exists(): raise HTTPException(status_code=404)
    return FileResponse(fp)

# ================== Health ==================
@app.get("/health")
async def health():
    return {"ok": True}

# ================== Template bootstrap (eksikse yaz) ==================
for name, content in {
    "layout.html": LAYOUT_HTML,
    "login.html": LOGIN_HTML,
    "index.html": INDEX_HTML,
    "onboard.html": ONBOARD_HTML,
    "verify.html": VERIFY_HTML,
    "forgot.html": FORGOT_HTML,
    "reset.html": RESET_HTML,
}.items():
    p = TEMPLATE_DIR / name
    if not p.exists():
        p.write_text(content, encoding="utf-8")
