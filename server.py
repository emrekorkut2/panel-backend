import os
import sqlite3
import mimetypes
import secrets
import uuid
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException, status, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import Response
from passlib.context import CryptContext

# ----------------- Paths & Config -----------------
BASE_DIR = Path(__file__).resolve().parent
DB_PATH    = Path(os.environ.get("DB_PATH",    str(BASE_DIR / "app.db")))
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", str(BASE_DIR / "uploads")))
TEMPLATE_DIR = BASE_DIR / "templates"
UPLOAD_DIR.mkdir(exist_ok=True)
TEMPLATE_DIR.mkdir(exist_ok=True)

DB_PATH = BASE_DIR / "app.db"
SECRET_KEY = os.environ.get("APP_SECRET", secrets.token_hex(32))
BASE_DOMAIN = os.environ.get("BASE_DOMAIN", "")  
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "200"))

DEV_GLOBAL_MEDIA_TOKEN = os.environ.get("MEDIA_TOKEN", "")

# ----------------- App -----------------
app = FastAPI(title="Multi-tenant Media Panel (Secure)")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="lax", https_only=False)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

templates = Jinja2Templates(directory=str(TEMPLATE_DIR))

# ----------------- Security -----------------
PWD_CTX = CryptContext(
    schemes=["argon2", "bcrypt_sha256", "pbkdf2_sha256", "bcrypt"],
    deprecated="auto",
)

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".bmp", ".gif", ".webp"}
VIDEO_EXTS = {".mp4", ".mov", ".m4v", ".avi", ".mkv", ".webm"}


def guess_media_type(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    if ext in IMAGE_EXTS:
        return "image"
    if ext in VIDEO_EXTS:
        return "video"
    mt, _ = mimetypes.guess_type(filename)
    if mt and mt.startswith("image/"):
        return "image"
    if mt and mt.startswith("video/"):
        return "video"
    return "image"

# ----------------- DB -----------------

def db_conn():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db():
    con = db_conn()
    cur = con.cursor()

    # --- şemalar ---
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tenants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            email TEXT,
            role TEXT NOT NULL DEFAULT 'admin', -- owner|admin|viewer
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(tenant_id, username),
            FOREIGN KEY(tenant_id) REFERENCES tenants(id)
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS media (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            user_id INTEGER,
            filename TEXT NOT NULL,
            original_name TEXT NOT NULL,
            media_type TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY(tenant_id) REFERENCES tenants(id)
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS config (
            tenant_id INTEGER PRIMARY KEY,
            loop_all INTEGER NOT NULL DEFAULT 1,
            shuffle INTEGER NOT NULL DEFAULT 0,
            image_duration INTEGER NOT NULL DEFAULT 10,
            video_repeats INTEGER NOT NULL DEFAULT 2,
            FOREIGN KEY(tenant_id) REFERENCES tenants(id)
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL, -- SHA-256
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            UNIQUE(tenant_id, token_hash),
            FOREIGN KEY(tenant_id) REFERENCES tenants(id)
        );
    """)

    # --- bootstrap DEMO (idempotent) ---
    # tenant: varsa al, yoksa oluştur
    cur.execute("SELECT id FROM tenants WHERE slug='demo'")
    row = cur.fetchone()
    if row:
        tenant_id = row[0]
    else:
        cur.execute(
            "INSERT INTO tenants(slug, name, created_at) VALUES (?,?,?)",
            ("demo", "Demo Tenant", datetime.utcnow().isoformat()),
        )
        tenant_id = cur.lastrowid

    # config: yoksa oluştur (UNIQUE ihlali olmaz)
    cur.execute("INSERT OR IGNORE INTO config(tenant_id) VALUES (?)", (tenant_id,))

    # admin kullanıcı: yoksa ekle
    cur.execute(
        "SELECT 1 FROM users WHERE tenant_id=? AND username=?",
        (tenant_id, "admin"),
    )
    if not cur.fetchone():
        admin_hash = PWD_CTX.hash("admin123")
        cur.execute(
            "INSERT INTO users(tenant_id, username, email, role, password_hash, created_at) VALUES (?,?,?,?,?,?)",
            (tenant_id, "admin", "admin@demo.local", "owner", admin_hash, datetime.utcnow().isoformat()),
        )

    # en az bir cihaz token'ı olsun; yoksa üret ve konsola bir kez yaz
    cur.execute("SELECT 1 FROM api_tokens WHERE tenant_id=? LIMIT 1", (tenant_id,))
    if not cur.fetchone():
        boot_token = secrets.token_urlsafe(24)
        cur.execute(
            "INSERT INTO api_tokens(tenant_id, name, token_hash, created_at) VALUES (?,?,?,?)",
            (tenant_id, "default-device", hashlib.sha256(boot_token.encode()).hexdigest(), datetime.utcnow().isoformat()),
        )
        print("\n[BOOT INFO] Demo tenant: slug=demo | login: admin / admin123")
        print("[BOOT INFO] Demo device token (show once):", boot_token, "\n")

    con.commit()
    con.close()

init_db()

# ----------------- Helpers -----------------

def get_tenant_by_slug(slug: str) -> Optional[sqlite3.Row]:
    con = db_conn()
    cur = con.cursor()
    cur.execute("SELECT * FROM tenants WHERE slug=?", (slug,))
    row = cur.fetchone()
    con.close()
    return row


def resolve_tenant_from_host(host: str) -> Optional[str]:
    # host: slug.base-domain
    if not BASE_DOMAIN:
        return None
    host = (host or "").split(":")[0].lower()
    base = BASE_DOMAIN.lower()
    if host.endswith(base):
        sub = host[:-len(base)].rstrip(".")
        if sub and sub not in {"www", "panel"}:
            return sub
    return None


def require_login(request: Request) -> dict:
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=302, detail="login required")
    return user


def ensure_csrf(request: Request, csrf_form_value: str):
    sess_token = request.session.get("csrf_token")
    if not sess_token or not csrf_form_value or sess_token != csrf_form_value:
        raise HTTPException(status_code=400, detail="CSRF token invalid")


def get_or_set_csrf(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(16)
        request.session["csrf_token"] = token
    return token


def token_to_tenant_id(bearer: str) -> Optional[int]:
    if DEV_GLOBAL_MEDIA_TOKEN and bearer == DEV_GLOBAL_MEDIA_TOKEN:
        # dev override; not recommended in prod
        con = db_conn(); cur = con.cursor()
        cur.execute("SELECT id FROM tenants WHERE slug='demo'")
        row = cur.fetchone(); con.close()
        return row[0] if row else None
    th = hashlib.sha256(bearer.encode()).hexdigest()
    con = db_conn(); cur = con.cursor()
    cur.execute("SELECT tenant_id FROM api_tokens WHERE token_hash=?", (th,))
    row = cur.fetchone(); con.close()
    return row[0] if row else None


# ----------------- Templates (first-run writer) -----------------
LAYOUT_HTML = """
<!doctype html>
<html lang=\"tr\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>{{ title or 'Panel' }}</title>
  <style>
    :root { --bg:#0f172a; --fg:#e2e8f0; --muted:#94a3b8; --acc:#22d3ee; }
    html,body{margin:0;padding:0;background:var(--bg);color:var(--fg);font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,\"Helvetica Neue\",sans-serif}
    .wrap{max-width:960px;margin:0 auto;padding:24px}
    a{color:var(--acc);text-decoration:none}
    .card{background:#0b1220;border:1px solid #0b2545;border-radius:16px;padding:16px;margin:12px 0;box-shadow:0 10px 16px rgba(0,0,0,.25)}
    .row{display:flex;gap:12px;flex-wrap:wrap}
    input,select,button{border-radius:12px;border:1px solid #1f2a44;background:#0d1b2a;color:var(--fg);padding:10px 12px}
    button{cursor:pointer}
    table{width:100%;border-collapse:collapse}
    th,td{border-bottom:1px solid #203047;padding:8px;text-align:left}
    .muted{color:var(--muted)}
  </style>
</head>
<body>
  <div class=\"wrap\">
    <h2 style=\"margin:0 0 12px\">{{ title or 'Panel' }}</h2>
    {% block content %}{% endblock %}
  </div>
</body>
</html>
"""

LOGIN_HTML = """
{% extends 'layout.html' %}
{% block content %}
  <div class=\"card\">
    <form method=\"post\" action=\"/login\" class=\"row\">
      <div>
        <div>Müşteri (slug)</div>
        <input name=\"tenant\" placeholder=\"ornekfirma\" required />
      </div>
      <div>
        <div>Kullanıcı Adı</div>
        <input name=\"username\" required />
      </div>
      <div>
        <div>Şifre</div>
        <input type=\"password\" name=\"password\" required />
      </div>
      <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token }}\" />
      <div style=\"align-self:flex-end\"><button>Giriş Yap</button></div>
    </form>
    <p class=\"muted\">Demo: tenant <code>demo</code> | kullanıcı <code>admin</code> | şifre <code>admin123</code></p>
  </div>
{% endblock %}
"""

INDEX_HTML = """
{% extends 'layout.html' %}
{% block content %}
  <div class=\"card\" style=\"display:flex;justify-content:space-between;align-items:center\">
    <div>Merhaba, <strong>{{ user.username }}</strong> — <span class=\"muted\">{{ tenant.slug }}</span></div>
    <div class=\"row\">
      <form method=\"post\" action=\"/logout\"><input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token }}\" /><button>Çıkış</button></form>
    </div>
  </div>

  <div class=\"card\">
    <h3>Şifre Değiştir</h3>
    <form method=\"post\" action=\"/change_password\" class=\"row\">
      <input type=\"password\" name=\"old_password\" placeholder=\"Eski şifre\" required />
      <input type=\"password\" name=\"new_password\" placeholder=\"Yeni şifre\" required />
      <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token }}\" />
      <button>Güncelle</button>
    </form>
  </div>

  <div class=\"card\">
    <h3>Medya Yükle (Foto/Video)</h3>
    <form method=\"post\" action=\"/upload\" enctype=\"multipart/form-data\" class=\"row\">
      <input type=\"file\" name=\"files\" accept=\"image/*,video/*\" multiple required />
      <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token }}\" />
      <button>Yükle</button>
    </form>
    <p class=\"muted\">Yüklenenler sadece bu müşteriye aittir. Raspberry Pi cihazları **Bearer Token** ile erişir.</p>
  </div>

  <div class=\"card\">
    <h3>Oynatma Ayarları</h3>
    <form method=\"post\" action=\"/config\" class=\"row\">
      <label>Hepsi sırayla dönsün (loop)
        <select name=\"loop_all\">
          <option value=\"1\" {% if cfg.loop_all %}selected{% endif %}>Açık</option>
          <option value=\"0\" {% if not cfg.loop_all %}selected{% endif %}>Kapalı</option>
        </select>
      </label>
      <label>Karıştır (shuffle)
        <select name=\"shuffle\">
          <option value=\"0\" {% if not cfg.shuffle %}selected{% endif %}>Kapalı</option>
          <option value=\"1\" {% if cfg.shuffle %}selected{% endif %}>Açık</option>
        </select>
      </label>
      <label>Resim süresi (sn)
        <input type=\"number\" min=\"1\" name=\"image_duration\" value=\"{{ cfg.image_duration }}\" />
      </label>
      <label>Videoyu tekrar sayısı
        <input type=\"number\" min=\"1\" name=\"video_repeats\" value=\"{{ cfg.video_repeats }}\" />
      </label>
      <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token }}\" />
      <button>Kaydet</button>
    </form>
  </div>

  <div class=\"card\">
    <h3>Cihaz Tokenları</h3>
    <form method=\"post\" action=\"/tokens/new\" class=\"row\">
      <input name=\"name\" placeholder=\"token adı (örn: vitrin-raspi)\" required />
      <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token }}\" />
      <button>Yeni Token Oluştur</button>
    </form>
    <table>
      <thead><tr><th>Ad</th><th>Oluşturma</th><th>Son Kullanım</th></tr></thead>
      <tbody>
      {% for t in tokens %}
        <tr><td>{{ t.name }}</td><td class=\"muted\">{{ t.created_at }}</td><td class=\"muted\">{{ t.last_used_at or '-' }}</td></tr>
      {% endfor %}
      </tbody>
    </table>
  </div>

  <div class=\"card\">
    <h3>Yüklenen Medyalar</h3>
    <table>
      <thead><tr><th>ID</th><th>Önizleme</th><th>Tip</th><th>Ad</th><th>Tarih</th></tr></thead>
      <tbody>
      {% for m in media %}
        <tr>
          <td>{{ m.id }}</td>
          <td>
            {% if m.media_type == 'image' %}
              <img src=\"/panel/media/{{ m.filename }}\" style=\"height:56px;border-radius:8px\" />
            {% else %}
              <video src=\"/panel/media/{{ m.filename }}\" style=\"height:56px;border-radius:8px\" muted></video>
            {% endif %}
          </td>
          <td>{{ m.media_type }}</td>
          <td class=\"muted\">{{ m.original_name }}</td>
          <td class=\"muted\">{{ m.uploaded_at }}</td>
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
}.items():
    p = TEMPLATE_DIR / name
    if not p.exists():
        p.write_text(content, encoding="utf-8")

# ----------------- Middleware: Security Headers -----------------
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    resp: Response = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
    return resp

# ----------------- Routes -----------------
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    # tenant belirleme: hosttan ya da login sonrası sessiondan
    tenant_slug = resolve_tenant_from_host(request.headers.get("host"))
    user = request.session.get("user")
    if not user:
        csrf_token = get_or_set_csrf(request)
        return templates.TemplateResponse("login.html", {"request": request, "title": "Giriş", "csrf_token": csrf_token})

    con = db_conn(); cur = con.cursor()
    cur.execute("SELECT * FROM tenants WHERE id=?", (user["tenant_id"],))
    tenant = cur.fetchone()
    cur.execute("SELECT id, filename, original_name, media_type, uploaded_at FROM media WHERE tenant_id=? ORDER BY uploaded_at DESC", (user["tenant_id"],))
    rows = cur.fetchall()
    cur.execute("SELECT loop_all, shuffle, image_duration, video_repeats FROM config WHERE tenant_id=?", (user["tenant_id"],))
    cfg_row = cur.fetchone()
    cur.execute("SELECT name, created_at, last_used_at FROM api_tokens WHERE tenant_id=? ORDER BY created_at DESC", (user["tenant_id"],))
    tokens = cur.fetchall()
    con.close()

    media = [{"id": r["id"], "filename": r["filename"], "original_name": r["original_name"], "media_type": r["media_type"], "uploaded_at": r["uploaded_at"]} for r in rows]
    cfg = {"loop_all": bool(cfg_row[0]), "shuffle": bool(cfg_row[1]), "image_duration": int(cfg_row[2]), "video_repeats": int(cfg_row[3])}

    csrf_token = get_or_set_csrf(request)
    return templates.TemplateResponse("index.html", {"request": request, "user": user, "tenant": tenant, "media": media, "cfg": cfg, "tokens": tokens, "csrf_token": csrf_token, "title": "Kontrol Paneli"})


@app.post("/login")
async def login(request: Request, tenant: str = Form(...), username: str = Form(...), password: str = Form(...), csrf_token: str = Form("")):
    ensure_csrf(request, csrf_token)
    tenant = tenant.strip().lower()
    con = db_conn(); cur = con.cursor()
    cur.execute("SELECT id, slug, name FROM tenants WHERE slug=?", (tenant,))
    t = cur.fetchone()
    if not t:
        con.close(); return RedirectResponse(url="/", status_code=302)
    cur.execute("SELECT id, username, role, password_hash FROM users WHERE tenant_id=? AND username=?", (t["id"], username))
    row = cur.fetchone(); con.close()
    if row and PWD_CTX.verify(password, row["password_hash"]):
        request.session["user"] = {"id": row["id"], "username": row["username"], "role": row["role"], "tenant_id": t["id"], "tenant_slug": t["slug"]}
        return RedirectResponse(url="/", status_code=302)
    return RedirectResponse(url="/", status_code=302)


@app.post("/logout")
async def logout(request: Request, csrf_token: str = Form("")):
    ensure_csrf(request, csrf_token)
    request.session.clear()
    return RedirectResponse(url="/", status_code=302)


@app.post("/change_password")
async def change_password(request: Request, old_password: str = Form(...), new_password: str = Form(...), csrf_token: str = Form("")):
    user = require_login(request)
    ensure_csrf(request, csrf_token)
    con = db_conn(); cur = con.cursor()
    cur.execute("SELECT password_hash FROM users WHERE id=? AND tenant_id=?", (user["id"], user["tenant_id"]))
    row = cur.fetchone()
    if not row or not PWD_CTX.verify(old_password, row["password_hash"]):
        con.close(); return RedirectResponse(url="/", status_code=302)
    new_hash = PWD_CTX.hash(new_password)
    cur.execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, user["id"]))
    con.commit(); con.close()
    return RedirectResponse(url="/", status_code=302)


@app.post("/upload")
async def upload(request: Request, files: list[UploadFile] = File(...), csrf_token: str = Form("")):
    user = require_login(request)
    ensure_csrf(request, csrf_token)
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
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_UPLOAD_MB * 1024 * 1024:
                    out.close(); dest.unlink(missing_ok=True)
                    raise HTTPException(status_code=413, detail="Dosya çok büyük")
                out.write(chunk)
        media_type = guess_media_type(new_name)
        cur.execute(
            "INSERT INTO media(tenant_id, user_id, filename, original_name, media_type, uploaded_at) VALUES (?,?,?,?,?,?)",
            (user["tenant_id"], user["id"], new_name, f.filename, media_type, datetime.utcnow().isoformat()),
        )
    con.commit(); con.close()
    return RedirectResponse(url="/", status_code=302)


@app.post("/config")
async def set_config(request: Request, loop_all: int = Form(1), shuffle: int = Form(0), image_duration: int = Form(10), video_repeats: int = Form(2), csrf_token: str = Form("")):
    user = require_login(request)
    ensure_csrf(request, csrf_token)
    con = db_conn(); cur = con.cursor()
    cur.execute(
        "INSERT INTO config(tenant_id, loop_all, shuffle, image_duration, video_repeats) VALUES (?,?,?,?,?)\n         ON CONFLICT(tenant_id) DO UPDATE SET loop_all=excluded.loop_all, shuffle=excluded.shuffle, image_duration=excluded.image_duration, video_repeats=excluded.video_repeats",
        (user["tenant_id"], int(loop_all), int(shuffle), int(image_duration), int(video_repeats)),
    )
    con.commit(); con.close()
    return RedirectResponse(url="/", status_code=302)


# --------- Token Yönetimi (panel) ---------
@app.post("/tokens/new")
async def new_token(request: Request, name: str = Form(...), csrf_token: str = Form("")):
    user = require_login(request)
    ensure_csrf(request, csrf_token)
    if user.get("role") not in {"owner", "admin"}:
        raise HTTPException(status_code=403, detail="yetki yok")
    token_plain = secrets.token_urlsafe(24)
    token_hash = hashlib.sha256(token_plain.encode()).hexdigest()
    con = db_conn(); cur = con.cursor()
    cur.execute("INSERT INTO api_tokens(tenant_id, name, token_hash, created_at) VALUES (?,?,?,?)",
                (user["tenant_id"], name.strip(), token_hash, datetime.utcnow().isoformat()))
    con.commit(); con.close()
    # Tokenı sadece 1 kere göster
    return PlainTextResponse(f"Yeni token (bir kez gösterilir):\n{token_plain}")


# --------- Panel içi medya görüntüleme (giriş gerekli) ---------
@app.get("/panel/media/{filename}")
async def panel_media(filename: str, request: Request):
    user = require_login(request)
    # Dosya var mı ve bu tenant'a mı ait?
    con = db_conn(); cur = con.cursor()
    cur.execute("SELECT 1 FROM media WHERE tenant_id=? AND filename=?", (user["tenant_id"], filename))
    ok = cur.fetchone(); con.close()
    if not ok:
        raise HTTPException(status_code=404)
    fp = UPLOAD_DIR / filename
    if not fp.exists():
        raise HTTPException(status_code=404)
    return FileResponse(fp)


# --------- Device API: playlist + dosya indirme ---------

def _auth_bearer(request: Request) -> int:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Token gerekli")
    token = auth[7:].strip()
    tenant_id = token_to_tenant_id(token)
    if not tenant_id:
        raise HTTPException(status_code=401, detail="Token geçersiz")
    return tenant_id


@app.get("/api/playlist")
async def api_playlist(request: Request):
    tenant_id = _auth_bearer(request)
    con = db_conn(); cur = con.cursor()
    cur.execute("SELECT id, filename, media_type FROM media WHERE tenant_id=? ORDER BY uploaded_at ASC", (tenant_id,))
    rows = cur.fetchall()
    cur.execute("SELECT loop_all, shuffle, image_duration, video_repeats FROM config WHERE tenant_id=?", (tenant_id,))
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
    tenant_id = _auth_bearer(request)
    con = db_conn(); cur = con.cursor()
    cur.execute("SELECT 1 FROM media WHERE tenant_id=? AND filename=?", (tenant_id, filename))
    ok = cur.fetchone();
    if ok:
        cur.execute("UPDATE api_tokens SET last_used_at=? WHERE token_hash IN (SELECT token_hash FROM api_tokens WHERE tenant_id=?)",
                    (datetime.utcnow().isoformat(), tenant_id))
    con.commit(); con.close()
    if not ok:
        raise HTTPException(status_code=404)
    fp = UPLOAD_DIR / filename
    if not fp.exists():
        raise HTTPException(status_code=404)
    return FileResponse(fp)


# --------- Health ---------
@app.get("/health")
async def health():
    return {"ok": True}


# --------- Bootstrap templates if not exist ---------
if not (TEMPLATE_DIR / "layout.html").exists():
    (TEMPLATE_DIR / "layout.html").write_text(LAYOUT_HTML, encoding="utf-8")
if not (TEMPLATE_DIR / "login.html").exists():
    (TEMPLATE_DIR / "login.html").write_text(LOGIN_HTML, encoding="utf-8")
if not (TEMPLATE_DIR / "index.html").exists():
    (TEMPLATE_DIR / "index.html").write_text(INDEX_HTML, encoding="utf-8")

# Run with: python -m uvicorn server:app --host 0.0.0.0 --port 8000
