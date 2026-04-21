from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import sqlite3, hashlib, random, string, os, subprocess, time, json
from datetime import datetime, timedelta
from pydantic import BaseModel
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = FastAPI(title="PyHost API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── CONFIG ───────────────────────────────────────────────
DB_PATH = "pyhost.db"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = hashlib.sha256("admin123".encode()).hexdigest()

# Email sozlamalari (o'zingiznikini kiriting)
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "your@gmail.com")
SMTP_PASS = os.getenv("SMTP_PASS", "yourpassword")

# Tarif limitleri
PLANS = {
    "free":       {"price": 0,      "disk_mb": 64,    "projects": 1,  "label": "Starter"},
    "basic":      {"price": 6300,   "disk_mb": 1024,  "projects": 3,  "label": "Basic"},
    "pro":        {"price": 9830,   "disk_mb": 2048,  "projects": 10, "label": "Pro"},
    "business":   {"price": 47000,  "disk_mb": 10240, "projects": 30, "label": "Business"},
    "enterprise": {"price": 219000, "disk_mb": 51200, "projects": -1, "label": "Enterprise"},
}

# ─── DATABASE ─────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            plan TEXT DEFAULT 'free',
            balance INTEGER DEFAULT 0,
            is_verified INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1,
            trial_end TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS verify_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            code TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            type TEXT DEFAULT 'bot',
            language TEXT DEFAULT 'python',
            status TEXT DEFAULT 'stopped',
            container_id TEXT,
            port INTEGER,
            disk_used INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            type TEXT NOT NULL,
            description TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    """)
    conn.commit()
    conn.close()

init_db()

# ─── HELPERS ──────────────────────────────────────────────
def hash_password(p): return hashlib.sha256(p.encode()).hexdigest()
def gen_token(): return ''.join(random.choices(string.ascii_letters + string.digits, k=64))
def gen_code(): return str(random.randint(1000, 9999))

def send_email(to: str, subject: str, body: str):
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USER
        msg['To'] = to
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html'))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
    except Exception as e:
        print(f"Email xatosi: {e}")

def get_user_by_token(token: str):
    conn = get_db()
    c = conn.cursor()
    now = datetime.now().isoformat()
    c.execute("SELECT * FROM sessions WHERE token=? AND expires_at>?", (token, now))
    session = c.fetchone()
    if not session:
        conn.close()
        return None
    c.execute("SELECT * FROM users WHERE id=?", (session['user_id'],))
    user = c.fetchone()
    conn.close()
    return dict(user) if user else None

def require_auth(token: str = None):
    if not token:
        raise HTTPException(status_code=401, detail="Token kerak")
    user = get_user_by_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Token yaroqsiz")
    return user

def require_admin(token: str = None):
    user = require_auth(token)
    if user['email'] != ADMIN_USERNAME:
        raise HTTPException(status_code=403, detail="Admin huquqi kerak")
    return user

# ─── MODELS ───────────────────────────────────────────────
class RegisterModel(BaseModel):
    name: str
    email: str
    password: str

class VerifyModel(BaseModel):
    email: str
    code: str

class LoginModel(BaseModel):
    name: str
    password: str

class ProjectModel(BaseModel):
    name: str
    type: str = "bot"
    language: str = "python"

class AddBalanceModel(BaseModel):
    user_id: int
    amount: int

class ChangePlanModel(BaseModel):
    user_id: int
    plan: str

# ─── AUTH ─────────────────────────────────────────────────
@app.post("/api/auth/register")
async def register(data: RegisterModel, bg: BackgroundTasks):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE email=?", (data.email,))
    if c.fetchone():
        conn.close()
        raise HTTPException(400, "Bu email allaqachon ro'yxatdan o'tgan")

    # Parolni hash qilamiz
    hashed = hash_password(data.password)

    # Trial tugash sanasi (1 oy)
    trial_end = (datetime.now() + timedelta(days=30)).isoformat()

    c.execute("""
        INSERT INTO users (name, email, password, plan, trial_end)
        VALUES (?, ?, ?, 'free', ?)
    """, (data.name, data.email, hashed, trial_end))
    conn.commit()

    # Tasdiqlash kodi
    code = gen_code()
    expires = (datetime.now() + timedelta(minutes=10)).isoformat()
    c.execute("INSERT INTO verify_codes (email, code, expires_at) VALUES (?, ?, ?)",
              (data.email, code, expires))
    conn.commit()
    conn.close()

    # Email yuborish
    bg.add_task(send_email, data.email,
        "PyHost - Email tasdiqlash",
        f"""
        <div style="font-family:sans-serif;max-width:400px;margin:0 auto;padding:24px">
        <h2 style="color:#0055e5">PyHost</h2>
        <p>Salom <b>{data.name}</b>!</p>
        <p>Email tasdiqlash kodingiz:</p>
        <div style="font-size:36px;font-weight:900;letter-spacing:8px;
                    color:#0055e5;padding:16px;background:#eef3ff;
                    border-radius:10px;text-align:center;margin:16px 0">
            {code}
        </div>
        <p style="color:#999">Kod 10 daqiqa davomida amal qiladi.</p>
        </div>
        """)

    return {"ok": True, "message": "Emailga tasdiqlash kodi yuborildi"}

@app.post("/api/auth/verify")
async def verify_email(data: VerifyModel):
    conn = get_db()
    c = conn.cursor()
    now = datetime.now().isoformat()
    c.execute("""
        SELECT * FROM verify_codes
        WHERE email=? AND code=? AND expires_at>? AND used=0
        ORDER BY id DESC LIMIT 1
    """, (data.email, data.code, now))
    row = c.fetchone()
    if not row:
        conn.close()
        raise HTTPException(400, "Kod noto'g'ri yoki muddati o'tgan")
    c.execute("UPDATE verify_codes SET used=1 WHERE id=?", (row['id'],))
    c.execute("UPDATE users SET is_verified=1 WHERE email=?", (data.email,))
    conn.commit()
    conn.close()
    return {"ok": True, "message": "Email tasdiqlandi!"}

@app.post("/api/auth/login")
async def login(data: LoginModel):
    conn = get_db()
    c = conn.cursor()
    hashed = hash_password(data.password)
    c.execute("SELECT * FROM users WHERE name=? AND password=?", (data.name, hashed))
    user = c.fetchone()
    if not user:
        conn.close()
        raise HTTPException(400, "Ism yoki parol noto'g'ri")
    if not user['is_active']:
        conn.close()
        raise HTTPException(400, "Hisobingiz bloklangan")

    token = gen_token()
    expires = (datetime.now() + timedelta(days=30)).isoformat()
    c.execute("INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)",
              (user['id'], token, expires))
    conn.commit()
    conn.close()
    return {
        "ok": True,
        "token": token,
        "user": {
            "id": user['id'],
            "name": user['name'],
            "email": user['email'],
            "plan": user['plan'],
            "balance": user['balance'],
        }
    }

@app.post("/api/auth/logout")
async def logout(token: str):
    conn = get_db()
    conn.execute("DELETE FROM sessions WHERE token=?", (token,))
    conn.commit()
    conn.close()
    return {"ok": True}

@app.get("/api/auth/me")
async def me(token: str):
    user = require_auth(token)
    return {"ok": True, "user": user}

# ─── PROJECTS ─────────────────────────────────────────────
@app.get("/api/projects")
async def get_projects(token: str):
    user = require_auth(token)
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM projects WHERE user_id=?", (user['id'],))
    projects = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"ok": True, "projects": projects}

@app.post("/api/projects")
async def create_project(data: ProjectModel, token: str):
    user = require_auth(token)
    plan = PLANS.get(user['plan'], PLANS['free'])

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) as cnt FROM projects WHERE user_id=?", (user['id'],))
    count = c.fetchone()['cnt']

    if plan['projects'] != -1 and count >= plan['projects']:
        conn.close()
        raise HTTPException(400, f"Tarifingizda maksimal {plan['projects']} ta loyiha")

    c.execute("""
        INSERT INTO projects (user_id, name, type, language)
        VALUES (?, ?, ?, ?)
    """, (user['id'], data.name, data.type, data.language))
    conn.commit()
    project_id = c.lastrowid
    conn.close()
    return {"ok": True, "project_id": project_id}

@app.delete("/api/projects/{project_id}")
async def delete_project(project_id: int, token: str):
    user = require_auth(token)
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM projects WHERE id=? AND user_id=?", (project_id, user['id']))
    project = c.fetchone()
    if not project:
        conn.close()
        raise HTTPException(404, "Loyiha topilmadi")
    # Container ni to'xtatamiz
    if project['container_id']:
        try:
            subprocess.run(['docker', 'rm', '-f', project['container_id']], capture_output=True)
        except: pass
    c.execute("DELETE FROM projects WHERE id=?", (project_id,))
    conn.commit()
    conn.close()
    return {"ok": True}

@app.post("/api/projects/{project_id}/start")
async def start_project(project_id: int, token: str):
    user = require_auth(token)
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM projects WHERE id=? AND user_id=?", (project_id, user['id']))
    project = c.fetchone()
    if not project:
        conn.close()
        raise HTTPException(404, "Loyiha topilmadi")

    project_dir = f"/app/projects/{user['id']}/{project_id}"
    os.makedirs(project_dir, exist_ok=True)

    container_name = f"pyhost_{user['id']}_{project_id}"

    # Lang bo'yicha image
    images = {
        "python": "python:3.11-slim",
        "nodejs": "node:18-slim",
        "php": "php:8.2-cli",
    }
    image = images.get(project['language'], "python:3.11-slim")

    # Start commands
    cmds = {
        "python": "pip install -r requirements.txt 2>/dev/null; python main.py",
        "nodejs": "npm install 2>/dev/null; node index.js",
        "php": "php index.php",
    }
    cmd = cmds.get(project['language'], "python main.py")

    plan = PLANS.get(user['plan'], PLANS['free'])
    mem_limit = f"{min(plan['disk_mb'], 512)}m"

    try:
        subprocess.run(['docker', 'rm', '-f', container_name], capture_output=True)
        result = subprocess.run([
            'docker', 'run', '-d',
            '--name', container_name,
            '--memory', mem_limit,
            '--cpus', '0.5',
            '--restart', 'unless-stopped',
            '-v', f'{project_dir}:/app',
            '-w', '/app',
            image,
            'sh', '-c', cmd
        ], capture_output=True, text=True)

        container_id = result.stdout.strip()
        c.execute("UPDATE projects SET status='running', container_id=? WHERE id=?",
                  (container_id, project_id))
        conn.commit()
        conn.close()
        return {"ok": True, "status": "running"}
    except Exception as e:
        conn.close()
        raise HTTPException(500, str(e))

@app.post("/api/projects/{project_id}/stop")
async def stop_project(project_id: int, token: str):
    user = require_auth(token)
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM projects WHERE id=? AND user_id=?", (project_id, user['id']))
    project = c.fetchone()
    if not project:
        conn.close()
        raise HTTPException(404, "Loyiha topilmadi")
    container_name = f"pyhost_{user['id']}_{project_id}"
    try:
        subprocess.run(['docker', 'stop', container_name], capture_output=True)
    except: pass
    c.execute("UPDATE projects SET status='stopped' WHERE id=?", (project_id,))
    conn.commit()
    conn.close()
    return {"ok": True, "status": "stopped"}

@app.post("/api/projects/{project_id}/restart")
async def restart_project(project_id: int, token: str):
    await stop_project(project_id, token)
    return await start_project(project_id, token)

@app.get("/api/projects/{project_id}/logs")
async def get_logs(project_id: int, token: str):
    user = require_auth(token)
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM projects WHERE id=? AND user_id=?", (project_id, user['id']))
    project = c.fetchone()
    conn.close()
    if not project:
        raise HTTPException(404, "Loyiha topilmadi")
    container_name = f"pyhost_{user['id']}_{project_id}"
    try:
        result = subprocess.run(['docker', 'logs', '--tail', '100', container_name],
                                capture_output=True, text=True)
        return {"ok": True, "logs": result.stdout + result.stderr}
    except:
        return {"ok": True, "logs": "Loglar mavjud emas"}

# ─── FILES ────────────────────────────────────────────────
@app.get("/api/projects/{project_id}/files")
async def list_files(project_id: int, token: str):
    user = require_auth(token)
    project_dir = f"/app/projects/{user['id']}/{project_id}"
    os.makedirs(project_dir, exist_ok=True)
    files = []
    for f in os.listdir(project_dir):
        fp = os.path.join(project_dir, f)
        files.append({
            "name": f,
            "size": os.path.getsize(fp),
            "is_dir": os.path.isdir(fp)
        })
    return {"ok": True, "files": files}

@app.get("/api/projects/{project_id}/files/{filename}")
async def read_file(project_id: int, filename: str, token: str):
    user = require_auth(token)
    fp = f"/app/projects/{user['id']}/{project_id}/{filename}"
    if not os.path.exists(fp):
        raise HTTPException(404, "Fayl topilmadi")
    with open(fp, 'r', errors='replace') as f:
        content = f.read()
    return {"ok": True, "content": content}

class SaveFileModel(BaseModel):
    content: str

@app.post("/api/projects/{project_id}/files/{filename}")
async def save_file(project_id: int, filename: str, data: SaveFileModel, token: str):
    user = require_auth(token)
    project_dir = f"/app/projects/{user['id']}/{project_id}"
    os.makedirs(project_dir, exist_ok=True)
    fp = os.path.join(project_dir, filename)
    with open(fp, 'w') as f:
        f.write(data.content)
    return {"ok": True}

@app.delete("/api/projects/{project_id}/files/{filename}")
async def delete_file(project_id: int, filename: str, token: str):
    user = require_auth(token)
    fp = f"/app/projects/{user['id']}/{project_id}/{filename}"
    if os.path.exists(fp):
        os.remove(fp)
    return {"ok": True}

# ─── ADMIN ────────────────────────────────────────────────
@app.get("/api/admin/users")
async def admin_users(token: str):
    require_admin(token)
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users ORDER BY id DESC")
    users = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"ok": True, "users": users}

@app.post("/api/admin/balance")
async def admin_add_balance(data: AddBalanceModel, token: str):
    require_admin(token)
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (data.user_id,))
    user = c.fetchone()
    if not user:
        conn.close()
        raise HTTPException(404, "Foydalanuvchi topilmadi")
    c.execute("UPDATE users SET balance=balance+? WHERE id=?", (data.amount, data.user_id))
    c.execute("""
        INSERT INTO transactions (user_id, amount, type, description)
        VALUES (?, ?, 'deposit', 'Admin tomonidan qo''shildi')
    """, (data.user_id, data.amount))
    conn.commit()
    conn.close()
    return {"ok": True, "message": f"{data.amount} so'm qo'shildi"}

@app.post("/api/admin/plan")
async def admin_change_plan(data: ChangePlanModel, token: str):
    require_admin(token)
    if data.plan not in PLANS:
        raise HTTPException(400, "Noto'g'ri tarif")
    conn = get_db()
    conn.execute("UPDATE users SET plan=? WHERE id=?", (data.plan, data.user_id))
    conn.commit()
    conn.close()
    return {"ok": True}

@app.post("/api/admin/block/{user_id}")
async def admin_block(user_id: int, token: str):
    require_admin(token)
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT is_active FROM users WHERE id=?", (user_id,))
    user = c.fetchone()
    if not user:
        conn.close()
        raise HTTPException(404, "Foydalanuvchi topilmadi")
    new_status = 0 if user['is_active'] else 1
    c.execute("UPDATE users SET is_active=? WHERE id=?", (new_status, user_id))
    conn.commit()
    conn.close()
    return {"ok": True, "is_active": new_status}

@app.get("/api/admin/stats")
async def admin_stats(token: str):
    require_admin(token)
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) as cnt FROM users")
    total_users = c.fetchone()['cnt']
    c.execute("SELECT COUNT(*) as cnt FROM projects")
    total_projects = c.fetchone()['cnt']
    c.execute("SELECT COUNT(*) as cnt FROM projects WHERE status='running'")
    running = c.fetchone()['cnt']
    c.execute("SELECT SUM(balance) as total FROM users")
    total_balance = c.fetchone()['total'] or 0
    conn.close()
    return {
        "ok": True,
        "stats": {
            "total_users": total_users,
            "total_projects": total_projects,
            "running_projects": running,
            "total_balance": total_balance,
        }
    }

@app.get("/api/admin/login")
async def admin_login_get():
    return {"message": "POST so'rov yuboring"}

class AdminLoginModel(BaseModel):
    password: str

@app.post("/api/admin/login")
async def admin_login(data: AdminLoginModel):
    if hash_password(data.password) != ADMIN_PASSWORD:
        raise HTTPException(400, "Parol noto'g'ri")
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE email=?", (ADMIN_USERNAME,))
    admin = c.fetchone()
    if not admin:
        c.execute("""
            INSERT INTO users (name, email, password, is_verified, plan)
            VALUES ('Admin', ?, ?, 1, 'enterprise')
        """, (ADMIN_USERNAME, ADMIN_PASSWORD))
        conn.commit()
        c.execute("SELECT * FROM users WHERE email=?", (ADMIN_USERNAME,))
        admin = c.fetchone()
    token = gen_token()
    expires = (datetime.now() + timedelta(days=365)).isoformat()
    c.execute("INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)",
              (admin['id'], token, expires))
    conn.commit()
    conn.close()
    return {"ok": True, "token": token}

@app.get("/api/plans")
async def get_plans():
    return {"ok": True, "plans": PLANS}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
