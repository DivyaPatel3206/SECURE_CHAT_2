"""
╔══════════════════════════════════════════════════════════════════╗
║  Secure Real-Time Chat System                                    ║
║  Anti-Sniffing · DDoS Protection · Brute Force Guard            ║
║  FastAPI + WebSockets + SQLite + Jinja2                         ║
║                                                                  ║
║  Run:  uvicorn main:app --reload                                 ║
║  Deploy: Render → Web Service → uvicorn main:app --host 0.0.0.0 ║
╚══════════════════════════════════════════════════════════════════╝
"""

# ─────────────────────────── stdlib ────────────────────────────────────────
import asyncio
import base64
import hashlib
import io
import json
import os
import secrets
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from typing import Optional

# ─────────────────────────── third-party ───────────────────────────────────
import aiosqlite
import httpx
import qrcode
from fastapi import (
    FastAPI, Request, WebSocket, WebSocketDisconnect,
    HTTPException, Response
)
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# ═══════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

DB_PATH            = "chat.db"
RATE_LIMIT_MAX     = 120      # requests per 60 s
BURST_LIMIT        = 30       # requests per 5 s before burst flag
BURST_WINDOW       = 5        # seconds
BLOCK_DURATION     = 60       # seconds an IP stays blocked
WS_MSG_LIMIT       = 5        # WS messages per WS_MSG_WINDOW seconds
WS_MSG_WINDOW      = 2
MAX_LOGIN_ATTEMPTS = 5        # per ATTEMPT_WINDOW
ATTEMPT_WINDOW     = 60
QR_TTL             = 300      # seconds until QR token expires
PROBE_TTL          = 3600     # seconds until probe token expires

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ═══════════════════════════════════════════════════════════════════════════
#  DATABASE SCHEMA
# ═══════════════════════════════════════════════════════════════════════════

DDL = """
CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL,
    username     TEXT NOT NULL,
    fingerprint  TEXT NOT NULL,
    ip           TEXT NOT NULL,
    created_at   REAL NOT NULL,
    last_seen    REAL NOT NULL,
    threat_score INTEGER DEFAULT 0,
    status       TEXT DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS probe_tokens (
    token       TEXT PRIMARY KEY,
    session_id  TEXT NOT NULL,
    ip          TEXT NOT NULL,
    created_at  REAL NOT NULL,
    used        INTEGER DEFAULT 0,
    used_by_ip  TEXT,
    used_at     REAL
);
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT,
    alert_type  TEXT NOT NULL,
    severity    TEXT NOT NULL,
    description TEXT NOT NULL,
    ip          TEXT,
    timestamp   REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS request_logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT,
    ip           TEXT NOT NULL,
    method       TEXT NOT NULL,
    path         TEXT NOT NULL,
    payload_size INTEGER DEFAULT 0,
    user_agent   TEXT,
    timestamp    REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS chat_messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id    TEXT NOT NULL,
    session_id TEXT NOT NULL,
    username   TEXT NOT NULL,
    content    TEXT NOT NULL,
    timestamp  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS qr_tokens (
    token       TEXT PRIMARY KEY,
    room_id     TEXT NOT NULL,
    created_at  REAL NOT NULL,
    expires_at  REAL NOT NULL,
    used        INTEGER DEFAULT 0,
    fingerprint TEXT
);
CREATE TABLE IF NOT EXISTS sim_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_type TEXT NOT NULL,
    triggered_by TEXT,
    timestamp   REAL NOT NULL,
    details     TEXT
);
"""

async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(DDL)
        await db.commit()

# ═══════════════════════════════════════════════════════════════════════════
#  UTILITY HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def now() -> float:
    return time.time()

def make_token(n: int = 32) -> str:
    return secrets.token_urlsafe(n)

def hash_fp(ua: str, screen: str, tz: str) -> str:
    """SHA-256 of browser fingerprint signals. Raw values never stored."""
    return hashlib.sha256(f"{ua}|{screen}|{tz}".encode()).hexdigest()

def client_ip(request) -> str:
    """Extract real IP, honouring X-Forwarded-For (Render proxy)."""
    fwd = getattr(request, "headers", {}).get("x-forwarded-for") \
        or getattr(request, "headers", {}).get("X-Forwarded-For")
    if fwd:
        return fwd.split(",")[0].strip()
    if hasattr(request, "client") and request.client:
        return request.client.host
    return "unknown"

# ─── Geo-IP (free ipapi.co, cached) ────────────────────────────────────────
_geo_cache: dict[str, dict] = {}

async def get_geo(ip: str) -> dict:
    """Return full geo data including lat/lon/flag for map rendering."""
    LOCAL = {
        "country": "Local", "city": "Localhost", "isp": "—",
        "lat": 20.5937, "lon": 78.9629,
        "country_code": "IN", "flag": "🏠"
    }
    if ip in ("127.0.0.1", "::1", "localhost", "unknown"):
        return LOCAL
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        async with httpx.AsyncClient(timeout=4.0) as c:
            r = await c.get(f"https://ipapi.co/{ip}/json/")
            d = r.json()
            if d.get("error"):
                return LOCAL
            cc = d.get("country_code", "")
            flag = (chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)) if len(cc) == 2 else "🌐"
            result = {
                "country":      d.get("country_name", "Unknown"),
                "country_code": cc,
                "city":         d.get("city", "Unknown"),
                "isp":          d.get("org", "Unknown"),
                "lat":          float(d.get("latitude",  0.0)),
                "lon":          float(d.get("longitude", 0.0)),
                "flag":         flag,
            }
            _geo_cache[ip] = result
            return result
    except Exception:
        return LOCAL

# ═══════════════════════════════════════════════════════════════════════════
#  RATE LIMITER  (in-memory, per-IP sliding window)
# ═══════════════════════════════════════════════════════════════════════════

class RateLimiter:
    def __init__(self):
        self._reqs:    dict[str, deque] = defaultdict(deque)
        self._bursts:  dict[str, deque] = defaultdict(deque)
        self._blocked: dict[str, float] = {}
        self._ws:      dict[str, deque] = defaultdict(deque)

    def check(self, ip: str) -> tuple[bool, str]:
        t = now()
        # Active block?
        if ip in self._blocked:
            if t < self._blocked[ip]:
                return False, f"Blocked for {int(self._blocked[ip]-t)}s"
            del self._blocked[ip]

        # Sliding 60-s window
        dq = self._reqs[ip]
        while dq and dq[0] < t - 60: dq.popleft()
        dq.append(t)
        if len(dq) > RATE_LIMIT_MAX:
            self._blocked[ip] = t + BLOCK_DURATION
            return False, "Rate limit exceeded — IP blocked"

        # Burst window
        bq = self._bursts[ip]
        while bq and bq[0] < t - BURST_WINDOW: bq.popleft()
        bq.append(t)
        if len(bq) > BURST_LIMIT:
            return False, "Burst threshold exceeded"

        return True, "ok"

    def check_ws(self, sid: str) -> bool:
        t = now()
        dq = self._ws[sid]
        while dq and dq[0] < t - WS_MSG_WINDOW: dq.popleft()
        dq.append(t)
        return len(dq) <= WS_MSG_LIMIT

    def block(self, ip: str, secs: int = BLOCK_DURATION):
        self._blocked[ip] = now() + secs

    def blocked_list(self) -> list[dict]:
        t = now()
        return [
            {"ip": ip, "remaining": int(until - t)}
            for ip, until in self._blocked.items() if t < until
        ]

    def req_count(self, ip: str) -> int:
        t = now()
        dq = self._reqs[ip]
        while dq and dq[0] < t - 60: dq.popleft()
        return len(dq)

limiter = RateLimiter()

# ═══════════════════════════════════════════════════════════════════════════
#  ALERT SYSTEM
# ═══════════════════════════════════════════════════════════════════════════

_alert_hooks: list = []   # async callables for WS push

async def emit_alert(
    alert_type: str, severity: str, description: str,
    session_id: str = None, ip: str = None
) -> dict:
    t = now()
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "INSERT INTO alerts (session_id,alert_type,severity,description,ip,timestamp) VALUES (?,?,?,?,?,?)",
            (session_id, alert_type, severity, description, ip, t)
        )
        aid = cur.lastrowid
        await db.commit()

    alert = {"id": aid, "type": alert_type, "severity": severity,
              "description": description, "session_id": session_id,
              "ip": ip, "timestamp": t}

    for hook in list(_alert_hooks):
        try:
            await hook(alert)
        except Exception:
            if hook in _alert_hooks: _alert_hooks.remove(hook)

    return alert

def register_alert_hook(fn): _alert_hooks.append(fn)
def remove_alert_hook(fn):
    if fn in _alert_hooks: _alert_hooks.remove(fn)

# ═══════════════════════════════════════════════════════════════════════════
#  SESSION BINDING  (Token ↔ Fingerprint ↔ IP)
# ═══════════════════════════════════════════════════════════════════════════

_sess_cache: dict[str, dict] = {}

async def session_create(sid: str, user_id: str, username: str,
                          fp: str, ip: str):
    t = now()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR REPLACE INTO sessions "
            "(id,user_id,username,fingerprint,ip,created_at,last_seen,threat_score,status) "
            "VALUES (?,?,?,?,?,?,?,0,'active')",
            (sid, user_id, username, fp, ip, t, t)
        )
        await db.commit()
    _sess_cache[sid] = {"user_id": user_id, "username": username,
                         "fingerprint": fp, "ip": ip,
                         "last_seen": t, "threat_score": 0, "status": "active"}

async def session_get(sid: str) -> dict | None:
    if sid in _sess_cache:
        return _sess_cache[sid]
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM sessions WHERE id=? AND status='active'", (sid,)
        ) as cur:
            row = await cur.fetchone()
            if not row: return None
            d = dict(row)
            _sess_cache[sid] = d
            return d

async def session_validate(sid: str, fp: str, ip: str) -> dict:
    """Returns {valid, risk, alerts[]}. Detects fingerprint/IP anomalies."""
    s = await session_get(sid)
    if not s:
        return {"valid": False, "risk": 0, "alerts": ["Unknown session"]}

    risk, alerts = 0, []

    if s["fingerprint"] != fp:
        risk += 40
        alerts.append("FINGERPRINT_MISMATCH")
        await emit_alert("FINGERPRINT_MISMATCH", "high",
            f"Fingerprint changed for {s['username']} from {s['ip']}",
            session_id=sid, ip=ip)

    if s["ip"] != ip:
        age = now() - s["last_seen"]
        if age < 60:
            risk += 30
            alerts.append("RAPID_IP_CHANGE")
            await emit_alert("RAPID_IP_CHANGE", "medium",
                f"{s['username']}: IP changed {s['ip']}→{ip} in {age:.0f}s",
                session_id=sid, ip=ip)

    await _session_touch(sid, ip, risk)
    return {"valid": True, "risk": risk, "alerts": alerts}

async def _session_touch(sid: str, ip: str, delta: int = 0):
    t = now()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE sessions SET last_seen=?,ip=?,threat_score=threat_score+? WHERE id=?",
            (t, ip, delta, sid)
        )
        await db.commit()
    if sid in _sess_cache:
        _sess_cache[sid].update({"last_seen": t, "ip": ip})
        _sess_cache[sid]["threat_score"] = _sess_cache[sid].get("threat_score", 0) + delta

async def session_add_risk(sid: str, delta: int):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE sessions SET threat_score=threat_score+? WHERE id=?", (delta, sid)
        )
        await db.commit()
    if sid in _sess_cache:
        _sess_cache[sid]["threat_score"] = _sess_cache[sid].get("threat_score", 0) + delta

async def session_invalidate(sid: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("UPDATE sessions SET status='invalidated' WHERE id=?", (sid,))
        await db.commit()
    _sess_cache.pop(sid, None)

async def sessions_all() -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM sessions WHERE status='active' ORDER BY last_seen DESC"
        ) as cur:
            return [dict(r) for r in await cur.fetchall()]

def threat_level(score: int) -> str:
    return "Attack" if score >= 70 else "Suspicious" if score >= 30 else "Normal"

# ═══════════════════════════════════════════════════════════════════════════
#  PROBE (CANARY TOKEN) SYSTEM
# ═══════════════════════════════════════════════════════════════════════════

async def probe_issue(sid: str, ip: str) -> str:
    token = make_token(24)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO probe_tokens (token,session_id,ip,created_at) VALUES (?,?,?,?)",
            (token, sid, ip, now())
        )
        await db.commit()
    return token

async def probe_verify(token: str, sid: str, ip: str) -> dict:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM probe_tokens WHERE token=?", (token,)
        ) as cur:
            row = await cur.fetchone()

        if not row:
            return {"ok": False, "attack": True, "reason": "Unknown probe token"}
        row = dict(row)

        if row["used"]:
            return {"ok": False, "attack": True,
                    "reason": f"Probe replayed (first used by {row['used_by_ip']})"}

        if now() - row["created_at"] > PROBE_TTL:
            return {"ok": False, "attack": False, "reason": "Probe expired"}

        attack = row["ip"] != ip or row["session_id"] != sid
        await db.execute(
            "UPDATE probe_tokens SET used=1,used_by_ip=?,used_at=? WHERE token=?",
            (ip, now(), token)
        )
        await db.commit()

        if attack:
            reason = (f"Probe stolen: original IP={row['ip']}, used from {ip}"
                      if row["ip"] != ip else "Probe used by different session")
            return {"ok": False, "attack": True, "reason": reason}

        return {"ok": True, "attack": False, "reason": "Valid"}

# ═══════════════════════════════════════════════════════════════════════════
#  BEHAVIORAL ANALYSIS  (request patterns per IP)
# ═══════════════════════════════════════════════════════════════════════════

_req_history: dict[str, list] = defaultdict(list)
_login_attempts: dict[str, list] = defaultdict(list)

async def analyze_request(ip: str, path: str, method: str,
                           ua: str, size: int, sid: str = None):
    t = now()
    hist = _req_history[ip]
    hist.append({"path": path, "t": t, "ua": ua})
    _req_history[ip] = [h for h in hist if t - h["t"] < 60]
    recent = _req_history[ip]

    # Bot/scripted UA
    bot_uas = {"python-requests", "curl", "Go-http-client", "wget", "Wget"}
    if not ua or ua.strip() in bot_uas or "bot" in ua.lower():
        await emit_alert("SCRIPTED_TRAFFIC", "medium",
            f"Bot UA from {ip}: '{ua[:60]}'", ip=ip)
        if sid: await session_add_risk(sid, 35)

    # Repeated same endpoint
    same = sum(1 for h in recent if h["path"] == path)
    if same > 25:
        await emit_alert("REPEATED_REQUESTS", "medium",
            f"{ip} hit {path} {same}× in 60s", ip=ip)

    # High volume
    if len(recent) > 60:
        await emit_alert("HIGH_REQ_RATE", "high",
            f"{ip} made {len(recent)} requests/60s", ip=ip)
        if sid: await session_add_risk(sid, 25)

    # Persist log
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO request_logs "
            "(session_id,ip,method,path,payload_size,user_agent,timestamp) "
            "VALUES (?,?,?,?,?,?,?)",
            (sid, ip, method, path, size, ua, t)
        )
        await db.commit()

# Geo anomaly cache
_session_geo: dict[str, str] = {}

async def check_geo(sid: str, ip: str):
    geo = await get_geo(ip)
    loc = f"{geo['country']}/{geo['city']}"
    prev = _session_geo.get(sid)
    if prev and prev != loc and prev != "Local/Localhost":
        await session_add_risk(sid, 30)
        await emit_alert("GEO_ANOMALY", "medium",
            f"Location changed: {prev} → {loc}", session_id=sid, ip=ip)
    _session_geo[sid] = loc

def brute_check(ip: str) -> bool:
    """Returns True if IP is within attempt limit."""
    t = now()
    lst = _login_attempts[ip]
    _login_attempts[ip] = [x for x in lst if t - x < ATTEMPT_WINDOW]
    _login_attempts[ip].append(t)
    return len(_login_attempts[ip]) <= MAX_LOGIN_ATTEMPTS

# ═══════════════════════════════════════════════════════════════════════════
#  WEBSOCKET CONNECTION MANAGER
# ═══════════════════════════════════════════════════════════════════════════

class WSManager:
    def __init__(self):
        # room_id → [{ws, sid, username}]
        self._rooms: dict[str, list[dict]] = defaultdict(list)
        self._dashboards: list[WebSocket] = []

    async def join(self, ws: WebSocket, room: str, sid: str, username: str):
        await ws.accept()
        self._rooms[room].append({"ws": ws, "sid": sid, "username": username})

    def leave(self, ws: WebSocket, room: str):
        self._rooms[room] = [c for c in self._rooms[room] if c["ws"] is not ws]

    def users(self, room: str) -> list[str]:
        return [c["username"] for c in self._rooms[room]]

    def all_rooms(self) -> dict:
        return {r: self.users(r) for r in self._rooms if self._rooms[r]}

    def online_count(self) -> int:
        return sum(len(v) for v in self._rooms.values())

    async def broadcast(self, room: str, msg: dict):
        data, dead = json.dumps(msg), []
        for c in self._rooms[room]:
            try: await c["ws"].send_text(data)
            except: dead.append(c)
        for d in dead: self._rooms[room].remove(d)

    async def send(self, ws: WebSocket, msg: dict):
        try: await ws.send_text(json.dumps(msg))
        except: pass

    async def kick(self, sid: str, reason: str = "Security violation"):
        for room in list(self._rooms):
            for c in list(self._rooms[room]):
                if c["sid"] == sid:
                    try:
                        await c["ws"].send_text(json.dumps({"type": "kicked", "reason": reason}))
                        await c["ws"].close()
                    except: pass
                    self._rooms[room].remove(c)

    async def dash_connect(self, ws: WebSocket):
        await ws.accept()
        self._dashboards.append(ws)

    def dash_leave(self, ws: WebSocket):
        if ws in self._dashboards: self._dashboards.remove(ws)

    async def dash_push(self, alert: dict):
        dead, data = [], json.dumps({"type": "alert", "data": alert})
        for ws in self._dashboards:
            try: await ws.send_text(data)
            except: dead.append(ws)
        for d in dead: self._dashboards.remove(d)

ws_mgr = WSManager()

# ═══════════════════════════════════════════════════════════════════════════
#  APP STARTUP / SHUTDOWN
# ═══════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    # Wire IDS alerts → dashboard WebSocket
    register_alert_hook(ws_mgr.dash_push)
    print("✅  DB ready  |  🔒 IDS active  |  🚀 http://127.0.0.1:8000")
    yield
    print("👋  Shutdown")

app = FastAPI(title="SecureChat", lifespan=lifespan)

# Templates & static
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
static_dir = os.path.join(BASE_DIR, "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

# ═══════════════════════════════════════════════════════════════════════════
#  MIDDLEWARE  (rate-limit + request logging for every HTTP call)
# ═══════════════════════════════════════════════════════════════════════════

@app.middleware("http")
async def security_mw(request: Request, call_next):
    ip = client_ip(request)
    path = request.url.path

    # Skip static files from rate limiting
    if not path.startswith("/static"):
        ok, reason = limiter.check(ip)
        if not ok:
            return JSONResponse(status_code=429, content={"detail": reason})

    response = await call_next(request)

    # Async request logging (fire and forget, never crashes the request)
    if not path.startswith("/static"):
        sid = request.headers.get("x-session-token")
        ua  = request.headers.get("user-agent", "")
        asyncio.create_task(analyze_request(
            ip, path, request.method, ua,
            int(request.headers.get("content-length", 0)), sid
        ))

    return response

# ═══════════════════════════════════════════════════════════════════════════
#  AUTH  ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════

@app.post("/auth/register")
async def auth_register(request: Request):
    ip = client_ip(request)

    # Brute-force guard
    if not brute_check(ip):
        raise HTTPException(429, "Too many attempts. Wait 60 seconds.")

    body = await request.json()
    username = str(body.get("username", "")).strip()[:32]
    if not username:
        raise HTTPException(400, "Username required (1–32 chars)")

    ua      = body.get("user_agent", "")
    screen  = body.get("screen_res", "unknown")
    tz      = body.get("timezone", "UTC")
    fp      = hash_fp(ua, screen, tz)
    sid     = make_token(32)
    uid     = str(uuid.uuid4())

    await session_create(sid, uid, username, fp, ip)
    probe = await probe_issue(sid, ip)
    asyncio.create_task(check_geo(sid, ip))

    return {"session_token": sid, "username": username,
            "probe_token": probe}           # probe is silent — JS uses it

@app.get("/auth/me")
async def auth_me(request: Request):
    token = (request.headers.get("x-session-token")
             or request.cookies.get("session_token"))
    if not token: raise HTTPException(401, "No session")
    s = await session_get(token)
    if not s: raise HTTPException(401, "Invalid session")
    return {"username": s["username"], "threat_score": s["threat_score"]}

@app.post("/auth/logout")
async def auth_logout(request: Request):
    token = request.headers.get("x-session-token")
    if token: await session_invalidate(token)
    return {"status": "ok"}

# ═══════════════════════════════════════════════════════════════════════════
#  CHAT  ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/chat/rooms")
async def chat_rooms():
    active = list(ws_mgr.all_rooms().keys())
    default = ["general", "dev", "security"]
    return {"rooms": list(dict.fromkeys(default + active))}

@app.post("/chat/rooms")
async def chat_create_room(request: Request):
    body = await request.json()
    rid = str(body.get("room_id", "")).strip().lower().replace(" ", "-")[:32]
    if not rid: raise HTTPException(400, "Invalid room_id")
    return {"room_id": rid}

@app.get("/chat/qr/{room_id}")
async def chat_qr(room_id: str, request: Request):
    """Generate a single-use, short-lived, device-bound QR token."""
    token = make_token(16)
    t = now()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO qr_tokens (token,room_id,created_at,expires_at) VALUES (?,?,?,?)",
            (token, room_id, t, t + QR_TTL)
        )
        await db.commit()

    # ✅ Build URL from actual request so QR works on any server/device/network
    scheme = request.headers.get("x-forwarded-proto") or request.url.scheme
    host   = request.headers.get("x-forwarded-host")  or request.headers.get("host") or request.url.netloc
    base_url = f"{scheme}://{host}"
    join_url = f"{base_url}/chat/{room_id}?qr_token={token}"
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8, border=2
    )
    qr.add_data(join_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#00e5ff", back_color="#0a0f1a")
    buf = io.BytesIO()
    img.save(buf, "PNG")
    b64 = base64.b64encode(buf.getvalue()).decode()

    return {"qr_image": f"data:image/png;base64,{b64}",
            "expires_in": QR_TTL, "join_url": join_url,
            "base_url": base_url}

@app.post("/chat/join-qr")
async def chat_join_qr(request: Request):
    body = await request.json()
    token = body.get("token", "")
    fp    = body.get("fingerprint", "")
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM qr_tokens WHERE token=?", (token,)
        ) as cur:
            row = await cur.fetchone()
        if not row: raise HTTPException(400, "Invalid QR token")
        row = dict(row)
        if row["used"]: raise HTTPException(400, "QR token already used")
        if now() > row["expires_at"]: raise HTTPException(400, "QR token expired")
        await db.execute(
            "UPDATE qr_tokens SET used=1,fingerprint=? WHERE token=?", (fp, token)
        )
        await db.commit()
    return {"room_id": row["room_id"]}

# ─────────────────── WebSocket Chat ────────────────────────────────────────

@app.websocket("/ws/chat/{room_id}")
async def ws_chat(websocket: WebSocket, room_id: str):
    ip       = client_ip(websocket)
    sid      = None
    username = "anonymous"

    await websocket.accept()

    try:
        # ── 1. Auth handshake ─────────────────────────────────────────────
        raw  = await asyncio.wait_for(websocket.receive_text(), timeout=10)
        auth = json.loads(raw)
        if auth.get("type") != "auth":
            await websocket.send_text(json.dumps({"type":"error","msg":"Send auth first"}))
            await websocket.close(); return

        sid = auth.get("session_token", "")
        fp  = auth.get("fingerprint", "")

        result = await session_validate(sid, fp, ip)
        if not result["valid"]:
            await websocket.send_text(json.dumps({"type":"error","msg":"Invalid session"}))
            await websocket.close(); return

        s = await session_get(sid)
        username = s["username"] if s else "unknown"

        # Register (socket already accepted above; add to room manually)
        ws_mgr._rooms[room_id].append({"ws": websocket, "sid": sid, "username": username})

        await ws_mgr.broadcast(room_id, {
            "type": "system", "msg": f"{username} joined",
            "users": ws_mgr.users(room_id)
        })

        # ── 2. Message loop ───────────────────────────────────────────────
        while True:
            raw = await websocket.receive_text()

            if not limiter.check_ws(sid):
                await ws_mgr.send(websocket, {"type":"error","msg":"Message rate limit — slow down"})
                continue

            try: msg = json.loads(raw)
            except: continue

            mtype = msg.get("type", "chat")

            if mtype == "chat":
                content = str(msg.get("content", "")).strip()[:1000]
                if not content: continue
                async with aiosqlite.connect(DB_PATH) as db:
                    await db.execute(
                        "INSERT INTO chat_messages (room_id,session_id,username,content,timestamp) VALUES (?,?,?,?,?)",
                        (room_id, sid, username, content, now())
                    )
                    await db.commit()
                await ws_mgr.broadcast(room_id, {
                    "type": "chat", "username": username,
                    "content": content, "ts": now()
                })

            elif mtype == "probe_echo":
                res = await probe_verify(msg.get("probe_token",""), sid, ip)
                if res["attack"]:
                    await session_add_risk(sid, 60)
                    await emit_alert("PROBE_MISUSE", "critical",
                        f"Probe stolen: {res['reason']}", session_id=sid, ip=ip)
                    limiter.block(ip, 120)

            elif mtype == "ping":
                await ws_mgr.send(websocket, {"type":"pong"})

    except (WebSocketDisconnect, asyncio.TimeoutError):
        pass
    except Exception:
        pass
    finally:
        ws_mgr.leave(websocket, room_id)
        if username != "anonymous":
            await ws_mgr.broadcast(room_id, {
                "type":"system","msg":f"{username} left",
                "users": ws_mgr.users(room_id)
            })

# ═══════════════════════════════════════════════════════════════════════════
#  DASHBOARD  ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════

@app.websocket("/ws/dashboard")
async def ws_dashboard(websocket: WebSocket):
    await ws_mgr.dash_connect(websocket)
    try:
        while True: await websocket.receive_text()   # keep alive (pings)
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        ws_mgr.dash_leave(websocket)

@app.get("/api/sessions")
async def api_sessions():
    sess = await sessions_all()
    for s in sess:
        s["threat_level"] = threat_level(s.get("threat_score", 0))
    return {"sessions": sess, "total": len(sess)}

@app.get("/api/alerts")
async def api_alerts(limit: int = 100):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
        ) as cur:
            rows = [dict(r) for r in await cur.fetchall()]
    return {"alerts": rows, "total": len(rows)}

@app.get("/api/logs")
async def api_logs(limit: int = 100):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM request_logs ORDER BY timestamp DESC LIMIT ?", (limit,)
        ) as cur:
            rows = [dict(r) for r in await cur.fetchall()]
    return {"logs": rows}

@app.get("/api/stats")
async def api_stats():
    sess = await sessions_all()
    breakdown = {"Normal": 0, "Suspicious": 0, "Attack": 0}
    for s in sess: breakdown[threat_level(s.get("threat_score", 0))] += 1

    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute("SELECT COUNT(*) FROM alerts") as c:
            total_alerts = (await c.fetchone())[0]
        async with db.execute("SELECT COUNT(*) FROM alerts WHERE severity='critical'") as c:
            crit = (await c.fetchone())[0]
        async with db.execute("SELECT COUNT(*) FROM probe_tokens WHERE used=1 AND used_by_ip!=ip") as c:
            suspicious_probes = (await c.fetchone())[0]

    return {
        "online": ws_mgr.online_count(),
        "sessions": len(sess),
        "rooms": len(ws_mgr.all_rooms()),
        "alerts_total": total_alerts,
        "alerts_critical": crit,
        "suspicious_probes": suspicious_probes,
        "blocked_ips": len(limiter.blocked_list()),
        "threat_breakdown": breakdown,
    }

@app.get("/api/blocked")
async def api_blocked():
    return {"blocked": limiter.blocked_list()}

@app.post("/api/kick/{sid}")
async def api_kick(sid: str):
    await ws_mgr.kick(sid, "Kicked by admin")
    await session_invalidate(sid)
    return {"status": "kicked"}

# ═══════════════════════════════════════════════════════════════════════════
#  ATTACK SIMULATION
# ═══════════════════════════════════════════════════════════════════════════

async def _log_sim(attack: str, ip: str, detail: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO sim_log (attack_type,triggered_by,timestamp,details) VALUES (?,?,?,?)",
            (attack, ip, now(), detail)
        )
        await db.commit()

@app.post("/simulate/ddos")
async def sim_ddos(request: Request):
    ip = client_ip(request)
    for _ in range(150): limiter._reqs[ip].append(now())
    limiter.block(ip, 30)
    await emit_alert("DDOS_ATTACK", "critical",
        f"🔴 DDoS FLOOD DETECTED: 150 requests from {ip} in <1 second — IP BLOCKED 30s", ip=ip)
    await _log_sim("DDOS", ip, "150 simulated requests")
    return {
        "attack": "DDoS Flood Attack",
        "icon": "🌊",
        "color": "#ff3355",
        "alert_raised": True,
        "severity": "CRITICAL",
        "what_is_it": "A DDoS (Distributed Denial of Service) attack floods your server with thousands of fake requests, crashing it for real users.",
        "steps": [
            {"icon": "💻", "label": "Step 1 — Attacker Starts", "text": "Attacker launches a bot that sends 150+ requests per second to your server."},
            {"icon": "📊", "label": "Step 2 — Rate Limiter Detects", "text": "System counts 150 requests in under 1 second from the same IP — way above the 30/5s limit."},
            {"icon": "🚨", "label": "Step 3 — Burst Alert Fires", "text": "IDS engine fires a CRITICAL alert and logs it to the dashboard in real time."},
            {"icon": "🚫", "label": "Step 4 — IP Blocked", "text": "Attacker IP is automatically blocked for 30 seconds. All their requests now get HTTP 429 error."},
            {"icon": "✅", "label": "Step 5 — System Protected", "text": "Real users continue unaffected. Block lifts after timeout and system self-heals."}
        ]
    }

@app.post("/simulate/brute-force")
async def sim_brute(request: Request):
    ip = client_ip(request)
    for _ in range(50): _login_attempts[ip].append(now())
    limiter.block(ip, 300)
    await emit_alert("BRUTE_FORCE", "critical",
        f"🔑 BRUTE FORCE DETECTED: 50 login attempts from {ip} — IP LOCKED OUT 5 minutes", ip=ip)
    await _log_sim("BRUTE_FORCE", ip, "50 simulated attempts")
    return {
        "attack": "Brute Force Login Attack",
        "icon": "🔑",
        "color": "#ffaa00",
        "alert_raised": True,
        "severity": "CRITICAL",
        "what_is_it": "A brute force attack tries thousands of password combinations rapidly until one works, like a thief trying every key on a keyring.",
        "steps": [
            {"icon": "🤖", "label": "Step 1 — Bot Starts Guessing", "text": "Attacker's script tries passwords: 'password123', 'admin', '123456'… one after another, very fast."},
            {"icon": "📈", "label": "Step 2 — Counter Increments", "text": "System counts login attempts from this IP. After 5 failures in 60 seconds, threshold is breached."},
            {"icon": "🚨", "label": "Step 3 — Alert Triggered", "text": "IDS fires CRITICAL alert: '50 login attempts from IP x.x.x.x'. Admin sees it instantly on dashboard."},
            {"icon": "⛔", "label": "Step 4 — IP Locked Out", "text": "IP is blocked for 5 minutes (300 seconds). Even correct password won't work during lockout."},
            {"icon": "🛡", "label": "Step 5 — Account Protected", "text": "Attacker gave up or waits. Real user can login normally after lockout expires."}
        ]
    }

@app.post("/simulate/session-misuse")
async def sim_session(request: Request):
    ip = client_ip(request)
    fake_sid = make_token()
    await emit_alert("SESSION_HIJACK", "critical",
        f"👤 SESSION HIJACK: Token {fake_sid[:16]}… stolen & replayed from {ip} — fingerprint MISMATCH",
        session_id=fake_sid, ip=ip)
    await _log_sim("SESSION_MISUSE", ip, f"Fake sid: {fake_sid[:16]}…")
    return {
        "attack": "Session Hijacking / Token Theft",
        "icon": "🕵️",
        "color": "#aa44ff",
        "alert_raised": True,
        "severity": "CRITICAL",
        "what_is_it": "An attacker intercepts your session token (like stealing your hotel key card) and uses it to pretend they are you.",
        "steps": [
            {"icon": "🍪", "label": "Step 1 — Token Exists", "text": "You log in. Server gives you a secret session token (like a VIP wristband) stored in your browser."},
            {"icon": "👂", "label": "Step 2 — Attacker Intercepts", "text": "Attacker sniffs network traffic or steals the token from an insecure connection. Now they have your wristband."},
            {"icon": "🎭", "label": "Step 3 — Attacker Pretends to be You", "text": "Attacker sends requests using YOUR token from THEIR device. They say 'I am you' to the server."},
            {"icon": "🔍", "label": "Step 4 — Fingerprint Mismatch Caught", "text": "Our IDS checks browser fingerprint (screen size, timezone, browser). It doesn't match! RED FLAG."},
            {"icon": "🚫", "label": "Step 5 — Session Killed", "text": "Server immediately invalidates the stolen token. Attacker is locked out. You're asked to re-login safely."}
        ]
    }

@app.get("/simulate/history")
async def sim_history():
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM sim_log ORDER BY timestamp DESC LIMIT 50"
        ) as cur:
            rows = [dict(r) for r in await cur.fetchall()]
    return {"history": rows}


# ═══════════════════════════════════════════════════════════════════════════
#  GEO MAP  ENDPOINTS  (for Leaflet map in dashboard)
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/api/geo/sessions")
async def api_geo_sessions():
    """All active sessions with real lat/lon for map pins."""
    ss = await sessions_all()
    result = []
    for s in ss:
        geo = await get_geo(s["ip"])
        result.append({
            "username":     s["username"],
            "ip":           s["ip"],
            "threat_score": s.get("threat_score", 0),
            "threat_level": threat_level(s.get("threat_score", 0)),
            "country":      geo["country"],
            "city":         geo["city"],
            "lat":          geo["lat"],
            "lon":          geo["lon"],
            "isp":          geo.get("isp", "—"),
            "flag":         geo.get("flag", "🌐"),
        })
    return {"points": result}

@app.get("/api/geo/alerts")
async def api_geo_alerts():
    """Recent alerts with geo coordinates for attack-origin visualization."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM alerts WHERE ip IS NOT NULL ORDER BY timestamp DESC LIMIT 40"
        ) as cur:
            rows = [dict(r) for r in await cur.fetchall()]
    result = []
    for r in rows:
        geo = await get_geo(r["ip"])
        result.append({
            **r,
            "lat":     geo["lat"],
            "lon":     geo["lon"],
            "country": geo["country"],
            "city":    geo["city"],
            "flag":    geo.get("flag", "🌐"),
        })
    return {"points": result}

# ═══════════════════════════════════════════════════════════════════════════
#  PAGE ROUTES
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
async def page_index(request: Request):
    return templates.TemplateResponse(request, "index.html")

@app.get("/chat/{room_id}", response_class=HTMLResponse)
async def page_chat(room_id: str, request: Request):
    return templates.TemplateResponse(request, "chat.html", {"room_id": room_id})

@app.get("/dashboard", response_class=HTMLResponse)
async def page_dashboard(request: Request):
    return templates.TemplateResponse(request, "dashboard.html")

@app.get("/health")
async def health():
    return {"status": "ok"}
