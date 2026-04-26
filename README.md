# SecureChat — Secure Real-Time Chat with Anti-Sniffing, DDoS & Brute Force Protection

## Files
```
securechat/
├── main.py               ← entire backend (FastAPI + all logic)
├── requirements.txt
├── README.md
└── templates/
    ├── index.html        ← landing + login
    ├── chat.html         ← real-time chat UI
    └── dashboard.html    ← admin panel
```

---

## Run Locally

```bash
pip install -r requirements.txt
uvicorn main:app --reload
# → http://127.0.0.1:8000
```

---

## Deploy on Render (Manual)

1. Push this folder to a GitHub repo
2. Go to https://render.com → **New → Web Service**
3. Connect your GitHub repo
4. Set:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
   - **Environment:** Python 3
5. Click **Deploy**

> The `$PORT` variable is injected automatically by Render.

---

## Pages

| URL | Description |
|-----|-------------|
| `/` | Login / landing |
| `/chat/general` | Chat room |
| `/dashboard` | Admin panel |

## API

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/register` | Create session |
| POST | `/auth/logout` | Invalidate session |
| WS | `/ws/chat/{room}` | Real-time chat |
| WS | `/ws/dashboard` | Live alert stream |
| GET | `/api/stats` | Aggregate stats |
| GET | `/api/sessions` | Active sessions |
| GET | `/api/alerts` | IDS alert log |
| GET | `/api/logs` | HTTP request log |
| POST | `/api/kick/{sid}` | Force-kick session |
| POST | `/simulate/ddos` | DDoS simulation |
| POST | `/simulate/brute-force` | Brute force sim |
| POST | `/simulate/session-misuse` | Session theft sim |

## Security Features

- **Session Binding** — Token ↔ SHA-256(fingerprint) ↔ IP; mismatch = alert
- **Canary Probe Tokens** — Silent tokens detect session theft / replay
- **DDoS Guard** — 120 req/min sliding window + 30 req/5s burst, then IP block
- **Brute Force Guard** — 5 attempts per 60s then locked
- **WebSocket Guard** — 5 messages per 2s per session
- **Geo-IP Tracking** — Location change detection via ipapi.co
- **Behavioral Analysis** — Bot UA detection, repeated requests, high volume
- **QR Room Access** — Single-use 5-minute device-bound tokens
