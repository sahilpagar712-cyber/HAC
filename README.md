# RedactZero (SecureX) — Full-Stack PII Sanitization & Security Workbench

RedactZero combines a **100% client-side deterministic PII detection & redaction engine** (React + Vite + Tailwind CSS) with a **Python FastAPI + SQLite backend** for persistent scan history, SHA-256 static file analysis, threat alert management, activity logging, passive network diagnostics, password strength evaluation, and user authentication.

---

## Architecture Overview

- **Frontend (`src/`):** React 18, Vite, Tailwind CSS, Lucide React
  - Client-side PII engine (`src/engine/luhn.js`, `src/engine/piiDetector.js`, `src/engine/redactor.js`)
  - Centralized API client (`src/api/client.js`) using `VITE_API_URL` (proxied via Vite `/api` -> `http://127.0.0.1:8000`)
- **Backend (`backend/`):** Python FastAPI, SQLAlchemy, SQLite (`redactzero.db`), JWT (`python-jose` + `passlib[bcrypt]`)
  - Interactive Swagger Docs: `http://localhost:8000/api/docs`
  - ReDoc: `http://localhost:8000/api/redoc`

---

## Installation

### 1. Backend Setup
```powershell
cd backend
pip install -r requirements.txt
copy .env.example .env
```

### 2. Frontend Setup
```powershell
npm install
copy .env.example .env
```

---

## Startup Commands

### Start Backend (Port 8000)
```powershell
cd backend
uvicorn main:app --reload --port 8000
```

### Start Frontend (Port 5173)
```powershell
npm run dev
```

Open **http://localhost:5173/** in your browser.

---

## API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Backend health check |
| `POST` | `/api/auth/register` | Register a new user & receive JWT |
| `POST` | `/api/auth/login` | Authenticate user & receive JWT |
| `POST` | `/api/auth/logout` | Revoke active user sessions |
| `GET` | `/api/auth/me` | Get authenticated user profile |
| `GET` | `/api/dashboard/stats` | Aggregated DB stats, recent scans, alerts, and activity |
| `POST` | `/api/scans/` | Save a PII scan summary & results to SQLite |
| `POST` | `/api/scans/upload` | Upload file for SHA-256 hash + static analysis |
| `GET` | `/api/scans/` | List scan history |
| `GET` | `/api/alerts/` | List threat alerts (filter by `severity`, `acknowledged`) |
| `PATCH` | `/api/alerts/{id}/acknowledge` | Acknowledge a threat alert |
| `GET` | `/api/activity/` | List activity logs (filter by `level`, `search`) |
| `POST` | `/api/activity/` | Append an activity log entry |
| `GET` | `/api/settings/` | Retrieve user settings (authenticated) |
| `PUT` | `/api/settings/` | Save user settings (authenticated) |
| `GET` | `/api/firewall/status` | Report CSP & application security posture |
| `GET` | `/api/network/info` | Passive local hostname & interface check |
| `POST` | `/api/privacy/check-password-strength` | Evaluate password strength without storing |

---

## Honest Feature Limitations

- **Firewall View:** Browser/web applications cannot and do not modify the host OS firewall (Windows Defender / `iptables`). `/api/firewall/status` accurately reports the application's CSP (`connect-src 'self'`) and security posture.
- **Network Monitor:** Performs only safe, passive local hostname and interface inspection via Python's `socket` module—no active port scanning or packet sniffing.
- **Password Strength Evaluator:** Evaluates password entropy/rules in memory without logging or storing the submitted password.
