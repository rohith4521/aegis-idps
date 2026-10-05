# AEGIS-IDPS Production Deployment Guide

This guide provides end-to-end instructions for deploying **AEGIS-IDPS** to **Vercel** (Frontend) and a persistent cloud container service (**Render, Railway, Fly.io, or VPS**) with **Managed PostgreSQL**.

---

## 🏛️ Deployment Architecture & Feasibility Analysis

AEGIS-IDPS consists of:
1. **Frontend**: React 18, TypeScript, Tailwind CSS, Recharts SPA built with Vite.
2. **Backend**: FastAPI (Python 3.11), SQLAlchemy 2.0 ORM, Alembic migrations, deterministic threat scoring, and safe mock prevention engine.
3. **Real-Time Streaming**: Persistent native WebSockets (`/ws/events`) with in-frame token auth, client queue limits, and background broadcasting.
4. **Database**: SQLite (Local Dev / Tests) and PostgreSQL (Production).

### Why Vercel Frontend + Persistent Backend?
- **Vercel Edge Network**: Ideal for the Vite SPA. Provides global CDN caching, instant asset delivery, and automatic client-side routing rewrites (`vercel.json`).
- **Serverless Limitations on Vercel for FastAPI**:
  - **No Persistent WebSockets**: Vercel Serverless Functions (AWS Lambda) terminate immediately after request completion. They cannot maintain open WebSocket tunnels for live SOC feeds.
  - **Stateless Concurrency**: In-memory subscription queues and `threading.RLock()` in the prevention engine require a stateful process.
  - **Ephemeral Disk**: Local SQLite is discarded between cold starts.
- **Recommended Production Stack**:
  - **Frontend**: Vercel (Free tier, global CDN)
  - **Backend**: Render, Railway, Fly.io, or Linux VPS (Persistent Python container with WebSockets)
  - **Database**: Managed PostgreSQL (Neon.tech, Supabase, Render Postgres, or Railway)

---

## 📦 Required Environment Variables

### 1. Frontend Environment Variables (Set in Vercel Dashboard)
| Variable | Value / Format | Purpose |
|---|---|---|
| `VITE_API_URL` | `https://your-backend.onrender.com/api` | Base URL for REST API endpoints. |
| `VITE_WS_URL` | `wss://your-backend.onrender.com/ws/events` | Secure WebSocket URL for live SOC telemetry. |
| `VITE_DEMO_MODE` | `"false"` | Set to `"false"` in production to hide evaluator quickfill buttons. |

> [!NOTE]
> Never place backend database URLs, passwords, or `SECRET_KEY` in `VITE_` variables. Only public client configuration belongs on Vercel.

---

### 2. Backend Environment Variables (Set in Render / Railway / Cloud Host)
| Variable | Value / Format | Purpose |
|---|---|---|
| `ENVIRONMENT` | `"production"` | Activates strict production validation rules. |
| `DEBUG` | `"false"` | Disables debug logs and development traces. |
| `DATABASE_URL` | `postgresql+psycopg2://user:pass@host:5432/dbname` | Connection string to your managed PostgreSQL instance. *(Supports `postgres://` auto-normalization)* |
| `SECRET_KEY` | Random 64-char string (e.g. `openssl rand -hex 32`) | Cryptographic secret for signing JWT access tokens. |
| `ADMIN_PASSWORD` | Strong password (e.g. `SocSecure2026!#Vault`) | Initial password for the production `admin` account. Default demo passwords (`Admin@123456`) are rejected in production. |
| `CORS_ORIGINS` | `https://your-aegis-idps.vercel.app` | Comma-separated list of allowed frontend domains. |
| `PREVENTION_PROVIDER`| `"mock"` | Keeps mock prevention active. Real firewall modification is strictly disabled. |
| `PREVENTION_ENABLED` | `"true"` | Enables automated threat assessment response ledger. |
| `DEMO_MODE` | `"false"` | Disables synthetic demo account creation in production. |

---

## 🚀 Step 1: Deploy Database (Managed PostgreSQL)

You can provision a free PostgreSQL instance in 2 minutes using **Neon.tech**, **Supabase**, or **Render**:

1. Create a free project at [Neon.tech](https://neon.tech) or [Supabase.com](https://supabase.com).
2. Copy your connection string:
   ```
   postgres://[user]:[password]@[endpoint].neon.tech/neondb?sslmode=require
   ```
3. Save this string for the backend `DATABASE_URL` configuration. *(Our engine automatically normalizes `postgres://` to `postgresql+psycopg2://`)*.

---

## 🚀 Step 2: Deploy Backend (Render / Railway / Fly.io / VPS)

### Option A: Deploy on Render (Recommended)
1. Fork or push this repository to your GitHub account.
2. Log in to [Render Dashboard](https://dashboard.render.com).
3. Click **New +** -> **Web Service**.
4. Connect your GitHub repository.
5. Configure the service settings:
   - **Name**: `aegis-idps-backend`
   - **Region**: Closest to your users (e.g. Oregon, Frankfurt, Singapore)
   - **Branch**: `main`
   - **Root Directory**: `backend`
   - **Runtime**: `Python 3`
   - **Build Command**:
     ```bash
     pip install -r requirements.txt && alembic upgrade head
     ```
   - **Start Command**:
     ```bash
     python -m app.database.init_db && uvicorn app.main:app --host 0.0.0.0 --port $PORT
     ```
6. Click **Advanced** -> **Add Environment Variable** and add the variables from the Backend table above.
7. Click **Create Web Service**.
8. Once deployed, note your service URL: `https://aegis-idps-backend.onrender.com`.

---

## 🚀 Step 3: Deploy Frontend (Vercel)

1. Log in to [Vercel Dashboard](https://vercel.com).
2. Click **Add New...** -> **Project**.
3. Import your GitHub repository.
4. In the configuration screen:
   - **Framework Preset**: `Vite` (automatically detected)
   - **Root Directory**: Click *Edit* and select `frontend`
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`
5. Expand **Environment Variables** and add:
   - `VITE_API_URL`: `https://aegis-idps-backend.onrender.com/api`
   - `VITE_WS_URL`: `wss://aegis-idps-backend.onrender.com/ws/events`
   - `VITE_DEMO_MODE`: `false`
6. Click **Deploy**.
7. Vercel will build and assign your domain: `https://your-aegis-idps.vercel.app`.

---

## 🔄 Step 4: Finalize CORS Configuration

Return to your backend host (e.g. Render Dashboard):
1. In the Environment Variables section, update `CORS_ORIGINS`:
   ```
   CORS_ORIGINS=https://your-aegis-idps.vercel.app
   ```
2. Save changes (Render will automatically redeploy the backend with the new allowed origin).

---

## 🧪 Step 5: Verification & Acceptance Testing

Open your deployed Vercel domain in your browser (`https://your-aegis-idps.vercel.app`):
1. **Login Verification**:
   - Log in with username `admin` and the strong `ADMIN_PASSWORD` you configured.
   - Verify access to `/dashboard`.
2. **WebSocket Health**:
   - Check the top header bar: verify `LIVE WS CONNECTED` is green.
3. **Incident Correlation & Threat Scoring**:
   - Navigate to `/incidents` and `/threats` to verify data loaded from the PostgreSQL database.
4. **Mock Prevention Safety**:
   - Navigate to `/prevention`. Verify provider indicates `Mock Provider` and host firewall alterations remain disabled.
5. **Client-Side Routing**:
   - Refresh the page while on `/incidents` or `/blocked-sources`.
   - Verify that Vercel serves the route correctly without any 404 error (handled by `frontend/vercel.json`).

---

## 📡 Remote Telemetry Sensor Integration (Local Lab to Cloud)

If running a live Suricata sensor on a local machine or physical gateway:
1. Ensure Suricata writes EVE JSON to `/var/log/suricata/eve.json`.
2. Use an authenticated forwarding script or cron to POST batches to your hosted backend:
   ```bash
   curl -X POST "https://your-backend.onrender.com/api/events/ingest" \
     -H "Authorization: Bearer <ADMIN_OR_ANALYST_JWT_TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{"events": [<EVE_JSON_OBJECTS>]}'
   ```
3. The cloud IDPS will parse, normalize, correlate, score, and push live alerts across all connected WebSocket dashboards in real time.
