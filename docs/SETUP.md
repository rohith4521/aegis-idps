# Deployment & Environment Setup Guide

## 1. Local Development Setup

### System Requirements
- Python 3.11+
- Node.js 18+ and npm 9+
- Git

### Step-by-Step Installation:

1. **Clone the repository**:
   ```bash
   git clone <repository_url>
   cd "cn pbl"
   ```

2. **Configure Backend Environment**:
   ```bash
   cd backend
   python -m venv .venv
   
   # On Windows (PowerShell):
   .venv\Scripts\activate
   # On Linux/macOS:
   source .venv/bin/activate

   pip install --upgrade pip
   pip install -r requirements.txt
   ```

3. **Database Initialization**:
   ```bash
   # Run migrations
   alembic upgrade head

   # Seed default administrative credentials and detection rules
   python -m app.database.init_db
   ```

4. **Start Backend Server**:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```
   FastAPI interactive OpenAPI documentation is accessible at `http://localhost:8000/docs`.

5. **Start Frontend Server**:
   ```bash
   # In a separate terminal window:
   cd frontend
   npm install
   npm run dev
   ```
   The application dashboard will open at `http://localhost:5173`.

---

## 2. Docker Compose Deployment

A containerized stack is provided in the repository root for one-command deployment.

### Starting the Stack:
```bash
docker-compose up --build -d
```

### Services Deployed:
- `backend`: FastAPI Python 3.11 service exposed on port 8000.
- `frontend`: High-performance Nginx web server serving Vite production build on port 80.
- `suricata` (optional): Suricata IDS engine with shared EVE JSON log volume.

### Stopping the Stack:
```bash
docker-compose down
```

---

## 3. Configuration Environment Variables

Key parameters configurable via environment variables or a `.env` file in the `backend/` directory:

| Variable | Default Value | Description |
|---|---|---|
| `SECRET_KEY` | `dev-insecure-secret-key-change-in-production` | Secret key for JWT signing |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `1440` | JWT token validity lifetime (24h) |
| `DATABASE_URL` | `sqlite:///./idps.db` | Database connection string (PostgreSQL or SQLite) |
| `PREVENTION_PROVIDER` | `mock` | Prevention provider adapter (`mock` or `firewall`) |
| `PREVENTION_ENABLED` | `true` | Automated policy evaluation state |
| `AUTO_PREVENTION_THRESHOLD` | `80` | Threat score threshold required to trigger mock blocking |
| `DEFAULT_BLOCK_DURATION_MINUTES` | `60` | Timed lease duration before automated block expires |
