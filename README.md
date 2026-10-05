# AEGIS-IDPS: Intelligent Intrusion Detection & Prevention System

[![Backend Test Suite](https://img.shields.io/badge/Backend%20Tests-60%20Passed%20(100%25)-emerald)](file:///c:/projects/cn%20pbl/backend/tests)
[![Frontend Build](https://img.shields.io/badge/Frontend-Vite%20%2B%20React%2018%20(Passing)-cyan)](file:///c:/projects/cn%20pbl/frontend)
[![Alembic Migrations](https://img.shields.io/badge/Alembic-Head%20(d449e463c746)-blue)](file:///c:/projects/cn%20pbl/backend/alembic/versions)
[![Safety Guarantee](https://img.shields.io/badge/Firewall%20Mode-Mock%20Lab%20Preservation-green)](file:///c:/projects/cn%20pbl/backend/app/prevention/provider.py)

**AEGIS-IDPS** is a production-grade, full-stack, modular Security Operations Center (SOC) web application built for high-performance network threat analysis. It integrates **Suricata EVE JSON telemetry**, an event normalization pipeline, real-time cross-event correlation, a **deterministic explainable threat scoring engine (0–100)**, an auditable pluggable prevention engine with **safe mock enforcement**, and a real-time reactive WebSocket dashboard.

---

## 🌟 Core System Differentiators

Traditional Intrusion Detection Systems (IDS) simply alert operators without contextualizing threat severity or mitigating attacks. Basic scripts attempt dangerous OS firewall rules that break host connectivity. **AEGIS-IDPS** addresses both shortcomings:

```
[Network Traffic / EVE JSON Telemetry]
                 │
                 ▼
[Normalizer & Credential Sanitizer]
                 │
                 ▼
[Correlation Engine (300s Sliding Window)] ────► [Incident Dossiers]
                 │
                 ▼
[Explainable Threat Scoring Engine (0-100)] ───► [Mathematical Factor Breakdown]
                 │
                 ▼
[Multi-Tier Automated Prevention Engine]
                 │
        ┌────────┴────────┐
        ▼                 ▼
[Safety Checks &     [MockPreventionProvider] ──► [Audited Action Ledger & Timed Expiry]
 Allowlist Guard]    (Host Firewall Safe)
```

1. **Explainable Deterministic Threat Scoring**: Eliminates opaque machine-learning claims. Every score from 0 to 100 is backed by a verifiable factor breakdown (e.g., base signature severity, repeated burst frequency, destination port sensitivity, protocol anomalies).
2. **Safe Lab Prevention Architecture**: Uses a pluggable `BasePreventionProvider` interface. The system defaults to `MockPreventionProvider`, recording full block decisions, expiry schedules, and audit entries while keeping real host firewall modifications strictly disabled.
3. **Lab Attack Simulator with Safety Guardrails**: Built-in simulator can generate synthetic SSH brute force, SQL injection, RCE, and port scan events. Every generated event is marked with `is_simulation: true` and is strictly excluded from triggering automated block actions.
4. **Resilient WebSocket Delivery**: Real-time updates utilize post-commit asynchronous event publishing with bounded per-client queues. Slow or unresponsive browser clients never block or degrade database operations.

---

## 🏗️ Technology Stack

| Layer | Technology | Key Highlights |
|---|---|---|
| **Backend Framework** | FastAPI (Python 3.11) | Fully typed Pydantic models, async endpoints, Swagger/OpenAPI docs |
| **Database & ORM** | SQLAlchemy 2.0 & SQLite / PostgreSQL | Dual-engine support, foreign key constraints, connection pooling |
| **Migrations** | Alembic | Tracked schema versioning, repeatable migrations |
| **Authentication & RBAC** | JWT (HS256) & bcrypt | Token expiry, `admin` vs `analyst` authorization tiers |
| **Real-Time Streaming** | Native WebSockets & Asyncio | Post-commit non-blocking dispatch, bounded queue buffer (100 msgs) |
| **Frontend UI** | React 18, TypeScript, Vite | Tailwind CSS cyber SOC theme, Recharts metrics visualization |
| **Containerization** | Docker, Docker Compose, Nginx | Multi-stage production builds, healthchecks |

---

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.11+
- Node.js 18+ and npm
- (Optional) Docker & Docker Compose

### 1. Backend Setup & Startup
```bash
# Navigate to backend directory
cd backend

# Create virtual environment and activate
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run migrations and seed database
alembic upgrade head
python -m app.database.init_db

# Start FastAPI server on port 8000
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 2. Frontend Setup & Startup
```bash
# In a separate terminal, navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Start Vite development server with API proxy
npm run dev
```
Open **[http://localhost:5173](http://localhost:5173)** in your browser.

---

## 🔑 Default Evaluator Credentials

The database seeder automatically initializes two role-separated operator accounts for testing:

| Role | Username | Password | Capabilities |
|---|---|---|---|
| **SOC Administrator** | `admin` | `Admin@123456` | Full access: Configure prevention policies, allowlist IPs, unblock targets, trigger simulation |
| **Security Analyst** | `analyst` | `Analyst@123456` | Triage access: Inspect incidents, review threat scoring breakdowns, manual unblock, view audit logs |

---

## 🧪 Verified Test Suite & Quality Status

AEGIS-IDPS includes comprehensive automated test coverage spanning authentication, event ingestion, threat scoring, incident correlation, prevention policies, and WebSockets.

Run the test suite from the backend directory:
```bash
cd backend
.venv\Scripts\pytest -v
```
**Backend Test Results: 60 passed, 0 failed (100% pass rate in ~6s).**  
**Frontend Production Build: `tsc -b && vite build` (Exit Code 0, cleanly bundled).**  
**Live Browser SOC Traversal: Fully executed and verified via headless browser automation.**

---

## ⚠️ Verification Scope & Known Limitations

To maintain absolute academic and engineering integrity, the verification boundaries of this implementation are transparently documented:

| Feature / Subsystem | Verification Status | Details |
|---|---|---|
| **SQLite DB & Alembic** | **VERIFIED (Active)** | Fresh DB initialization, migrations (up to `d449e463c746`), foreign key pragma, and transactional rollback fully tested. |
| **Mock Prevention Provider** | **VERIFIED (Active)** | Safe lab simulation, allowlist bypass, duplicate block prevention, expiry cleanup, and failed unblock scenarios fully tested. |
| **Real-time WebSockets** | **VERIFIED (Active)** | Handshake auth, post-commit publishing, payload credential sanitization, client queue limits, and disconnect cleanup verified. |
| **React 18 + Vite SOC UI** | **VERIFIED (Active)** | All pages, drawer modals, threat score breakdowns, origin badges (REAL/SIM/MIXED), and RBAC controls tested in browser. |
| **PostgreSQL Support** | *Implemented, Unverified* | SQLAlchemy models and data types are dialect-agnostic; PostgreSQL server was not active in this local test environment. |
| **Docker Compose** | *Configured, Unverified* | Multi-stage Dockerfile and `docker-compose.yml` configured; Docker Desktop daemon was not running during audit. |
| **Live Host Firewall** | *Disabled by Design* | Real OS firewall alteration (`iptables`/`netsh`) is strictly disabled to prevent host lockout in educational environments. |
| **Live Suricata Interface** | *File Parser Verified* | Standard EVE JSON schema validated; live network sniffing driver (`AF_PACKET`) was not bound to physical hardware. |

---

## 📚 Detailed Documentation

- **[System Architecture](docs/ARCHITECTURE.md)**: Data pipelines, correlation logic, and prevention engine design.
- **[REST & WebSocket API Guide](docs/API.md)**: Complete endpoint contracts, payload examples, and WebSocket protocol.
- **[Database Schema & Migrations](docs/DATABASE.md)**: Tables, relational keys, indexes, and Alembic tracking.
- **[Security & DevSecOps Model](docs/SECURITY.md)**: Defense-in-depth, token security, sanitization, and lab safety.
- **[Demonstration & Evaluator Script](docs/DEMO.md)**: Step-by-step evaluator walkthrough for project review.
- **[Deployment & Setup Guide](docs/SETUP.md)**: Local, virtualenv, and Docker Compose instructions.
- **[Production Cloud & Vercel Deployment](docs/DEPLOYMENT.md)**: End-to-end Vercel and managed PostgreSQL deployment walkthrough.
