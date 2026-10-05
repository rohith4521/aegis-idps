# REST & WebSocket API Specification

## 1. Authentication & Session Management

All protected endpoints require an HTTP `Authorization` header containing a valid JSON Web Token (JWT):
```http
Authorization: Bearer <access_token>
```

### POST `/api/auth/login`
Authenticate SOC operator and receive JWT access token.
- **Request Body**:
  ```json
  {
    "username": "admin",
    "password": "Admin@123456"
  }
  ```
- **Response `200 OK`**:
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIsIn...",
    "token_type": "bearer",
    "expires_in": 1440,
    "user": {
      "id": 1,
      "username": "admin",
      "email": "admin@aegis-idps.net",
      "role": "admin",
      "is_active": true,
      "created_at": "2026-10-04T12:00:00Z"
    }
  }
  ```

### GET `/api/auth/me`
Retrieve currently authenticated operator profile.
- **Response `200 OK`**: Returns `User` object.

---

## 2. Ingestion & Security Events

### POST `/api/events/ingest`
Ingest single or batch Suricata EVE JSON alerts and telemetry events.
- **Required Role**: `analyst` or `admin`
- **Request Body**:
  ```json
  {
    "events": [
      {
        "timestamp": "2026-10-04T14:32:00.000+0000",
        "event_type": "alert",
        "src_ip": "198.51.100.42",
        "dest_ip": "10.0.0.15",
        "dest_port": 22,
        "proto": "TCP",
        "alert": {
          "signature": "ET SCAN Potential SSH Brute Force",
          "category": "Attempted Information Leak",
          "severity": 2
        },
        "is_simulation": false
      }
    ]
  }
  ```
- **Response `200 OK`**:
  ```json
  {
    "status": "success",
    "ingested_count": 1,
    "events": [...]
  }
  ```

### GET `/api/events`
List normalized security events with pagination and filters.
- **Query Parameters**:
  - `skip` (int, default: 0)
  - `limit` (int, default: 50, max: 200)
  - `event_type` (string, optional: alert, http, dns, tls, flow)
  - `category` (string, optional)
  - `is_simulation` (bool, optional)
  - `source_ip` (string, optional)

### POST `/api/events/demo/generate`
Trigger synthetic lab attack scenarios.
- **Request Body**:
  ```json
  {
    "count": 10,
    "scenario": "mixed" // "ssh_bruteforce", "sqli", "rce", "portscan", "benign", "mixed"
  }
  ```

---

## 3. Incidents & Threat Scoring

### GET `/api/incidents`
List correlated incident dossiers with score filtering.
- **Query Parameters**: `severity`, `status`, `source_ip`, `skip`, `limit`

### GET `/api/incidents/{id}`
Retrieve complete incident dossier, including all linked events and threat score breakdown.

### PATCH `/api/incidents/{id}/status`
Update incident status and append analyst notes.
- **Request Body**:
  ```json
  {
    "status": "INVESTIGATING", // "ACTIVE", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"
    "notes": "Analyst investigating firewall logs."
  }
  ```

### GET `/api/threats`
List explainable threat score assessments.
- **Query Parameters**: `severity`, `min_score`, `skip`, `limit`

---

## 4. Blocked Sources & Prevention Engine

### GET `/api/blocked-sources`
List blocked IP addresses, statuses, and allowlist exemptions.
- **Query Parameters**: `status` (ACTIVE, EXPIRED, MANUALLY_UNBLOCKED, WHITELISTED), `ip`, `skip`, `limit`

### POST `/api/blocked-sources/{id}/unblock`
Manually unblock an active blocked IP source.
- **Required Role**: `analyst` or `admin`
- **Request Body**:
  ```json
  {
    "reason": "Security review verified false positive alarm."
  }
  ```

### POST `/api/blocked-sources/allowlist`
Add an IP address to the permanent allowlist.
- **Required Role**: `admin`
- **Request Body**:
  ```json
  {
    "ip": "10.0.0.1",
    "reason": "Default SOC gateway router"
  }
  ```

### GET `/api/prevention/status`
Retrieve prevention engine operational readiness, active provider, and threshold configuration.
- **Response `200 OK`**:
  ```json
  {
    "enabled": true,
    "provider": "mock",
    "auto_block_threshold": 80,
    "default_block_duration_minutes": 60,
    "active_blocks_count": 3,
    "whitelisted_count": 1,
    "real_firewall_enabled": false,
    "mode_description": "Safe Mock Prevention Provider"
  }
  ```

### GET `/api/prevention/policies`
Get current policy thresholds and response tiers.

### PATCH `/api/prevention/policies`
Update automated prevention thresholds (Admin only).
- **Required Role**: `admin`
- **Request Body**:
  ```json
  {
    "enabled": true,
    "auto_block_threshold": 80,
    "default_block_duration_minutes": 60
  }
  ```

---

## 5. Real-Time WebSocket Streaming

- **Endpoint**: `/ws/events`
- **Protocol Handshake**:
  Client initiates connection and immediately sends authentication frame:
  ```json
  {
    "type": "authenticate",
    "token": "<JWT_TOKEN>"
  }
  ```
  Server confirms:
  ```json
  {
    "type": "connection_established",
    "user": "analyst",
    "session_id": "ws-1728065000"
  }
  ```

- **Ping / Pong**:
  Client may send: `{"type": "ping"}`
  Server replies: `{"type": "pong", "timestamp": "..."}`

- **Versioned Broadcast Envelope**:
  All broadcasted events follow a strict, versioned schema:
  ```json
  {
    "event_type": "incident.created",
    "version": "1.0",
    "event_id": "a93df5eb-2679-4d6f-bf75-fa274438344e",
    "timestamp": "2026-10-04T14:35:10.123Z",
    "resource_id": 42,
    "data": {
      "id": 42,
      "title": "SQL Injection Surge on Database Cluster",
      "severity": "CRITICAL",
      "threat_score": 92,
      "source_ip": "198.51.100.77"
    }
  }
  ```
