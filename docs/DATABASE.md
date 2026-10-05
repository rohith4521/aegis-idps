# Database Architecture & Migration Specification

## 1. Relational Entity-Relationship Model

AEGIS-IDPS leverages an enterprise relational schema supported across both SQLite (for local lab environments) and PostgreSQL (for production clustering).

```mermaid
erDiagram
    USERS ||--o{ AUDIT_LOGS : performs
    SECURITY_EVENTS }o--|| INCIDENTS : correlated_into
    INCIDENTS ||--o| THREAT_SCORES : evaluated_by
    INCIDENTS ||--o{ PREVENTION_ACTIONS : triggers
    BLOCKED_SOURCES ||--o{ PREVENTION_ACTIONS : target_of

    USERS {
        int id PK
        string username UK
        string email UK
        string hashed_password
        string full_name
        string role "admin | analyst"
        boolean is_active
        datetime created_at
    }

    SECURITY_EVENTS {
        int id PK
        datetime timestamp
        string source_ip
        string destination_ip
        int source_port
        int destination_port
        string protocol
        string event_type
        string signature
        string category
        int severity
        string action
        boolean is_simulation
        int incident_id FK
    }

    INCIDENTS {
        int id PK
        string title
        string category
        string severity "LOW | MEDIUM | HIGH | CRITICAL"
        string status "ACTIVE | INVESTIGATING | RESOLVED | FALSE_POSITIVE"
        int threat_score
        int confidence
        string source_ip
        string destination_ip
        datetime first_seen
        datetime last_seen
        int event_count
        boolean is_simulation
    }

    THREAT_SCORES {
        int id PK
        int incident_id FK, UK
        int score
        string severity
        int confidence
        json factors
        datetime created_at
    }

    BLOCKED_SOURCES {
        int id PK
        string ip UK
        string reason
        string severity
        int threat_score
        datetime blocked_time
        datetime expiry
        string status "ACTIVE | EXPIRED | MANUALLY_UNBLOCKED | WHITELISTED"
        boolean is_whitelisted
        string provider
        boolean is_simulation
        string created_by
    }

    PREVENTION_ACTIONS {
        int id PK
        int incident_id FK
        string action "BLOCK | UNBLOCK | ALLOWLIST | WHITELIST_BYPASS"
        string target
        string reason
        int duration_minutes
        string status "EXECUTED | FAILED | REVERTED"
        string provider
        boolean is_simulation
        datetime executed_at
    }
```

---

## 2. Table Specifications & Indexes

### `security_events`
- Primary table capturing normalized raw alerts and protocol telemetry.
- **Indexes**:
  - `ix_security_events_source_ip` (`source_ip`): Fast lookups for correlation.
  - `ix_security_events_timestamp` (`timestamp`): Sliding window filtering.
  - `ix_security_events_incident_id` (`incident_id`): Rapid dossier joining.

### `incidents`
- High-level security incident dossiers aggregated by the correlation engine.
- **Indexes**:
  - `ix_incidents_source_ip` (`source_ip`)
  - `ix_incidents_status` (`status`)
  - `ix_incidents_severity` (`severity`)
  - `ix_incidents_last_seen` (`last_seen`)

### `blocked_sources`
- Tracks IP block leases, expiry timestamps, and permanent allowlist entries.
- **Unique Constraint**: `uq_blocked_sources_ip` (`ip`)
- **Indexes**: `ix_blocked_sources_status`, `ix_blocked_sources_expiry`

### `prevention_actions`
- Immutable audit ledger recording every automated and manual prevention decision.
- **Indexes**: `ix_prevention_actions_target`, `ix_prevention_actions_executed_at`

---

## 3. Alembic Migration History

Schema evolution is tracked using Alembic migrations:

| Revision ID | Description | Key Changes |
|---|---|---|
| `e14a8219c670` | Initial baseline | Created `users`, `security_events`, `detection_rules`, `system_settings`, `audit_logs` |
| `a793c21b93f2` | Incidents & Scoring | Created `incidents`, `threat_scores`; added `incident_id` foreign key on `security_events` |
| `d449e463c746` (head) | Safe Prevention & Blocking | Created `blocked_sources`, `prevention_actions`; added `is_simulation` columns |
