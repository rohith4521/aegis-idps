# Security Architecture & DevSecOps Controls

## 1. Threat Modeling & Defense-in-Depth

AEGIS-IDPS is constructed with defense-in-depth security principles to protect both the operational monitoring platform and the host infrastructure upon which it runs.

```
                    ┌─────────────────────────┐
                    │     JWT Auth / RBAC     │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │ Ingestion Sanitization  │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │ Lab Simulation Boundary │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │ Allowlist Safety Guard  │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │ Mock Execution Sandbox  │
                    └─────────────────────────┘
```

---

## 2. Authentication & Authorization Security

1. **Role-Based Access Control (RBAC)**:
   - `admin`: Has permission to modify prevention thresholds, manage allowlists, generate simulated attacks, and manage system settings.
   - `analyst`: Can view telemetry, triage incidents, review threat factors, and perform manual unblocking with required audit justification.
2. **Cryptographic Password Hashing**:
   - Implemented using direct, native `bcrypt` salt and key derivation. Plaintext passwords or outdated algorithms (e.g. MD5/SHA1) are strictly rejected.
3. **Session Tokens**:
   - Short-lived JWT tokens signed with HMAC-SHA256 (`HS256`).
   - WebSockets require token verification via an initial connection payload rather than exposing tokens in query strings or access logs.

---

## 3. Strict Host Preservation & Lab Safety

To ensure that the IDPS can run safely on any instructor, reviewer, or student workstation without risk of accidental lockout:
- **Real OS Firewall Modifications are Permanently Disabled**: The system adapter `FirewallPreventionProvider` rejects commands unless explicitly enabled with lab authorization flags.
- **Default Mock Mode**: `MockPreventionProvider` is the default provider. It simulates and logs blocking actions into the database without altering kernel routing tables, iptables, nftables, or the Windows Defender Firewall.
- **Simulation Event Isolation**: Synthetic lab traffic generated for demonstrations is marked with `is_simulation: true`. Automated prevention evaluation strictly rejects simulation events:
  ```python
  if incident.is_simulation:
      return None, "Simulation safety check: Simulated events are excluded from automated prevention."
  ```

---

## 4. Input Validation & Injection Mitigation

- **Pydantic Model Enforcement**: All inbound REST JSON payloads are validated against strict Pydantic schemas. Unrecognized or extraneous fields are rejected.
- **IP Address Sanitization**: Target IP addresses are parsed via Python's standard `ipaddress` module. Injection payloads (e.g., shell meta-characters like `; rm -rf /` or command substitutes) fail validation before reaching any processing logic.
- **SQL Injection Prevention**: All database queries are executed via SQLAlchemy ORM parameterized statements. Raw SQL string concatenation is prohibited.

---

## 5. Audit Logging & Non-Repudiation

Every sensitive action performed on the platform is written to the immutable `audit_logs` table:
- **Actor Identity**: Captured from authenticated JWT claims (`current_user.username` or `AUTOMATED_PREVENTION_ENGINE`).
- **Action Type**: `SOURCE_BLOCKED`, `SOURCE_MANUALLY_UNBLOCKED`, `IP_ALLOWLISTED`, `POLICY_UPDATED`.
- **Reason & Justification**: Recorded alongside execution timestamps and provider results.
