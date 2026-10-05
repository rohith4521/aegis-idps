# Evaluator & Demonstration Walkthrough Script

This guide outlines a step-by-step evaluation procedure for academic reviewers, professors, and project evaluators testing **AEGIS-IDPS**.

---

## 🎬 5-Minute Demonstration Walkthrough

### Step 1: Login & Role Inspection
1. Navigate to `http://localhost:5173/login`.
2. Notice the Quick Credential buttons for evaluators. Click **Admin** (`admin` / `Admin@123456`) and click **Sign In To Console**.
3. Verify that the top bar indicates `LIVE WS CONNECTED` and `PREVENTION: MOCK LAB MODE`.

---

### Step 2: Triggering Attack Simulation
1. In the left navigation sidebar under the user profile, locate the **Lab Attack Simulator** card.
2. Click **Trigger Simulation**.
3. Watch the live counter increase as 8 synthetic lab events are ingested.
4. Switch to the **Security Events** tab (`/events`).
5. Notice that all simulated events are highlighted with a cyan **[SIMULATION]** badge, demonstrating safe lab telemetry tagging.

---

### Step 3: Inspecting Correlated Incidents & Triage
1. Click **Incidents & Triage** in the sidebar (`/incidents`).
2. Observe how raw events have been grouped by `source_ip` and `category` within a 300-second window.
3. Click an incident to open the detailed drawer:
   - View the linked Suricata events.
   - Inspect the first-seen and last-seen timestamps.
   - Update the status from `ACTIVE` to `INVESTIGATING` with a triage note.
   - Notice the status updates immediately in the dashboard without a page reload.

---

### Step 4: Reviewing Explainable Threat Scoring
1. Click **Threat Scores** in the sidebar (`/threats`).
2. Observe the calculated score (0–100), severity tier, and engine confidence percentage.
3. Click on any threat row to expand the **Mathematical Factor Breakdown**:
   - See how each point was earned (e.g. `+40 Base Signature Weight`, `+25 Burst Frequency Surge`, `+15 Destination Port Sensitivity`).
   - Confirm that scoring is deterministic and rule-based rather than an unverified black-box ML model.

---

### Step 5: Auditing the Safe Prevention Engine
1. Click **Prevention Engine** in the sidebar (`/prevention`).
2. Confirm the **Safe Lab Preservation Guarantee** banner:
   - Host firewall modification: **DISABLED**.
   - Active provider: **Mock Prevention Provider**.
   - Auto-block threshold: **Score >= 80 (CRITICAL only)**.
3. Review the **Multi-Tier Automated Response Policy Matrix** explaining the LOW, MEDIUM, HIGH, and CRITICAL response actions.
4. Review the **Prevention Decision & Audit Ledger** showing every automated mock block, duration, and status.

---

### Step 6: Managing Blocked Sources & Allowlists
1. Click **Blocked Sources** in the sidebar (`/blocked-sources`).
2. Click **Allowlist IP** (top-right button):
   - Enter `10.0.0.1` and reason `"Core Lab Gateway"`.
   - Click **Add to Allowlist**.
3. For any active blocked IP, click the **Unblock** action button:
   - Provide an analyst reason: `"Verified test completion"`.
   - Confirm unblock.
   - Observe the source change status to `MANUALLY_UNBLOCKED` in real time.

---

### Step 7: Verifying Live WebSocket Streaming
1. Open two browser windows side-by-side on `http://localhost:5173`.
2. In Window A, trigger another attack simulation or manually update an incident status.
3. In Window B, observe that the new events, score evaluations, and incident updates appear instantly via the WebSocket connection without refreshing the page.
