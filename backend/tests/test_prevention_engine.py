import pytest
from datetime import datetime, timedelta, timezone
from fastapi import status
from app.models.incident import Incident
from app.models.blocked_source import BlockedSource
from app.models.prevention_action import PreventionAction
from app.models.system_setting import SystemSetting
from app.prevention.engine import PreventionEngine
from app.prevention.provider import MockPreventionProvider, FirewallPreventionProvider


def test_mock_provider_success():
    provider = MockPreventionProvider()
    res = provider.block_source("198.51.100.42", "Test block", duration_minutes=30, is_simulation=True)
    assert res.success is True
    assert res.provider == "mock"
    assert res.status == "EXECUTED"
    assert res.is_simulation is True
    assert "mock mode" in res.message.lower()

    unblock_res = provider.unblock_source("198.51.100.42", "Test unblock", is_simulation=True)
    assert unblock_res.success is True
    assert unblock_res.action == "UNBLOCK"


def test_firewall_provider_disabled_safety():
    provider = FirewallPreventionProvider(authorized_in_lab=False)
    res = provider.block_source("198.51.100.42", "Attempted firewall block", duration_minutes=30, is_simulation=False)
    assert res.success is False
    assert res.provider == "firewall"
    assert res.status == "FAILED"
    assert "not authorized" in res.message.lower()


def test_policy_tiers_behavior(db):
    # Low score (20)
    inc_low = Incident(
        title="Low event", category="Telemetry", severity="LOW",
        threat_score=20, confidence=70, source_ip="198.51.100.11",
        first_seen=datetime.utcnow(), last_seen=datetime.utcnow(),
        is_simulation=False
    )
    db.add(inc_low)
    db.commit()
    act, msg = PreventionEngine.evaluate_and_prevent(db, inc_low)
    assert act is None
    assert "LOG_ONLY" in msg

    # Medium score (45)
    inc_med = Incident(
        title="Med event", category="Suspicious", severity="MEDIUM",
        threat_score=45, confidence=75, source_ip="198.51.100.22",
        first_seen=datetime.utcnow(), last_seen=datetime.utcnow(),
        is_simulation=False
    )
    db.add(inc_med)
    db.commit()
    act_m, msg_m = PreventionEngine.evaluate_and_prevent(db, inc_med)
    assert act_m is None
    assert "ALERT_ONLY" in msg_m

    # High score (70)
    inc_high = Incident(
        title="High event", category="Port Scan", severity="HIGH",
        threat_score=70, confidence=80, source_ip="198.51.100.33",
        first_seen=datetime.utcnow(), last_seen=datetime.utcnow(),
        is_simulation=False
    )
    db.add(inc_high)
    db.commit()
    act_h, msg_h = PreventionEngine.evaluate_and_prevent(db, inc_high)
    assert act_h is None
    assert "MONITOR_ONLY" in msg_h

    # Critical score (90) -> Automated Mock Block
    inc_crit = Incident(
        title="Critical event", category="Exploit", severity="CRITICAL",
        threat_score=90, confidence=95, source_ip="198.51.100.44",
        first_seen=datetime.utcnow(), last_seen=datetime.utcnow(),
        is_simulation=False
    )
    db.add(inc_crit)
    db.commit()
    act_c, msg_c = PreventionEngine.evaluate_and_prevent(db, inc_crit)
    assert act_c is not None
    assert act_c.status == "EXECUTED"
    assert act_c.is_simulation is False
    assert act_c.provider == "mock"

    # Verify BlockedSource entry
    blocked = db.query(BlockedSource).filter(BlockedSource.ip == "198.51.100.44").first()
    assert blocked is not None
    assert blocked.status == "ACTIVE"
    assert blocked.threat_score == 90
    assert blocked.is_simulation is False


def test_simulated_events_never_trigger_prevention(db):
    inc_sim = Incident(
        title="[SIMULATION] Simulated RCE Exploit",
        category="Exploit",
        severity="CRITICAL",
        threat_score=99,
        confidence=95,
        source_ip="198.51.100.99",
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        is_simulation=True
    )
    db.add(inc_sim)
    db.commit()
    act, msg = PreventionEngine.evaluate_and_prevent(db, inc_sim)
    assert act is None
    assert "Simulation safety check" in msg
    assert db.query(BlockedSource).filter(BlockedSource.ip == "198.51.100.99").first() is None


def test_allowlisted_source_never_blocked(db):
    ip = "192.168.1.100"
    whitelist_entry = BlockedSource(
        ip=ip, reason="Internal trusted monitoring host", severity="LOW",
        threat_score=0, blocked_time=datetime.utcnow(), status="WHITELISTED",
        is_whitelisted=True
    )
    db.add(whitelist_entry)
    db.commit()

    inc = Incident(
        title="Critical false alarm", category="Exploit", severity="CRITICAL",
        threat_score=100, confidence=95, source_ip=ip,
        first_seen=datetime.utcnow(), last_seen=datetime.utcnow(),
        is_simulation=False
    )
    db.add(inc)
    db.commit()

    act, msg = PreventionEngine.evaluate_and_prevent(db, inc)
    assert act is not None
    assert act.action == "WHITELIST_BYPASS"
    assert "allowlisted" in msg.lower()
    
    entry = db.query(BlockedSource).filter(BlockedSource.ip == ip).first()
    assert entry.is_whitelisted is True
    assert entry.status == "WHITELISTED"


def test_prevention_disabled_safety(db):
    setting = db.query(SystemSetting).filter(SystemSetting.key == "prevention_enabled").first()
    if setting:
        setting.value = "false"
        db.commit()

    inc = Incident(
        title="RCE attack", category="Exploit", severity="CRITICAL",
        threat_score=95, confidence=90, source_ip="203.0.113.12",
        first_seen=datetime.utcnow(), last_seen=datetime.utcnow(),
        is_simulation=False
    )
    db.add(inc)
    db.commit()

    act, msg = PreventionEngine.evaluate_and_prevent(db, inc)
    assert act is None
    assert "disabled" in msg.lower()

    if setting:
        setting.value = "true"
        db.commit()


def test_duplicate_active_block_prevention(db):
    ip = "198.51.100.88"
    inc1 = Incident(
        title="First wave", category="Brute Force", severity="CRITICAL",
        threat_score=85, confidence=80, source_ip=ip,
        first_seen=datetime.utcnow(), last_seen=datetime.utcnow(),
        is_simulation=False
    )
    db.add(inc1)
    db.commit()
    act1, _ = PreventionEngine.evaluate_and_prevent(db, inc1)
    assert act1 is not None

    inc2 = Incident(
        title="Second wave", category="Brute Force", severity="CRITICAL",
        threat_score=95, confidence=85, source_ip=ip,
        first_seen=datetime.utcnow(), last_seen=datetime.utcnow(),
        is_simulation=False
    )
    db.add(inc2)
    db.commit()
    act2, msg2 = PreventionEngine.evaluate_and_prevent(db, inc2)
    assert act2 is None
    assert "already has an active block" in msg2

    blocks = db.query(BlockedSource).filter(BlockedSource.ip == ip).all()
    assert len(blocks) == 1
    assert blocks[0].threat_score == 95


def test_expiry_cleanup(db):
    now = datetime.utcnow()
    # Add an expired block
    expired_block = BlockedSource(
        ip="203.0.113.77",
        reason="Test expired block",
        severity="HIGH",
        threat_score=85,
        blocked_time=now - timedelta(hours=2),
        expiry=now - timedelta(minutes=10),
        status="ACTIVE",
        is_whitelisted=False,
        provider="mock"
    )
    db.add(expired_block)
    db.commit()

    cleaned_count = PreventionEngine.cleanup_expired_blocks(db)
    assert cleaned_count >= 1

    db.refresh(expired_block)
    assert expired_block.status == "EXPIRED"


def test_manual_unblock_and_api(client, db):
    # 1. Login
    login_resp = client.post(
        "/api/auth/login",
        json={"username": "analyst", "password": "Analyst@123456"}
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Ingest real critical events to trigger automated block
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+0000")
    events = [
        {
            "timestamp": now_str,
            "event_type": "alert",
            "src_ip": "198.51.100.150",
            "dest_ip": "10.0.0.5",
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "signature": "ET EXPLOIT Remote Command Execution Shell Spawn Attempt",
                "category": "attempted-admin",
                "severity": 1,
            },
            "is_simulation": False
        }
        for _ in range(6)
    ]
    ingest_resp = client.post(
        "/api/events/ingest",
        json={"events": events},
        headers=headers
    )
    assert ingest_resp.status_code == status.HTTP_200_OK

    # 3. GET /api/blocked-sources
    resp = client.get("/api/blocked-sources", headers=headers)
    assert resp.status_code == status.HTTP_200_OK
    items = resp.json()
    assert len(items) >= 1
    active_block = next((i for i in items if i["status"] == "ACTIVE"), items[0])

    # 4. POST /api/blocked-sources/{id}/unblock
    unblock_resp = client.post(
        f"/api/blocked-sources/{active_block['id']}/unblock",
        json={"reason": "Security analyst verified lab test completion."},
        headers=headers
    )
    assert unblock_resp.status_code == status.HTTP_200_OK
    assert unblock_resp.json()["status"] == "MANUALLY_UNBLOCKED"

    # 5. GET /api/prevention/status
    status_resp = client.get("/api/prevention/status", headers=headers)
    assert status_resp.status_code == status.HTTP_200_OK
    st = status_resp.json()
    assert st["provider"] == "mock"
    assert st["real_firewall_enabled"] is False

    # 6. GET /api/prevention/actions
    act_resp = client.get("/api/prevention/actions", headers=headers)
    assert act_resp.status_code == status.HTTP_200_OK
    assert len(act_resp.json()) >= 1


def test_invalid_ip_rejection_safety(db):
    inc_invalid = Incident(
        title="Malformed IP Exploit",
        category="Exploit",
        severity="CRITICAL",
        threat_score=95,
        confidence=90,
        source_ip="999.999.999.999",
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        is_simulation=False
    )
    db.add(inc_invalid)
    db.commit()

    act, reason = PreventionEngine.evaluate_and_prevent(db, inc_invalid)
    assert act is None
    assert "Invalid source IP address" in reason
    assert db.query(BlockedSource).filter(BlockedSource.ip == "999.999.999.999").first() is None


def test_analyst_forbidden_to_update_policies(client):
    # 1. Analyst login
    analyst_login = client.post(
        "/api/auth/login",
        json={"username": "analyst", "password": "Analyst@123456"}
    )
    analyst_token = analyst_login.json()["access_token"]
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}

    # Analyst tries to change prevention policy -> 403 Forbidden
    patch_resp = client.patch(
        "/api/prevention/policies",
        json={"auto_block_threshold": 75},
        headers=analyst_headers
    )
    assert patch_resp.status_code == status.HTTP_403_FORBIDDEN

    # 2. Admin login
    admin_login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "Admin@123456"}
    )
    admin_token = admin_login.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Admin updates policy -> 200 OK
    admin_patch = client.patch(
        "/api/prevention/policies",
        json={"auto_block_threshold": 85},
        headers=admin_headers
    )
    assert admin_patch.status_code == status.HTTP_200_OK
    assert "updated successfully" in admin_patch.json()["message"]


def test_provider_failure_reporting(db):
    # Force provider to firewall (which is disabled)
    setting = db.query(SystemSetting).filter(SystemSetting.key == "prevention_provider").first()
    if setting:
        setting.value = "firewall"
        db.commit()

    inc = Incident(
        title="Critical event with disabled firewall provider",
        category="Exploit",
        severity="CRITICAL",
        threat_score=95,
        confidence=95,
        source_ip="198.51.100.222",
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        is_simulation=False
    )
    db.add(inc)
    db.commit()

    act, msg = PreventionEngine.evaluate_and_prevent(db, inc)
    assert act is not None
    assert act.status == "FAILED"
    assert "not authorized" in msg.lower()

    # BlockedSource must NOT be active
    blocked = db.query(BlockedSource).filter(BlockedSource.ip == "198.51.100.222").first()
    assert blocked is None

    # Reset provider setting back to mock
    if setting:
        setting.value = "mock"
        db.commit()


def test_ipv6_validation_and_rejection():
    # Valid IPv6
    valid_ipv6 = "2001:db8:85a3::8a2e:370:7334"
    assert PreventionEngine.validate_ip_address(valid_ipv6) == valid_ipv6

    # Invalid IPv6
    invalid_ipv6_1 = "2001:db8:::1"
    assert PreventionEngine.validate_ip_address(invalid_ipv6_1) is None

    invalid_ipv6_2 = "::gggg"
    assert PreventionEngine.validate_ip_address(invalid_ipv6_2) is None


def test_failed_manual_unblock_scenarios(client, db):
    # 1. Login as analyst
    login_resp = client.post(
        "/api/auth/login",
        json={"username": "analyst", "password": "Analyst@123456"}
    )
    headers = {"Authorization": f"Bearer {login_resp.json()['access_token']}"}

    # 2. Non-existent record unblock -> 404
    resp_404 = client.post(
        "/api/blocked-sources/999999/unblock",
        json={"reason": "Testing non-existent ID"},
        headers=headers
    )
    assert resp_404.status_code == status.HTTP_404_NOT_FOUND
    assert "not found" in resp_404.json()["detail"].lower()

    # 3. Create a non-active blocked source
    inactive_block = BlockedSource(
        ip="198.51.100.199",
        reason="Test expired block",
        severity="HIGH",
        threat_score=85,
        blocked_time=datetime.utcnow() - timedelta(hours=2),
        expiry=datetime.utcnow() - timedelta(hours=1),
        status="EXPIRED",
        is_whitelisted=False,
        provider="mock"
    )
    db.add(inactive_block)
    db.commit()

    # 4. Attempt unblock on non-active source -> 400 Bad Request
    resp_400 = client.post(
        f"/api/blocked-sources/{inactive_block.id}/unblock",
        json={"reason": "Attempting unblock on expired entry"},
        headers=headers
    )
    assert resp_400.status_code == status.HTTP_400_BAD_REQUEST
    assert "not currently active" in resp_400.json()["detail"].lower()


def test_allowlist_authorization_rbac(client):
    # 1. Analyst login
    analyst_login = client.post(
        "/api/auth/login",
        json={"username": "analyst", "password": "Analyst@123456"}
    )
    analyst_headers = {"Authorization": f"Bearer {analyst_login.json()['access_token']}"}

    # Analyst tries to allowlist -> 403 Forbidden
    resp_forbid = client.post(
        "/api/blocked-sources/allowlist",
        json={"ip": "10.0.0.99", "reason": "Analyst attempted allowlist"},
        headers=analyst_headers
    )
    assert resp_forbid.status_code == status.HTTP_403_FORBIDDEN

    # 2. Admin login
    admin_login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "Admin@123456"}
    )
    admin_headers = {"Authorization": f"Bearer {admin_login.json()['access_token']}"}

    # Admin allowlists -> 200 OK
    resp_ok = client.post(
        "/api/blocked-sources/allowlist",
        json={"ip": "10.0.0.99", "reason": "Admin verified infrastructure"},
        headers=admin_headers
    )
    assert resp_ok.status_code == status.HTTP_200_OK
    assert resp_ok.json()["is_whitelisted"] is True


def test_concurrent_prevention_requests_same_ip(db):
    import concurrent.futures

    ip = "198.51.100.177"
    inc = Incident(
        title="Concurrent exploit attack",
        category="Exploit",
        severity="CRITICAL",
        threat_score=95,
        confidence=90,
        source_ip=ip,
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        is_simulation=False
    )
    db.add(inc)
    db.commit()

    results = []
    def attempt_prevent():
        act, msg = PreventionEngine.evaluate_and_prevent(db, inc)
        return act, msg

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(attempt_prevent) for _ in range(5)]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    # Exactly one executed action
    executed_actions = [r[0] for r in results if r[0] is not None and r[0].status == "EXECUTED"]
    assert len(executed_actions) == 1

    # Exactly one active blocked source in DB
    blocks = db.query(BlockedSource).filter(BlockedSource.ip == ip).all()
    assert len(blocks) == 1
    assert blocks[0].status == "ACTIVE"


