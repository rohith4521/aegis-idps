import json
import pytest
from app.core.security import create_access_token
from app.websocket.manager import ws_manager


def test_websocket_authenticated_connection(client):
    token = create_access_token(subject="analyst", role="analyst")
    with client.websocket_connect("/ws/events") as websocket:
        # Send authentication frame
        websocket.send_text(json.dumps({
            "type": "authenticate",
            "token": token
        }))
        response_text = websocket.receive_text()
        msg = json.loads(response_text)
        assert msg["type"] == "connection_established"
        assert msg["user"] == "analyst"

        # Ping-pong test
        websocket.send_text(json.dumps({"type": "ping"}))
        pong_text = websocket.receive_text()
        pong = json.loads(pong_text)
        assert pong["type"] == "pong"


def test_websocket_unauthenticated_rejection(client):
    with client.websocket_connect("/ws/events") as websocket:
        # Send bad token
        websocket.send_text(json.dumps({
            "type": "authenticate",
            "token": "invalid_bogus_token_xyz"
        }))
        response_text = websocket.receive_text()
        msg = json.loads(response_text)
        assert msg["type"] == "error"
        assert "Authentication failed" in msg["message"]


def test_websocket_event_envelope_broadcast(client):
    token = create_access_token(subject="admin", role="admin")
    with client.websocket_connect("/ws/events") as websocket:
        # Authenticate
        websocket.send_text(json.dumps({
            "type": "authenticate",
            "token": token
        }))
        auth_msg = websocket.receive_text()
        assert "connection_established" in auth_msg

        # Trigger broadcast via manager
        import asyncio
        loop = asyncio.get_event_loop()
        test_payload = {
            "id": 99,
            "title": "Simulated Exploit Incident",
            "threat_score": 95,
            "severity": "CRITICAL"
        }
        loop.run_until_complete(
            ws_manager.broadcast("incident.created", test_payload, resource_id=99)
        )

        event_text = websocket.receive_text()
        envelope = json.loads(event_text)

        # Validate standard envelope
        assert envelope["event_type"] == "incident.created"
        assert envelope["version"] == "1.0"
        assert "event_id" in envelope
        assert "timestamp" in envelope
        assert envelope["resource_id"] == 99
        assert envelope["data"]["title"] == "Simulated Exploit Incident"
        assert envelope["data"]["threat_score"] == 95
        # Ensure no secrets or credentials leaked
        assert "password" not in str(envelope)
        assert "token" not in str(envelope)


def test_websocket_multiple_clients(client):
    token = create_access_token(subject="analyst", role="analyst")
    with client.websocket_connect("/ws/events") as ws1:
        ws1.send_text(json.dumps({"type": "authenticate", "token": token}))
        assert "connection_established" in ws1.receive_text()

        with client.websocket_connect("/ws/events") as ws2:
            ws2.send_text(json.dumps({"type": "authenticate", "token": token}))
            assert "connection_established" in ws2.receive_text()

            # Broadcast to both
            import asyncio
            loop = asyncio.get_event_loop()
            loop.run_until_complete(
                ws_manager.broadcast("threat_score.created", {"score": 85}, resource_id=101)
            )

            msg1 = json.loads(ws1.receive_text())
            msg2 = json.loads(ws2.receive_text())

            assert msg1["event_type"] == "threat_score.created"
            assert msg2["event_type"] == "threat_score.created"
            assert msg1["data"]["score"] == 85
            assert msg2["data"]["score"] == 85


def test_websocket_slow_client_queue_full_safety():
    """Verify that slow clients with full queues do not block or crash the broadcast."""
    import asyncio
    from app.websocket.manager import ConnectionManager
    
    mgr = ConnectionManager(max_queue_size=2)
    fake_ws = object()  # dummy client
    q = asyncio.Queue(maxsize=2)
    q.put_nowait("msg1")
    q.put_nowait("msg2")
    assert q.full()

    mgr.active_connections[fake_ws] = q

    # Broadcast should catch QueueFull and not raise
    loop = asyncio.get_event_loop()
    loop.run_until_complete(
        mgr.broadcast("security_event.created", {"test": "data"}, resource_id=1)
    )
    # Queue remains full, no unhandled exception
    assert q.full()


def test_broadcast_failure_preserves_database(db):
    """Verify that if broadcast fails or raises, database transactions remain committed."""
    from app.models.incident import Incident
    from datetime import datetime
    from app.websocket.manager import broadcast_event_sync

    # Persist an incident
    inc = Incident(
        title="DB Preservation Check",
        category="Test",
        severity="MEDIUM",
        threat_score=50,
        confidence=80,
        source_ip="198.51.100.200",
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        is_simulation=False
    )
    db.add(inc)
    db.commit()
    db.refresh(inc)

    # Trigger broadcast sync (safe wrapper)
    broadcast_event_sync("incident.created", {"id": inc.id, "title": inc.title}, resource_id=inc.id)

    # Database state is fully preserved
    persisted = db.query(Incident).filter(Incident.id == inc.id).first()
    assert persisted is not None
    assert persisted.title == "DB Preservation Check"


def test_websocket_expired_token_rejection(client):
    from datetime import timedelta
    from app.core.security import create_access_token
    expired_token = create_access_token(
        subject="admin",
        role="admin",
        expires_delta=timedelta(seconds=-10)
    )
    with client.websocket_connect("/ws/events") as ws:
        ws.send_text(json.dumps({"type": "authenticate", "token": expired_token}))
        msg = json.loads(ws.receive_text())
        assert msg["type"] == "error"
        assert "Authentication failed" in msg["message"]


def test_websocket_inactive_user_rejection(client, db):
    from app.models.user import User
    from app.core.security import create_access_token, get_password_hash
    inactive_user = User(
        username="ws_inactive_user",
        email="inactive_ws@aegis-idps.net",
        full_name="Inactive WS Operator",
        hashed_password=get_password_hash("Pass12345!"),
        role="analyst",
        is_active=False
    )
    db.add(inactive_user)
    db.commit()

    token = create_access_token(subject="ws_inactive_user", role="analyst")
    with client.websocket_connect("/ws/events") as ws:
        ws.send_text(json.dumps({"type": "authenticate", "token": token}))
        msg = json.loads(ws.receive_text())
        assert msg["type"] == "error"
        assert "Authentication failed" in msg["message"]


def test_websocket_sensitive_data_sanitization(client):
    token = create_access_token(subject="admin", role="admin")
    with client.websocket_connect("/ws/events") as ws:
        ws.send_text(json.dumps({"type": "authenticate", "token": token}))
        assert "connection_established" in ws.receive_text()

        import asyncio
        loop = asyncio.get_event_loop()
        test_payload = {
            "incident_id": 123,
            "target": "198.51.100.5",
            "password": "SuperSecretPassword123!",
            "hashed_password": "$2b$12$e...",
            "token": "secret_session_token",
            "safe_metric": 42
        }
        loop.run_until_complete(
            ws_manager.broadcast("security_event.created", test_payload, resource_id=123)
        )

        msg = json.loads(ws.receive_text())
        data = msg["data"]
        assert data["incident_id"] == 123
        assert data["safe_metric"] == 42
        assert "password" not in data
        assert "hashed_password" not in data
        assert "token" not in data


def test_websocket_disconnect_and_cleanup(client):
    initial_count = ws_manager.active_connections_count()
    token = create_access_token(subject="analyst", role="analyst")
    with client.websocket_connect("/ws/events") as ws:
        ws.send_text(json.dumps({"type": "authenticate", "token": token}))
        assert "connection_established" in ws.receive_text()
        assert ws_manager.active_connections_count() == initial_count + 1

    # After context exit, client is disconnected and cleaned up
    assert ws_manager.active_connections_count() == initial_count


