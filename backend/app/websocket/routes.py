import asyncio
import json
import logging
from typing import Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from app.websocket.manager import ws_manager
from app.core.security import decode_token

from app.database.session import SessionLocal
from app.models.user import User

logger = logging.getLogger("idps.websocket")

ws_router = APIRouter(tags=["Real-time WebSockets"])


@ws_router.websocket("/ws/events")
async def websocket_events_endpoint(websocket: WebSocket):
    """
    Real-time SOC security event and incident stream.
    Enforces authentication via an initial auth frame or Sec-WebSocket-Protocol
    without exposing bearer tokens in URL query parameters.
    """
    queue = await ws_manager.connect(websocket)
    authenticated_user = None

    def verify_token_user(token_str: str) -> Optional[str]:
        payload = decode_token(token_str)
        if not payload or not payload.get("sub"):
            return None
        sub = payload.get("sub")
        db = SessionLocal()
        try:
            db_user = db.query(User).filter(User.username == sub).first()
            if db_user and db_user.is_active:
                return db_user.username
            return None
        finally:
            db.close()

    # Check subprotocol first if provided
    subprotocols = websocket.scope.get("subprotocols", [])
    for subp in subprotocols:
        user = verify_token_user(subp)
        if user:
            authenticated_user = user
            break

    # If not authenticated via subprotocol, expect first message auth within 5 seconds
    if not authenticated_user:
        try:
            auth_msg_raw = await asyncio.wait_for(websocket.receive_text(), timeout=5.0)
            auth_data = json.loads(auth_msg_raw)
            if auth_data.get("type") == "authenticate" and auth_data.get("token"):
                authenticated_user = verify_token_user(auth_data["token"])
        except asyncio.TimeoutError:
            logger.warning("WebSocket client authentication timed out (5s). Closing connection.")
        except Exception as e:
            logger.warning(f"WebSocket auth payload invalid: {e}")

    if not authenticated_user:
        try:
            await websocket.send_text(json.dumps({
                "type": "error",
                "message": "Authentication failed. Provide valid bearer token."
            }))
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        except Exception:
            pass
        await ws_manager.disconnect(websocket)
        return

    # Connection authenticated
    ws_manager.client_users[websocket] = authenticated_user
    await websocket.send_text(json.dumps({
        "type": "connection_established",
        "user": authenticated_user,
        "message": "Connected to AEGIS SOC real-time event pipeline"
    }))

    # Keep connection alive and listen for client pings or queries
    try:
        while True:
            text = await websocket.receive_text()
            try:
                msg = json.loads(text)
                if msg.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except Exception:
                pass
    except WebSocketDisconnect:
        logger.info(f"WebSocket client disconnected cleanly: {authenticated_user}")
    except Exception as e:
        logger.debug(f"WebSocket error: {e}")
    finally:
        await ws_manager.disconnect(websocket)
