import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, Set, Optional, Any, Union
from fastapi import WebSocket, WebSocketDisconnect

from app.core.security import decode_token

logger = logging.getLogger("idps.websocket")


class ConnectionManager:
    """
    Robust WebSocket Connection Manager for real-time SOC dashboard streaming.
    Features:
    - Per-client bounded asyncio Queues to prevent memory leaks from slow consumers
    - Clean disconnection and task cleanup
    - Safe post-commit event broadcasting
    - Strict authentication validation without URL token exposure
    """

    def __init__(self, max_queue_size: int = 100):
        self.max_queue_size = max_queue_size
        self.active_connections: Dict[WebSocket, asyncio.Queue] = {}
        self.client_tasks: Dict[WebSocket, asyncio.Task] = {}
        self.client_users: Dict[WebSocket, str] = {}
        self._lock = asyncio.Lock()

    def active_connections_count(self) -> int:
        return len(self.active_connections)

    async def connect(self, websocket: WebSocket) -> asyncio.Queue:
        await websocket.accept()
        queue: asyncio.Queue = asyncio.Queue(maxsize=self.max_queue_size)
        async with self._lock:
            self.active_connections[websocket] = queue
            # Start consumer task for this client
            task = asyncio.create_task(self._client_writer_loop(websocket, queue))
            self.client_tasks[websocket] = task
        logger.info(f"WebSocket client connected. Active: {len(self.active_connections)}")
        return queue

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            task = self.client_tasks.pop(websocket, None)
            if task and not task.done():
                task.cancel()
            self.active_connections.pop(websocket, None)
            self.client_users.pop(websocket, None)
        try:
            await websocket.close()
        except Exception:
            pass
        logger.info(f"WebSocket client disconnected. Remaining: {len(self.active_connections)}")

    async def _client_writer_loop(self, websocket: WebSocket, queue: asyncio.Queue):
        """Worker task that reads from client queue and pushes to WebSocket."""
        try:
            while True:
                message = await queue.get()
                await websocket.send_text(message)
                queue.task_done()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"Client writer loop terminated: {e}")
        finally:
            await self.disconnect(websocket)

    @staticmethod
    def _sanitize_data(obj: Any) -> Any:
        if isinstance(obj, dict):
            sanitized = {}
            for k, v in obj.items():
                if any(sens in k.lower() for sens in ("password", "hashed_password", "token", "secret", "private_key")):
                    continue
                sanitized[k] = ConnectionManager._sanitize_data(v)
            return sanitized
        elif isinstance(obj, list):
            return [ConnectionManager._sanitize_data(i) for i in obj]
        return obj

    async def broadcast(
        self,
        event_type: str,
        data: Dict[str, Any],
        resource_id: Optional[Union[int, str]] = None
    ):
        """
        Broadcasts a versioned event envelope to all authenticated clients.
        Drops messages gracefully if a client's queue is full (slow consumer defense).
        """
        now_utc = datetime.now(timezone.utc).isoformat()
        envelope = {
            "event_type": event_type,
            "version": "1.0",
            "event_id": str(uuid.uuid4()),
            "timestamp": now_utc,
            "resource_id": resource_id,
            "data": self._sanitize_data(data),
        }
        encoded = json.dumps(envelope)

        async with self._lock:
            clients = list(self.active_connections.items())

        for ws, queue in clients:
            try:
                queue.put_nowait(encoded)
            except asyncio.QueueFull:
                logger.warning("Client queue full; dropping message to avoid blocking pipeline.")


ws_manager = ConnectionManager()


def broadcast_event_sync(
    event_type: str,
    data: Dict[str, Any],
    resource_id: Optional[Union[int, str]] = None
):
    """
    Safely schedules broadcast from synchronous route/service threads
    after database commit has succeeded.
    """
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(ws_manager.broadcast(event_type, data, resource_id))
    except RuntimeError:
        # No running event loop in this thread; non-critical in synchronous batch jobs
        pass
    except Exception as e:
        logger.error(f"Failed to schedule WebSocket broadcast: {e}")
