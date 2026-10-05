from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.api.deps import get_db
from app.core.config import settings
from app.websocket.manager import ws_manager
from app.prevention.engine import PreventionEngine

router = APIRouter(tags=["Health & System"])


@router.get("/health")
def health_check(db: Session = Depends(get_db)):
    db_status = "healthy"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    provider = PreventionEngine.get_provider(db)
    provider_health = provider.health_check()

    return {
        "status": "healthy" if db_status == "healthy" else "degraded",
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "components": {
            "database": db_status,
            "detection_parser": "ready",
            "prevention_provider": provider_health.get("provider", "mock"),
            "prevention_enabled": PreventionEngine.is_prevention_enabled(db),
            "prevention_mode": provider_health.get("description", "Safe Mock"),
            "real_firewall_enabled": False,
            "demo_mode": settings.DEMO_MODE,
            "websocket_service": "ready",
            "active_websocket_connections": ws_manager.active_connections_count(),
        }
    }
