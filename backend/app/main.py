import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import settings
from app.database.session import SessionLocal
from app.database.init_db import init_db
from app.api.routes.auth import router as auth_router
from app.api.routes.events import router as events_router
from app.api.routes.incidents import router as incidents_router
from app.api.routes.threats import router as threats_router
from app.api.routes.blocked_sources import router as blocked_sources_router
from app.api.routes.prevention import router as prevention_router
from app.api.routes.health import router as health_router
from app.websocket.routes import ws_router

# Configure logging
logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("idps")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting AEGIS IDPS API server...")
    db = SessionLocal()
    try:
        init_db(db)
    except Exception as e:
        logger.error(f"Error during database startup initialization: {e}")
    finally:
        db.close()
    yield
    logger.info("Shutting down AEGIS IDPS API server...")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Intelligent Intrusion Detection & Prevention System (IDPS) Backend API",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_origin_regex=r"^https:\/\/.*\.vercel\.app$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Centralized exception handlers
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "status_code": exc.status_code},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = []
    for err in exc.errors():
        loc = " -> ".join(str(l) for l in err.get("loc", []))
        errors.append(f"{loc}: {err.get('msg')}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Validation error in request parameters",
            "errors": errors,
            "status_code": status.HTTP_422_UNPROCESSABLE_ENTITY,
        },
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.exception(f"Unhandled internal server error: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "An internal server error occurred. Please contact the SOC administrator.",
            "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
        },
    )


# Mount REST routers under /api
app.include_router(auth_router, prefix="/api")
app.include_router(events_router, prefix="/api")
app.include_router(incidents_router, prefix="/api")
app.include_router(threats_router, prefix="/api")
app.include_router(blocked_sources_router, prefix="/api")
app.include_router(prevention_router, prefix="/api")
app.include_router(health_router, prefix="/api")

# Also mount REST routers directly (e.g. /auth/login, /health)
app.include_router(auth_router)
app.include_router(events_router)
app.include_router(incidents_router)
app.include_router(threats_router)
app.include_router(blocked_sources_router)
app.include_router(prevention_router)
app.include_router(health_router)

# Mount WebSocket router
app.include_router(ws_router)


@app.get("/")
def root():
    return {
        "system": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs": "/api/docs",
        "health": "/api/health",
        "websocket": "/ws/events",
        "status": "online"
    }
