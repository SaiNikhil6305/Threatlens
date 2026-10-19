import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.database.init_db import init_db
from app.services.threat_classifier import threat_classifier
from app.api.analyze import router as analyze_router
from app.api.analyses import router as analyses_router
from app.api.dashboard import router as dashboard_router
from app.api.indicators import router as indicators_router
from app.api.reports import router as reports_router
from app.api.techniques import router as techniques_router
from app.api.feed import router as feed_router
from app.api.model import router as model_router
from app.api.system import router as system_router
from app.api.samples import router as samples_router
from app.api.scan import router as scan_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("threatlens")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup actions
    logger.info("Initializing ThreatLens database and seeding reference data...")
    init_db()
    # Check if a trained ML model exists and load it
    threat_classifier.load_active_model()
    logger.info("ThreatLens backend initialized and ready.")
    yield
    # Shutdown actions
    logger.info("ThreatLens backend shutting down.")

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="ThreatLens: NLP-Powered Cyber Threat Intelligence Assistant. See Beyond the Threat.",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Exception Handler to avoid exposing stack traces
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled server error on {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred while processing the intelligence request."}
    )

# Register routers under /api
app.include_router(analyze_router, prefix=settings.API_V1_STR)
app.include_router(analyses_router, prefix=settings.API_V1_STR)
app.include_router(dashboard_router, prefix=settings.API_V1_STR)
app.include_router(indicators_router, prefix=settings.API_V1_STR)
app.include_router(reports_router, prefix=settings.API_V1_STR)
app.include_router(techniques_router, prefix=settings.API_V1_STR)
app.include_router(feed_router, prefix=settings.API_V1_STR)
app.include_router(model_router, prefix=settings.API_V1_STR)
app.include_router(system_router, prefix=settings.API_V1_STR)
app.include_router(samples_router, prefix=settings.API_V1_STR)
app.include_router(scan_router, prefix=settings.API_V1_STR)

@app.get("/")
def root():
    return {
        "project": settings.PROJECT_NAME,
        "tagline": settings.PROJECT_TAGLINE,
        "status": "Operational",
        "api_documentation": "/api/docs"
    }
