from pathlib import Path
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc, text

from app.database.session import get_db
from app.models.entities import Analysis, Indicator, AuditEvent
from app.core.config import settings
from app.services.demo_data_service import DemoDataService
from app.services.threat_classifier import threat_classifier

router = APIRouter(tags=["System & Settings"])

@router.get("/health")
def health_check(db: Session = Depends(get_db)):
    """Health check endpoint verifying database connectivity, active model state, and dataset metadata."""
    db_status = "Connected"
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        db_status = "Error"

    meta_file = Path(settings.DATASET_DIR) / "metadata.json"
    meta_available = meta_file.exists()

    return {
        "status": "Healthy",
        "application_status": "Operational",
        "model_loading_status": "Loaded" if threat_classifier.model is not None else "Not Loaded",
        "dataset_metadata_availability": meta_available,
        "backend_version": "1.0.0",
        "project": settings.PROJECT_NAME,
        "tagline": settings.PROJECT_TAGLINE,
        "database": db_status,
        "ml_model_loaded": bool(threat_classifier.model is not None),
        "integrations": {
            "virustotal": bool(settings.VIRUSTOTAL_API_KEY),
            "alienvault_otx": bool(settings.ALIENVAULT_OTX_API_KEY)
        }
    }

@router.get("/settings")
def get_settings():
    """Returns current environment settings and integration statuses (without leaking secret values)."""
    return {
        "project_name": settings.PROJECT_NAME,
        "tagline": settings.PROJECT_TAGLINE,
        "database_type": "SQLite",
        "migration_target": "PostgreSQL Supported",
        "virustotal_configured": bool(settings.VIRUSTOTAL_API_KEY),
        "alienvault_configured": bool(settings.ALIENVAULT_OTX_API_KEY),
        "model_dir": settings.MODEL_DIR,
        "max_text_size_mb": settings.MAX_TEXT_SIZE_BYTES // (1024 * 1024),
        "max_file_size_mb": settings.MAX_FILE_SIZE_BYTES // (1024 * 1024)
    }

@router.get("/audit-logs")
def get_audit_logs(db: Session = Depends(get_db)):
    """Retrieves recent audit events for investigations and system changes."""
    logs = db.query(AuditEvent).order_by(desc(AuditEvent.created_at)).limit(50).all()
    return [
        {
            "id": l.id,
            "entity_type": l.entity_type,
            "entity_id": l.entity_id,
            "action": l.action,
            "details": l.details,
            "actor": l.actor,
            "created_at": l.created_at.isoformat()
        }
        for l in logs
    ]

@router.post("/demo/import")
def import_demo_dataset(db: Session = Depends(get_db)):
    """Imports synthetic, RFC-compliant demonstration scenarios into the database."""
    return DemoDataService.import_demo_data(db)

@router.post("/demo/clear")
def clear_demo_dataset(db: Session = Depends(get_db)):
    """Safely cleans demonstration scenarios without touching user-submitted investigations."""
    return DemoDataService.clear_demo_data(db)
