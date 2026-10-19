from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_

from app.database.session import get_db
from app.models.entities import Analysis, AuditEvent
from app.schemas.analysis import AnalysisResponse, AnalysisSummary
from app.api.analyze import _serialize_analysis_response

router = APIRouter(prefix="/analyses", tags=["Analysis History"])

@router.get("", response_model=List[AnalysisSummary])
def get_analyses(
    q: Optional[str] = Query(None, description="Search term in title or text"),
    category: Optional[str] = Query(None, description="Filter by threat category"),
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    status: Optional[str] = Query(None, description="Filter by status"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    """Retrieves paginated analysis records with multi-attribute filtering."""
    query = db.query(Analysis)

    if q and q.strip():
        term = f"%{q.strip()}%"
        query = query.filter(or_(Analysis.title.ilike(term), Analysis.original_text.ilike(term)))

    if category and category.strip() and category != "All":
        query = query.filter(Analysis.predicted_category == category.strip())

    if severity and severity.strip() and severity != "All":
        query = query.filter(Analysis.severity == severity.strip())

    if status and status.strip() and status != "All":
        query = query.filter(Analysis.status == status.strip())

    records = query.order_by(desc(Analysis.created_at)).offset(skip).limit(limit).all()

    summaries = []
    for a in records:
        summaries.append({
            "id": a.id,
            "title": a.title,
            "input_type": a.input_type,
            "predicted_category": a.predicted_category,
            "severity": a.severity,
            "confidence": a.confidence,
            "prediction_method": a.prediction_method,
            "indicators_count": len(a.indicators),
            "created_at": a.created_at.isoformat(),
            "status": a.status
        })
    return summaries


@router.get("/{analysis_id}", response_model=AnalysisResponse)
def get_analysis_detail(analysis_id: str, db: Session = Depends(get_db)):
    """Retrieves full analysis investigation findings and evidence."""
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis record not found.")
    return _serialize_analysis_response(analysis, db)


@router.delete("/{analysis_id}")
def delete_analysis(analysis_id: str, db: Session = Depends(get_db)):
    """Deletes an analysis record and cascades to associated link records."""
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis record not found.")

    # Audit event
    audit = AuditEvent(
        entity_type="ANALYSIS",
        entity_id=analysis_id,
        action="DELETE",
        details=f"Deleted analysis '{analysis.title}'"
    )
    db.add(audit)

    db.delete(analysis)
    db.commit()
    return {"success": True, "message": "Analysis record deleted successfully."}
