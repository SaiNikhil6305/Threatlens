from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_

from app.database.session import get_db
from app.models.entities import Indicator, AnalysisIndicator, AnalystNote, AuditEvent
from app.schemas.indicator import IndicatorResponse, IndicatorUpdateRequest
from app.services.ioc_extractor import IOCExtractor
from app.services.enrichment_service import EnrichmentService
from app.services.report_generator import ReportGenerator

router = APIRouter(prefix="/indicators", tags=["Indicator Investigation"])

def _serialize_indicator(ind: Indicator, db: Session) -> dict:
    links = db.query(AnalysisIndicator).filter(AnalysisIndicator.indicator_id == ind.id).all()
    associated_reports = [
        {
            "analysis_id": l.analysis.id,
            "title": l.analysis.title,
            "category": l.analysis.predicted_category,
            "severity": l.analysis.severity,
            "created_at": l.analysis.created_at.isoformat(),
            "evidence_snippet": l.evidence_snippet
        }
        for l in links if l.analysis
    ]

    notes = db.query(AnalystNote).filter(AnalystNote.indicator_id == ind.id).order_by(desc(AnalystNote.created_at)).all()
    notes_list = [
        {
            "id": n.id,
            "author": n.author,
            "note": n.note,
            "created_at": n.created_at.isoformat()
        }
        for n in notes
    ]

    return {
        "id": ind.id,
        "normalized_value": ind.normalized_value,
        "original_value": ind.original_value,
        "defanged_value": IOCExtractor.defang(ind.normalized_value, ind.indicator_type),
        "indicator_type": ind.indicator_type,
        "reputation_status": ind.reputation_status,
        "reputation_source": ind.reputation_source,
        "verification_status": ind.verification_status,
        "associated_reports_count": len(associated_reports),
        "associated_reports": associated_reports,
        "analyst_notes": notes_list,
        "first_observed": ind.first_observed.isoformat(),
        "last_observed": ind.last_observed.isoformat(),
        "last_enriched_at": ind.last_enriched_at.isoformat() if ind.last_enriched_at else None
    }


@router.get("", response_model=List[IndicatorResponse])
def get_indicators(
    q: Optional[str] = Query(None, description="Search indicator value"),
    type: Optional[str] = Query(None, description="Filter by indicator type"),
    status: Optional[str] = Query(None, description="Filter by verification status"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db)
):
    """Retrieves paginated indicators of compromise with filters."""
    query = db.query(Indicator)

    if q and q.strip():
        term = f"%{q.strip().lower()}%"
        query = query.filter(Indicator.normalized_value.ilike(term))

    if type and type != "All":
        query = query.filter(Indicator.indicator_type == type)

    if status and status != "All":
        query = query.filter(Indicator.verification_status == status)

    indicators = query.order_by(desc(Indicator.last_observed)).offset(skip).limit(limit).all()
    return [_serialize_indicator(ind, db) for ind in indicators]


@router.get("/export/csv")
def export_indicators_csv(
    type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """Exports filtered indicators as a CSV file."""
    query = db.query(Indicator)
    if type and type != "All":
        query = query.filter(Indicator.indicator_type == type)
    if status and status != "All":
        query = query.filter(Indicator.verification_status == status)

    indicators = query.all()
    serialized = [_serialize_indicator(ind, db) for ind in indicators]
    csv_text = ReportGenerator.export_csv_indicators(serialized)

    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=threatlens_indicators.csv"}
    )


@router.get("/{indicator_id}", response_model=IndicatorResponse)
def get_indicator_detail(indicator_id: str, db: Session = Depends(get_db)):
    """Retrieves detailed indicator evidence and associated investigations."""
    ind = db.query(Indicator).filter(Indicator.id == indicator_id).first()
    if not ind:
        raise HTTPException(status_code=404, detail="Indicator not found.")
    return _serialize_indicator(ind, db)


@router.patch("/{indicator_id}", response_model=IndicatorResponse)
def update_indicator(
    indicator_id: str,
    payload: IndicatorUpdateRequest,
    db: Session = Depends(get_db)
):
    """Updates verification status and adds analyst investigation notes."""
    ind = db.query(Indicator).filter(Indicator.id == indicator_id).first()
    if not ind:
        raise HTTPException(status_code=404, detail="Indicator not found.")

    if payload.verification_status:
        ind.verification_status = payload.verification_status

    if payload.analyst_note and payload.analyst_note.strip():
        note = AnalystNote(
            indicator_id=ind.id,
            author="Analyst",
            note=payload.analyst_note.strip()
        )
        db.add(note)

    # Audit event
    audit = AuditEvent(
        entity_type="INDICATOR",
        entity_id=ind.id,
        action="UPDATE",
        details=f"Updated indicator {ind.normalized_value}: Status={ind.verification_status}"
    )
    db.add(audit)

    db.commit()
    db.refresh(ind)
    return _serialize_indicator(ind, db)


@router.post("/{indicator_id}/enrich")
async def enrich_indicator(indicator_id: str, db: Session = Depends(get_db)):
    """Triggers external threat intelligence enrichment via VirusTotal or AlienVault."""
    ind = db.query(Indicator).filter(Indicator.id == indicator_id).first()
    if not ind:
        raise HTTPException(status_code=404, detail="Indicator not found.")

    res = await EnrichmentService.enrich_indicator(ind.normalized_value, ind.indicator_type)
    if res.get("success"):
        ind.reputation_status = res["reputation_status"]
        ind.reputation_source = res["reputation_source"]
        if res.get("last_enriched_at"):
            from datetime import datetime
            ind.last_enriched_at = datetime.fromisoformat(res["last_enriched_at"])

        audit = AuditEvent(
            entity_type="INDICATOR",
            entity_id=ind.id,
            action="ENRICH",
            details=f"Enriched {ind.normalized_value} via {res['reputation_source']}: {res['reputation_status']}"
        )
        db.add(audit)
        db.commit()

    return res
