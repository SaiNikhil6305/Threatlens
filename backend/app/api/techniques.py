from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.database.session import get_db
from app.models.entities import AttackTechnique, AnalysisTechnique

router = APIRouter(prefix="/attack", tags=["MITRE ATT&CK"])

@router.get("/techniques")
def get_attack_techniques(
    q: Optional[str] = Query(None),
    tactic: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """Retrieves MITRE ATT&CK reference techniques with usage counts in ThreatLens analyses."""
    query = db.query(AttackTechnique)

    if q and q.strip():
        term = f"%{q.strip()}%"
        query = query.filter(or_(
            AttackTechnique.technique_id.ilike(term),
            AttackTechnique.technique_name.ilike(term),
            AttackTechnique.description.ilike(term)
        ))

    if tactic and tactic != "All":
        query = query.filter(AttackTechnique.tactic == tactic)

    techniques = query.order_by(AttackTechnique.tactic, AttackTechnique.technique_id).all()

    results = []
    for t in techniques:
        occurrences = db.query(AnalysisTechnique).filter(AnalysisTechnique.technique_id == t.id).count()
        results.append({
            "id": t.id,
            "technique_id": t.technique_id,
            "technique_name": t.technique_name,
            "tactic": t.tactic,
            "description": t.description,
            "mapping_source": t.mapping_source,
            "url": t.url,
            "investigation_count": occurrences
        })

    return results
