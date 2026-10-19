import json
from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_

from app.database.session import get_db
from app.models.entities import IntelligenceFeedItem, AuditEvent
from app.services.enrichment_service import EnrichmentService

router = APIRouter(prefix="/feed", tags=["Intelligence Feed"])

@router.get("")
def get_intelligence_feed(
    q: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """Retrieves searchable intelligence feed items with origin attribution."""
    query = db.query(IntelligenceFeedItem)

    if q and q.strip():
        term = f"%{q.strip()}%"
        query = query.filter(or_(
            IntelligenceFeedItem.title.ilike(term),
            IntelligenceFeedItem.summary.ilike(term)
        ))

    if category and category != "All":
        query = query.filter(IntelligenceFeedItem.threat_category == category)

    if severity and severity != "All":
        query = query.filter(IntelligenceFeedItem.severity == severity)

    if source and source != "All":
        query = query.filter(IntelligenceFeedItem.source == source)

    items = query.order_by(desc(IntelligenceFeedItem.publication_date)).offset(skip).limit(limit).all()

    results = []
    for it in items:
        indicators = json.loads(it.indicators_json) if it.indicators_json else []
        results.append({
            "id": it.id,
            "title": it.title,
            "source": it.source,
            "publication_date": it.publication_date.isoformat(),
            "threat_category": it.threat_category,
            "severity": it.severity,
            "indicators": indicators,
            "summary": it.summary,
            "url": it.url,
            "is_local": it.is_local
        })

    return results

@router.post("/sync-cisa")
async def sync_cisa_feed(db: Session = Depends(get_db)):
    """Syncs public Known Exploited Vulnerabilities (KEV) from CISA into the intelligence feed."""
    res = await EnrichmentService.fetch_cisa_advisories()
    if not res.get("success"):
        return res

    advisories = res.get("advisories", [])
    added_count = 0
    for adv in advisories:
        existing = db.query(IntelligenceFeedItem).filter(IntelligenceFeedItem.title == adv["title"]).first()
        if not existing:
            item = IntelligenceFeedItem(
                title=adv["title"],
                source=adv["source"],
                threat_category=adv["threat_category"],
                severity=adv["severity"],
                indicators_json=json.dumps(adv.get("indicators", [])),
                summary=adv["summary"],
                url=adv.get("url"),
                is_local=False
            )
            db.add(item)
            added_count += 1

    if added_count > 0:
        audit = AuditEvent(
            entity_type="FEED",
            entity_id="CISA_SYNC",
            action="SYNC",
            details=f"Synchronized {added_count} public security advisories from CISA."
        )
        db.add(audit)
        db.commit()

    return {
        "success": True,
        "added_count": added_count,
        "message": f"Successfully synchronized {added_count} CISA advisories into the threat intelligence feed."
    }
