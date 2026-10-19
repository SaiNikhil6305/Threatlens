from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database.session import get_db
from app.models.entities import Analysis, Indicator
from app.schemas.dashboard import DashboardSummary
from app.services.ioc_extractor import IOCExtractor

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("/summary", response_model=DashboardSummary)
def get_dashboard_summary(
    category: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    days: Optional[int] = Query(30),
    db: Session = Depends(get_db)
):
    """Calculates all metrics and chart distributions strictly from the database."""
    query = db.query(Analysis)

    # Optional filters
    if category and category != "All":
        query = query.filter(Analysis.predicted_category == category)
    if severity and severity != "All":
        query = query.filter(Analysis.severity == severity)
    if status and status != "All":
        query = query.filter(Analysis.status == status)

    if days and days > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        query = query.filter(Analysis.created_at >= cutoff)

    analyses = query.order_by(desc(Analysis.created_at)).all()
    all_indicators = db.query(Indicator).all()

    total_reports = len(analyses)
    total_indicators = len(all_indicators)
    high_critical = sum(1 for a in analyses if a.severity in ("High", "Critical"))
    pending_review = sum(1 for ind in all_indicators if ind.verification_status == "Unverified")

    # Threat category distribution
    cat_counts = Counter(a.predicted_category for a in analyses)
    top_threat_category = cat_counts.most_common(1)[0][0] if cat_counts else "None"

    # Severity distribution
    sev_counts = Counter(a.severity for a in analyses)
    # Ensure all 5 standard levels appear in output
    severity_distribution = {
        "Critical": sev_counts.get("Critical", 0),
        "High": sev_counts.get("High", 0),
        "Medium": sev_counts.get("Medium", 0),
        "Low": sev_counts.get("Low", 0),
        "Informational": sev_counts.get("Informational", 0),
    }

    # Indicator distribution
    ind_counts = Counter(ind.indicator_type for ind in all_indicators)
    indicator_distribution = {
        "ipv4": ind_counts.get("ipv4", 0),
        "domain": ind_counts.get("domain", 0),
        "url": ind_counts.get("url", 0),
        "email": ind_counts.get("email", 0),
        "sha256": ind_counts.get("sha256", 0),
        "sha1": ind_counts.get("sha1", 0),
        "md5": ind_counts.get("md5", 0),
        "cve": ind_counts.get("cve", 0)
    }

    # Activity timeline (by date for the last 14 days)
    now = datetime.now(timezone.utc)
    date_buckets = {}
    for i in range(13, -1, -1):
        d_str = (now - timedelta(days=i)).strftime("%Y-%m-%d")
        date_buckets[d_str] = 0

    for a in analyses:
        d_str = a.created_at.strftime("%Y-%m-%d")
        if d_str in date_buckets:
            date_buckets[d_str] += 1

    activity_timeline = [{"date": k, "count": v} for k, v in date_buckets.items()]

    # Recent investigations (last 6)
    recent_investigations = []
    for a in analyses[:6]:
        recent_investigations.append({
            "id": a.id,
            "title": a.title,
            "predicted_category": a.predicted_category,
            "severity": a.severity,
            "confidence": a.confidence,
            "indicator_count": len(a.indicators),
            "status": a.status,
            "created_at": a.created_at.isoformat()
        })

    return {
        "total_reports": total_reports,
        "total_indicators": total_indicators,
        "high_critical_count": high_critical,
        "top_threat_category": top_threat_category,
        "pending_review_count": pending_review,
        "category_distribution": dict(cat_counts),
        "severity_distribution": severity_distribution,
        "indicator_distribution": indicator_distribution,
        "activity_timeline": activity_timeline,
        "recent_investigations": recent_investigations
    }
