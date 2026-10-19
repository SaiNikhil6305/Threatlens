import json
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.entities import Analysis
from app.api.analyze import _serialize_analysis_response
from app.services.report_generator import ReportGenerator

router = APIRouter(prefix="/reports", tags=["Intelligence Reports"])

@router.get("/{analysis_id}")
def get_report(analysis_id: str, db: Session = Depends(get_db)):
    """Generates the full structured 10-section intelligence report."""
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis record not found.")

    analysis_data = _serialize_analysis_response(analysis, db)
    report = ReportGenerator.generate_full_report(analysis_data)
    return report

@router.get("/{analysis_id}/export")
def export_report(
    analysis_id: str,
    format: str = Query("json", description="Export format: json, markdown, or csv"),
    db: Session = Depends(get_db)
):
    """Exports the threat intelligence report in JSON, Markdown, or CSV format."""
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis record not found.")

    analysis_data = _serialize_analysis_response(analysis, db)
    report = ReportGenerator.generate_full_report(analysis_data)

    fmt = format.lower()
    if fmt == "markdown" or fmt == "md":
        md_text = ReportGenerator.export_markdown(report)
        return Response(
            content=md_text,
            media_type="text/markdown",
            headers={"Content-Disposition": f"attachment; filename=threatlens_report_{analysis_id[:8]}.md"}
        )
    elif fmt == "csv":
        csv_text = ReportGenerator.export_csv_indicators(report["indicators"])
        return Response(
            content=csv_text,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=threatlens_indicators_{analysis_id[:8]}.csv"}
        )
    else:  # default JSON
        return Response(
            content=json.dumps(report, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=threatlens_report_{analysis_id[:8]}.json"}
        )
