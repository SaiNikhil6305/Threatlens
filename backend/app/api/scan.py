import os
import time
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, UploadFile, File, Form, Depends, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database.session import get_db
from app.models.entities import Scan, Finding
from app.services.document_parser import DocumentParser
from app.services.threat_engine import ThreatEngine
from app.services.report_pdf_generator import ReportPdfGenerator

router = APIRouter(tags=["Document Scanning & Threat Analysis"])

UPLOAD_DIR = Path(__file__).resolve().parent.parent.parent.parent / "reports" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
MODEL_METRICS_PATH = Path(__file__).resolve().parent.parent.parent.parent / "models" / "evaluation_results.json"

@router.post("/scan")
async def scan_document(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """
    Accepts a document upload (PDF, DOCX, TXT), validates signatures,
    extracts multi-page text, performs hybrid ML & rule threat analysis,
    generates a ReportLab PDF intelligence report, and stores scan history.
    """
    start_time = time.time()
    filename = file.filename or "unknown_document"
    content_bytes = await file.read()

    if not content_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # 1. Parse and extract text
    success, extracted_text, meta = DocumentParser.parse_file(filename, content_bytes)
    if not success:
        raise HTTPException(status_code=400, detail=meta.get("error", "Failed to parse document."))

    # Check for image-only / OCR required
    if meta.get("ocr_required"):
        # Save placeholder record
        scan_record = Scan(
            filename=filename,
            file_type=meta.get("file_type", "PDF"),
            severity="No significant indicators detected",
            severity_score=0.0,
            finding_count=0,
            processing_duration=round(time.time() - start_time, 2),
            extracted_text="",
            page_count=meta.get("page_count", 1),
            word_count=0,
            detection_method="OCR Check",
            predicted_category="Image/Scanned Document",
            confidence=0.0,
            status="OCR Required",
            ocr_required=True,
            recommended_actions_json=json.dumps(["Document is image-based. Run Optical Character Recognition (OCR) to inspect embedded text."])
        )
        db.add(scan_record)
        db.commit()
        db.refresh(scan_record)
        return {
            "scan_id": scan_record.id,
            "filename": filename,
            "file_type": scan_record.file_type,
            "overall_severity": scan_record.severity,
            "number_of_pages": scan_record.page_count,
            "extracted_text_statistics": {"word_count": 0, "character_count": 0},
            "findings": [],
            "suspicious_passages": [],
            "detection_method": "OCR Check",
            "processing_duration": scan_record.processing_duration,
            "ocr_required": True,
            "warning": meta.get("warning"),
            "recommended_actions": ["Optical Character Recognition (OCR) required for scanned/image-based documents."]
        }

    # 2. Analyze document using ThreatEngine
    analysis = ThreatEngine.analyze_document(
        filename=filename,
        full_text=extracted_text,
        pages=meta.get("pages", [])
    )
    duration = round(time.time() - start_time, 2)

    # 3. Save raw file for potential rescan
    stored_file_path = UPLOAD_DIR / f"{int(time.time())}_{filename}"
    with open(stored_file_path, "wb") as f:
        f.write(content_bytes)

    # 4. Create Scan DB Record
    scan_record = Scan(
        filename=filename,
        file_type=meta.get("file_type", "TXT"),
        severity=analysis["overall_severity"],
        severity_score=analysis["severity_score"],
        finding_count=analysis["finding_count"],
        processing_duration=duration,
        extracted_text=extracted_text,
        page_count=meta.get("page_count", 1),
        word_count=meta.get("word_count", len(extracted_text.split())),
        detection_method=analysis["detection_method"],
        predicted_category=analysis["predicted_category"],
        confidence=analysis["confidence"],
        status="Completed",
        ocr_required=False,
        recommended_actions_json=json.dumps(analysis["recommended_actions"])
    )
    db.add(scan_record)
    db.commit()
    db.refresh(scan_record)

    # 5. Persist discrete findings
    db_findings = []
    for f in analysis["findings"]:
        finding_obj = Finding(
            scan_id=scan_record.id,
            finding_type=f["finding_type"],
            severity=f["severity"],
            evidence=f["evidence"],
            page_number=f.get("page_number", 1),
            detection_method=f["detection_method"],
            explanation=f["explanation"],
            recommended_action=f.get("recommended_action")
        )
        db.add(finding_obj)
        db_findings.append(finding_obj)
    db.commit()

    # 6. Generate downloadable ReportLab PDF Report
    report_dict = {
        "id": scan_record.id,
        "filename": filename,
        "file_type": scan_record.file_type,
        "severity": scan_record.severity,
        "predicted_category": scan_record.predicted_category,
        "confidence": scan_record.confidence,
        "page_count": scan_record.page_count,
        "word_count": scan_record.word_count,
        "processing_duration": duration,
        "detection_method": scan_record.detection_method,
        "finding_count": scan_record.finding_count,
        "findings": analysis["findings"],
        "recommended_actions": analysis["recommended_actions"],
        "scan_timestamp": scan_record.scan_timestamp.isoformat()
    }
    try:
        report_pdf_path = ReportPdfGenerator.generate_scan_report(report_dict)
        scan_record.report_path = report_pdf_path
        db.commit()
    except Exception as e:
        print(f"[!] Warning: PDF report generation encountered issue: {e}")

    # Build suspicious passages snippet list
    suspicious_passages = [
        {
            "passage": f["evidence"],
            "page_number": f.get("page_number", 1),
            "finding_type": f["finding_type"],
            "severity": f["severity"]
        }
        for f in analysis["findings"]
    ]

    return {
        "scan_id": scan_record.id,
        "filename": filename,
        "file_type": scan_record.file_type,
        "overall_severity": scan_record.severity,
        "severity_score": scan_record.severity_score,
        "predicted_category": scan_record.predicted_category,
        "confidence": scan_record.confidence,
        "number_of_pages": scan_record.page_count,
        "extracted_text_statistics": {
            "word_count": scan_record.word_count,
            "character_count": len(extracted_text)
        },
        "finding_count": scan_record.finding_count,
        "findings": analysis["findings"],
        "suspicious_passages": suspicious_passages,
        "detection_method": scan_record.detection_method,
        "processing_duration": duration,
        "recommended_actions": analysis["recommended_actions"],
        "report_url": f"/api/scans/{scan_record.id}/report"
    }

@router.get("/scans")
def list_scans(db: Session = Depends(get_db)):
    """Returns recent scan history."""
    scans = db.query(Scan).order_by(desc(Scan.scan_timestamp)).limit(100).all()
    return [
        {
            "id": s.id,
            "filename": s.filename,
            "file_type": s.file_type,
            "scan_timestamp": s.scan_timestamp.isoformat(),
            "severity": s.severity,
            "severity_score": s.severity_score,
            "finding_count": s.finding_count,
            "processing_duration": s.processing_duration,
            "page_count": s.page_count,
            "predicted_category": s.predicted_category,
            "confidence": s.confidence,
            "status": s.status,
            "report_url": f"/api/scans/{s.id}/report"
        }
        for s in scans
    ]

@router.get("/scans/{scan_id}")
def get_scan_details(scan_id: str, db: Session = Depends(get_db)):
    """Returns details and discrete findings for a particular scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    recs = json.loads(scan.recommended_actions_json) if scan.recommended_actions_json else []

    return {
        "id": scan.id,
        "filename": scan.filename,
        "file_type": scan.file_type,
        "scan_timestamp": scan.scan_timestamp.isoformat(),
        "severity": scan.severity,
        "severity_score": scan.severity_score,
        "finding_count": scan.finding_count,
        "processing_duration": scan.processing_duration,
        "page_count": scan.page_count,
        "word_count": scan.word_count,
        "predicted_category": scan.predicted_category,
        "confidence": scan.confidence,
        "detection_method": scan.detection_method,
        "status": scan.status,
        "ocr_required": scan.ocr_required,
        "recommended_actions": recs,
        "report_url": f"/api/scans/{scan.id}/report",
        "findings": [
            {
                "id": f.id,
                "finding_type": f.finding_type,
                "severity": f.severity,
                "evidence": f.evidence,
                "page_number": f.page_number,
                "detection_method": f.detection_method,
                "explanation": f.explanation,
                "recommended_action": f.recommended_action
            }
            for f in findings
        ]
    }

@router.get("/scans/{scan_id}/report")
def download_scan_report(scan_id: str, db: Session = Depends(get_db)):
    """Downloads the generated PDF analysis report."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    reports_dir = Path(__file__).resolve().parent.parent.parent.parent / "reports"
    expected_filename = f"ThreatLens_Report_{scan_id[:8].upper()}.pdf"
    report_file = reports_dir / expected_filename

    # If report file does not exist, generate it on the fly
    if not report_file.exists():
        findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
        recs = json.loads(scan.recommended_actions_json) if scan.recommended_actions_json else []
        report_dict = {
            "id": scan.id,
            "filename": scan.filename,
            "file_type": scan.file_type,
            "severity": scan.severity,
            "predicted_category": scan.predicted_category,
            "confidence": scan.confidence,
            "page_count": scan.page_count,
            "word_count": scan.word_count,
            "processing_duration": scan.processing_duration,
            "detection_method": scan.detection_method,
            "finding_count": scan.finding_count,
            "findings": [
                {
                    "finding_type": f.finding_type,
                    "severity": f.severity,
                    "evidence": f.evidence,
                    "page_number": f.page_number,
                    "explanation": f.explanation,
                    "recommended_action": f.recommended_action
                }
                for f in findings
            ],
            "recommended_actions": recs,
            "scan_timestamp": scan.scan_timestamp.isoformat()
        }
        ReportPdfGenerator.generate_scan_report(report_dict)

    if not report_file.exists():
        raise HTTPException(status_code=404, detail="Analysis report file could not be located.")

    return FileResponse(
        str(report_file),
        media_type="application/pdf",
        filename=expected_filename
    )

@router.post("/rescan/{scan_id}")
def rescan_document(scan_id: str, db: Session = Depends(get_db)):
    """Rescans an existing document record if extracted text is available."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    if not scan.extracted_text:
        raise HTTPException(status_code=400, detail="Original text not available for rescan.")

    start_time = time.time()
    pages = [{"page_number": p, "text": scan.extracted_text} for p in range(1, scan.page_count + 1)]
    analysis = ThreatEngine.analyze_document(
        filename=scan.filename,
        full_text=scan.extracted_text,
        pages=pages
    )
    duration = round(time.time() - start_time, 2)

    # Update scan record
    scan.severity = analysis["overall_severity"]
    scan.severity_score = analysis["severity_score"]
    scan.finding_count = analysis["finding_count"]
    scan.predicted_category = analysis["predicted_category"]
    scan.confidence = analysis["confidence"]
    scan.processing_duration = duration
    scan.recommended_actions_json = json.dumps(analysis["recommended_actions"])
    scan.scan_timestamp = datetime.now(timezone.utc)

    # Replace findings
    db.query(Finding).filter(Finding.scan_id == scan_id).delete()
    for f in analysis["findings"]:
        db.add(Finding(
            scan_id=scan.id,
            finding_type=f["finding_type"],
            severity=f["severity"],
            evidence=f["evidence"],
            page_number=f.get("page_number", 1),
            detection_method=f["detection_method"],
            explanation=f["explanation"],
            recommended_action=f.get("recommended_action")
        ))
    db.commit()

    return {
        "message": "Rescan completed successfully.",
        "scan_id": scan.id,
        "severity": scan.severity,
        "finding_count": scan.finding_count,
        "predicted_category": scan.predicted_category
    }

@router.get("/analytics")
def get_analytics(db: Session = Depends(get_db)):
    """
    Returns high-level scanning metrics, severity distributions,
    threat category counts, and activity timeline.
    """
    scans = db.query(Scan).all()
    total_scanned = len(scans)

    safe_count = sum(1 for s in scans if s.severity in ["No significant indicators detected", "Informational", "Low"])
    suspicious_count = sum(1 for s in scans if s.severity in ["Medium", "High", "Critical"])
    high_critical_count = sum(1 for s in scans if s.severity in ["High", "Critical"])

    # Severity distribution
    sev_dist = {
        "Critical": sum(1 for s in scans if s.severity == "Critical"),
        "High": sum(1 for s in scans if s.severity == "High"),
        "Medium": sum(1 for s in scans if s.severity == "Medium"),
        "Low": sum(1 for s in scans if s.severity == "Low"),
        "No significant indicators detected": sum(1 for s in scans if s.severity in ["No significant indicators detected", "Informational"])
    }

    # Category distribution
    cat_dist = {}
    for s in scans:
        cat = s.predicted_category or "Other"
        cat_dist[cat] = cat_dist.get(cat, 0) + 1

    # Timeline (last 14 days)
    timeline = []
    now = datetime.now(timezone.utc)
    for i in range(13, -1, -1):
        d_str = (now - timedelta(days=i)).strftime("%Y-%m-%d")
        count = sum(1 for s in scans if s.scan_timestamp and s.scan_timestamp.strftime("%Y-%m-%d") == d_str)
        timeline.append({"date": d_str, "scans": count})

    return {
        "total_documents_scanned": total_scanned,
        "safe_document_count": safe_count,
        "suspicious_document_count": suspicious_count,
        "high_severity_count": high_critical_count,
        "severity_distribution": sev_dist,
        "category_distribution": cat_dist,
        "recent_scanning_activity": timeline
    }

@router.get("/model-metrics")
def get_model_metrics():
    """Returns actual ML evaluation metrics from models/evaluation_results.json."""
    if not MODEL_METRICS_PATH.exists():
        return {
            "status": "No evaluation artifacts found",
            "message": "Run python -m ml.train to train and evaluate candidate models."
        }
    with open(MODEL_METRICS_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data
