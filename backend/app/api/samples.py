import os
import json
import time
from pathlib import Path
from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.entities import Scan, Finding
from app.services.document_parser import DocumentParser
from app.services.threat_engine import ThreatEngine
from app.services.report_pdf_generator import ReportPdfGenerator

router = APIRouter(prefix="/samples", tags=["Sample Documents"])

SAMPLE_DOCS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "sample_documents"
MANIFEST_PATH = SAMPLE_DOCS_DIR / "test_manifest.json"

@router.get("", response_model=List[Dict[str, Any]])
def list_sample_documents():
    """Returns available sample test documents from sample_documents/test_manifest.json."""
    if not MANIFEST_PATH.exists():
        return []

    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    docs = data.get("documents", [])
    result = []
    for d in docs:
        pdf_path = SAMPLE_DOCS_DIR / d["filename"]
        exists = pdf_path.exists()
        file_size = pdf_path.stat().st_size if exists else 0
        result.append({
            "filename": d["filename"],
            "category": d.get("category", "Safe Documents"),
            "intended_classification": d.get("intended_classification", "Safe"),
            "description": d.get("description", ""),
            "page_count": d.get("pages", 3),
            "expected_severity": d.get("expected_severity", "No significant indicators detected"),
            "file_size": file_size,
            "download_url": f"/api/samples/{d['filename']}/download",
            "scan_url": f"/api/samples/{d['filename']}/scan"
        })
    return result

@router.get("/{filename}/download")
def download_sample_document(filename: str):
    """Directly downloads a sample document."""
    file_path = SAMPLE_DOCS_DIR / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Sample document not found.")
    ext = file_path.suffix.lower()
    media_types = {
        ".pdf": "application/pdf",
        ".txt": "text/plain",
        ".json": "application/json",
        ".csv": "text/csv",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    }
    media_type = media_types.get(ext, "application/octet-stream")
    return FileResponse(
        str(file_path),
        media_type=media_type,
        filename=filename
    )

@router.post("/{filename}/scan")
def scan_sample_document(filename: str, db: Session = Depends(get_db)):
    """Performs instant analysis of a sample document from the sample library."""
    file_path = SAMPLE_DOCS_DIR / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Sample document not found.")

    start_time = time.time()
    with open(file_path, "rb") as f:
        content_bytes = f.read()

    success, extracted_text, meta = DocumentParser.parse_file(filename, content_bytes)
    if not success:
        raise HTTPException(status_code=400, detail=meta.get("error", "Failed to parse sample file."))

    analysis = ThreatEngine.analyze_document(
        filename=filename,
        full_text=extracted_text,
        pages=meta.get("pages", [])
    )
    duration = round(time.time() - start_time, 2)
    file_type = file_path.suffix.lower().replace(".", "").upper() or "PDF"

    # Create scan record
    scan_record = Scan(
        filename=filename,
        file_type=file_type,
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

    for f in analysis["findings"]:
        db.add(Finding(
            scan_id=scan_record.id,
            finding_type=f["finding_type"],
            severity=f["severity"],
            evidence=f["evidence"],
            page_number=f.get("page_number", 1),
            detection_method=f["detection_method"],
            explanation=f["explanation"],
            recommended_action=f.get("recommended_action")
        ))
    db.commit()

    # Generate ReportLab PDF
    report_dict = {
        "id": scan_record.id,
        "filename": filename,
        "file_type": "PDF",
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
        print(f"[!] Warning: PDF report generation issue: {e}")

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
