import json
import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database.session import get_db
from app.models.entities import (
    Analysis, Indicator, AnalysisIndicator, ExtractedEntity,
    AttackTechnique, AnalysisTechnique, AnalystNote, AuditEvent, IntelligenceFeedItem
)
from app.schemas.analysis import (
    TextAnalysisRequest, IndicatorAnalysisRequest, AnalysisResponse, AnalysisSummary
)
from app.services.text_preprocessor import TextPreprocessor
from app.services.ioc_extractor import IOCExtractor
from app.services.entity_extractor import entity_extractor
from app.services.threat_classifier import threat_classifier
from app.services.severity_engine import SeverityEngine
from app.services.attack_mapper import AttackMapper
from app.services.recommendation_engine import RecommendationEngine
from app.services.document_parser import DocumentParser

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/analyze", tags=["Threat Analysis"])

def _process_and_save_analysis(
    text: str,
    title: Optional[str],
    input_type: str,
    source: Optional[str],
    file_name: Optional[str],
    notes: Optional[str],
    db: Session
) -> Analysis:
    # 1. Preprocess
    pre = TextPreprocessor.preprocess(text)
    if pre["is_empty"]:
        raise HTTPException(status_code=400, detail="Provided text contains no readable or printable content.")

    clean_text = pre["cleaned_text"]
    auto_title = title.strip() if title and title.strip() else f"Investigation - {clean_text[:50].strip()}..."

    # 2. Extract IOCs & Entities
    iocs = IOCExtractor.extract_all(clean_text)
    entities = entity_extractor.extract_entities(clean_text)

    # 3. Classify Threat
    clf = threat_classifier.predict(clean_text)

    # 4. Assess Severity
    severity_data = SeverityEngine.assess_severity(
        text=clean_text,
        category=clf["predicted_category"],
        indicators=iocs,
        entities=entities,
        source=source
    )

    # 5. MITRE ATT&CK Mapping
    techniques = AttackMapper.map_techniques(clean_text, db)

    # 6. Defensive Recommendations
    recommendations = RecommendationEngine.generate_recommendations(clf["predicted_category"], iocs)

    # 7. Persist Analysis record
    analysis = Analysis(
        title=auto_title,
        original_text=clean_text,
        input_type=input_type,
        file_name=file_name,
        source=source or "Manual Submission",
        predicted_category=clf["predicted_category"],
        confidence=clf["confidence"],
        prediction_method=clf["prediction_method"],
        model_version=clf.get("model_version"),
        is_uncertain=clf["is_uncertain"],
        severity=severity_data["severity"],
        severity_score=severity_data["severity_score"],
        severity_rationale=json.dumps(severity_data),
        defensive_recommendations=json.dumps(recommendations),
        status="Completed"
    )
    db.add(analysis)
    db.flush()

    # 8. Persist and Link Indicators
    for ioc in iocs:
        ind = db.query(Indicator).filter(Indicator.normalized_value == ioc["normalized_value"]).first()
        if not ind:
            ind = Indicator(
                normalized_value=ioc["normalized_value"],
                original_value=ioc["original_value"],
                indicator_type=ioc["indicator_type"],
                reputation_status="Not checked",
                verification_status="Unverified",
                first_observed=analysis.created_at,
                last_observed=analysis.created_at
            )
            db.add(ind)
            db.flush()
        else:
            ind.last_observed = analysis.created_at

        link = AnalysisIndicator(
            analysis_id=analysis.id,
            indicator_id=ind.id,
            evidence_snippet=ioc["evidence_snippet"],
            extraction_method="Regex Engine",
            extraction_confidence=ioc["confidence"],
            source_start=ioc["start"],
            source_end=ioc["end"]
        )
        db.add(link)

    # 9. Persist Entities
    for ent in entities:
        db_ent = ExtractedEntity(
            analysis_id=analysis.id,
            entity_type=ent["entity_type"],
            entity_value=ent["entity_value"],
            evidence_snippet=ent["evidence_snippet"],
            confidence=ent["confidence"],
            verification_status=ent.get("verification_status", "Unverified")
        )
        db.add(db_ent)

    # 10. Persist Techniques
    for tech in techniques:
        db_tech = AnalysisTechnique(
            analysis_id=analysis.id,
            technique_id=tech["database_id"],
            evidence=tech["evidence"],
            mapping_confidence=tech["mapping_confidence"],
            verification_status="Potential Mapping"
        )
        db.add(db_tech)

    # 11. Initial Analyst Note if provided
    if notes and notes.strip():
        db_note = AnalystNote(
            analysis_id=analysis.id,
            author="Analyst",
            note=notes.strip()
        )
        db.add(db_note)

    # 12. Also create an Intelligence Feed Item so it surfaces immediately in Intelligence Feed
    feed_item = IntelligenceFeedItem(
        title=analysis.title,
        source=analysis.source,
        publication_date=analysis.created_at,
        threat_category=analysis.predicted_category,
        severity=analysis.severity,
        indicators_json=json.dumps([ioc["normalized_value"] for ioc in iocs]),
        summary=clean_text[:160] + "...",
        is_local=True
    )
    db.add(feed_item)

    # Audit event
    audit = AuditEvent(
        entity_type="ANALYSIS",
        entity_id=analysis.id,
        action="CREATE",
        details=f"Analyzed {input_type} report: '{analysis.title}', Category: {analysis.predicted_category}, Severity: {analysis.severity}"
    )
    db.add(audit)

    db.commit()
    db.refresh(analysis)
    return analysis

def _serialize_analysis_response(analysis: Analysis, db: Session) -> dict:
    rationale = json.loads(analysis.severity_rationale) if analysis.severity_rationale else {}
    recs = json.loads(analysis.defensive_recommendations) if analysis.defensive_recommendations else []

    indicators_list = []
    for link in analysis.indicators:
        ind = link.indicator
        indicators_list.append({
            "id": ind.id,
            "original_value": ind.original_value,
            "normalized_value": ind.normalized_value,
            "defanged_value": IOCExtractor.defang(ind.normalized_value, ind.indicator_type),
            "indicator_type": ind.indicator_type,
            "reputation_status": ind.reputation_status,
            "verification_status": ind.verification_status,
            "evidence_snippet": link.evidence_snippet,
            "confidence": link.extraction_confidence
        })

    entities_list = [
        {
            "id": e.id,
            "entity_type": e.entity_type,
            "entity_value": e.entity_value,
            "evidence_snippet": e.evidence_snippet,
            "confidence": e.confidence,
            "verification_status": e.verification_status
        }
        for e in analysis.entities
    ]

    techniques_list = [
        {
            "technique_id": t.technique.technique_id,
            "technique_name": t.technique.technique_name,
            "tactic": t.technique.tactic,
            "description": t.technique.description,
            "evidence": t.evidence,
            "mapping_confidence": t.mapping_confidence,
            "verification_status": t.verification_status,
            "url": t.technique.url
        }
        for t in analysis.techniques if t.technique
    ]

    notes_list = [
        {
            "id": n.id,
            "author": n.author,
            "note": n.note,
            "created_at": n.created_at.isoformat()
        }
        for n in analysis.notes
    ]

    return {
        "id": analysis.id,
        "title": analysis.title,
        "original_text": analysis.original_text,
        "input_type": analysis.input_type,
        "file_name": analysis.file_name,
        "source": analysis.source,
        "predicted_category": analysis.predicted_category,
        "confidence": analysis.confidence,
        "prediction_method": analysis.prediction_method,
        "model_version": analysis.model_version,
        "is_uncertain": analysis.is_uncertain,
        "severity": analysis.severity,
        "severity_score": analysis.severity_score,
        "severity_rationale": rationale,
        "defensive_recommendations": recs,
        "indicators": indicators_list,
        "entities": entities_list,
        "techniques": techniques_list,
        "notes": notes_list,
        "status": analysis.status,
        "created_at": analysis.created_at.isoformat(),
        "updated_at": analysis.updated_at.isoformat()
    }


@router.post("/text", response_model=AnalysisResponse)
def analyze_text(payload: TextAnalysisRequest, db: Session = Depends(get_db)):
    """Analyzes raw unstructured threat narrative or report text."""
    analysis = _process_and_save_analysis(
        text=payload.text,
        title=payload.title,
        input_type="text",
        source=payload.source,
        file_name=None,
        notes=payload.notes,
        db=db
    )
    return _serialize_analysis_response(analysis, db)


@router.post("/document", response_model=AnalysisResponse)
async def analyze_document(
    file: UploadFile = File(...),
    title: Optional[str] = Form(None),
    source: Optional[str] = Form("Uploaded Document"),
    notes: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    """Safely extracts text from uploaded document (TXT, CSV, JSON, PDF) and performs threat analysis."""
    contents = await file.read()
    success, extracted_text, meta = DocumentParser.parse_file(file.filename, contents)
    if not success:
        raise HTTPException(status_code=400, detail=meta.get("error", "Failed to parse uploaded document."))

    doc_title = title if title and title.strip() else f"Document: {file.filename}"
    analysis = _process_and_save_analysis(
        text=extracted_text,
        title=doc_title,
        input_type="document",
        source=source,
        file_name=file.filename,
        notes=notes,
        db=db
    )
    return _serialize_analysis_response(analysis, db)


@router.post("/indicator", response_model=AnalysisResponse)
def analyze_indicator(payload: IndicatorAnalysisRequest, db: Session = Depends(get_db)):
    """Performs structured investigation on an individual technical indicator."""
    val = payload.indicator.strip()
    narrative = f"Target technical indicator submitted for investigation: {val}. Indicator query and correlation."
    doc_title = f"Indicator Triage: {IOCExtractor.defang(val, 'url')}"

    analysis = _process_and_save_analysis(
        text=narrative,
        title=doc_title,
        input_type="indicator",
        source="Direct Indicator Query",
        file_name=None,
        notes=payload.notes,
        db=db
    )
    return _serialize_analysis_response(analysis, db)
