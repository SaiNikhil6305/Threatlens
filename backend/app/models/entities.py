import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Text, Integer, Float, Boolean, DateTime, ForeignKey, Index
)
from sqlalchemy.orm import relationship
from app.database.session import Base

def generate_uuid() -> str:
    return str(uuid.uuid4())

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    title = Column(String(255), nullable=False, index=True)
    original_text = Column(Text, nullable=False)
    input_type = Column(String(50), nullable=False, default="text")  # text, document, indicator
    file_name = Column(String(255), nullable=True)
    source = Column(String(255), nullable=True, default="Manual Submission")
    
    # Classification results
    predicted_category = Column(String(100), nullable=False, default="Unknown", index=True)
    confidence = Column(Float, nullable=False, default=0.0)
    prediction_method = Column(String(100), nullable=False, default="Rule-based Fallback")
    model_version = Column(String(50), nullable=True)
    is_uncertain = Column(Boolean, default=False)

    # Severity assessment
    severity = Column(String(50), nullable=False, default="Informational", index=True)  # Critical, High, Medium, Low, Informational
    severity_score = Column(Float, default=0.0)
    severity_rationale = Column(Text, nullable=True)  # JSON or text description of triggered rules & missing info
    
    # Defensive & Mitre summaries
    defensive_recommendations = Column(Text, nullable=True)  # JSON string
    
    status = Column(String(50), default="Completed", index=True)  # Completed, Review Pending, Archived
    created_at = Column(DateTime, default=utc_now, index=True)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    # Relationships
    indicators = relationship("AnalysisIndicator", back_populates="analysis", cascade="all, delete-orphan")
    entities = relationship("ExtractedEntity", back_populates="analysis", cascade="all, delete-orphan")
    techniques = relationship("AnalysisTechnique", back_populates="analysis", cascade="all, delete-orphan")
    notes = relationship("AnalystNote", back_populates="analysis", cascade="all, delete-orphan")


class Indicator(Base):
    __tablename__ = "indicators"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    normalized_value = Column(String(500), unique=True, nullable=False, index=True)
    original_value = Column(String(500), nullable=False)
    indicator_type = Column(String(50), nullable=False, index=True)  # ipv4, domain, url, email, md5, sha1, sha256, cve
    
    reputation_status = Column(String(100), default="Not checked", index=True)
    reputation_source = Column(String(100), nullable=True)
    reputation_details = Column(Text, nullable=True)  # JSON formatted external detections or notes
    last_enriched_at = Column(DateTime, nullable=True)
    
    verification_status = Column(String(50), default="Unverified", index=True)  # Unverified, Analyst Confirmed, False Positive
    first_observed = Column(DateTime, default=utc_now, index=True)
    last_observed = Column(DateTime, default=utc_now)
    created_at = Column(DateTime, default=utc_now)
    
    # Relationships
    analyses = relationship("AnalysisIndicator", back_populates="indicator")
    notes = relationship("AnalystNote", back_populates="indicator", cascade="all, delete-orphan")


class AnalysisIndicator(Base):
    __tablename__ = "analysis_indicators"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    analysis_id = Column(String(36), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, index=True)
    indicator_id = Column(String(36), ForeignKey("indicators.id", ondelete="CASCADE"), nullable=False, index=True)
    
    evidence_snippet = Column(Text, nullable=True)
    extraction_method = Column(String(100), default="Regex Engine")
    extraction_confidence = Column(Float, default=1.0)
    source_start = Column(Integer, nullable=True)
    source_end = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=utc_now)

    # Relationships
    analysis = relationship("Analysis", back_populates="indicators")
    indicator = relationship("Indicator", back_populates="analyses")


class ExtractedEntity(Base):
    __tablename__ = "extracted_entities"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    analysis_id = Column(String(36), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, index=True)
    entity_type = Column(String(100), nullable=False, index=True)  # MALWARE, THREAT_ACTOR, CVE, TOOL, ORG, PRODUCT, TECH
    entity_value = Column(String(255), nullable=False)
    evidence_snippet = Column(Text, nullable=True)
    confidence = Column(Float, default=0.85)
    verification_status = Column(String(50), default="Unverified")
    created_at = Column(DateTime, default=utc_now)

    analysis = relationship("Analysis", back_populates="entities")


class AttackTechnique(Base):
    __tablename__ = "attack_techniques"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    technique_id = Column(String(50), unique=True, nullable=False, index=True)  # e.g., T1566, T1059
    technique_name = Column(String(255), nullable=False, index=True)
    tactic = Column(String(100), nullable=False, index=True)  # Initial Access, Execution, Persistence, etc.
    description = Column(Text, nullable=True)
    mapping_source = Column(String(100), default="MITRE ATT&CK Enterprise v14")
    url = Column(String(500), nullable=True)


class AnalysisTechnique(Base):
    __tablename__ = "analysis_techniques"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    analysis_id = Column(String(36), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, index=True)
    technique_id = Column(String(36), ForeignKey("attack_techniques.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence = Column(Text, nullable=True)
    mapping_confidence = Column(Float, default=0.8)
    verification_status = Column(String(50), default="Potential Mapping")  # Potential Mapping, Analyst Confirmed, False Positive
    created_at = Column(DateTime, default=utc_now)

    analysis = relationship("Analysis", back_populates="techniques")
    technique = relationship("AttackTechnique")


class AnalystNote(Base):
    __tablename__ = "analyst_notes"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    analysis_id = Column(String(36), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=True, index=True)
    indicator_id = Column(String(36), ForeignKey("indicators.id", ondelete="CASCADE"), nullable=True, index=True)
    author = Column(String(100), default="Lead Analyst")
    note = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)

    analysis = relationship("Analysis", back_populates="notes")
    indicator = relationship("Indicator", back_populates="notes")


class ModelVersion(Base):
    __tablename__ = "model_versions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    version = Column(String(50), unique=True, nullable=False)
    model_name = Column(String(100), nullable=False)
    dataset_reference = Column(String(255), nullable=False)
    configuration = Column(Text, nullable=True)  # JSON configuration
    is_active = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utc_now)

    evaluations = relationship("ModelEvaluation", back_populates="model_version", cascade="all, delete-orphan")


class ModelEvaluation(Base):
    __tablename__ = "model_evaluations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    model_version_id = Column(String(36), ForeignKey("model_versions.id", ondelete="CASCADE"), nullable=False, index=True)
    dataset_reference = Column(String(255), nullable=False)
    accuracy = Column(Float, nullable=False)
    precision = Column(Float, nullable=False)
    recall = Column(Float, nullable=False)
    f1_score = Column(Float, nullable=False)
    evaluation_details = Column(Text, nullable=False)  # JSON: per-class metrics, confusion matrix, sample counts
    created_at = Column(DateTime, default=utc_now)

    model_version = relationship("ModelVersion", back_populates="evaluations")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    entity_type = Column(String(100), nullable=False, index=True)
    entity_id = Column(String(36), nullable=False, index=True)
    action = Column(String(100), nullable=False)  # CREATE, UPDATE, DELETE, ENRICH, VERIFY
    details = Column(Text, nullable=True)  # JSON or descriptive text
    actor = Column(String(100), default="System")
    created_at = Column(DateTime, default=utc_now, index=True)


class IntelligenceFeedItem(Base):
    __tablename__ = "intelligence_feed_items"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    title = Column(String(255), nullable=False, index=True)
    source = Column(String(100), nullable=False, index=True)  # CISA, ThreatLens Local, Advisory, CERT
    publication_date = Column(DateTime, default=utc_now, index=True)
    threat_category = Column(String(100), nullable=False, index=True)
    severity = Column(String(50), nullable=False, default="Informational", index=True)
    indicators_json = Column(Text, nullable=True)  # JSON array of indicators
    summary = Column(Text, nullable=False)
    url = Column(String(500), nullable=True)
    is_local = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utc_now)


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    filename = Column(String(255), nullable=False, index=True)
    file_type = Column(String(50), nullable=False)
    scan_timestamp = Column(DateTime, default=utc_now, index=True)
    severity = Column(String(50), nullable=False, default="No significant indicators detected", index=True)
    severity_score = Column(Float, default=0.0)
    finding_count = Column(Integer, default=0)
    processing_duration = Column(Float, default=0.0)
    report_path = Column(String(500), nullable=True)
    extracted_text = Column(Text, nullable=True)
    page_count = Column(Integer, default=1)
    word_count = Column(Integer, default=0)
    detection_method = Column(String(100), default="Hybrid (ML + Rule-Based)")
    predicted_category = Column(String(100), default="Safe", index=True)
    confidence = Column(Float, default=0.0)
    status = Column(String(50), default="Completed", index=True)
    ocr_required = Column(Boolean, default=False)
    recommended_actions_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now)

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_type = Column(String(100), nullable=False)
    severity = Column(String(50), nullable=False, default="Medium")
    evidence = Column(Text, nullable=False)
    page_number = Column(Integer, nullable=True, default=1)
    detection_method = Column(String(100), default="Rule-based Heuristics")
    explanation = Column(Text, nullable=False)
    recommended_action = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utc_now)

    scan = relationship("Scan", back_populates="findings")
