from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime

class TextAnalysisRequest(BaseModel):
    text: str = Field(..., min_length=3, description="Unstructured cybersecurity report or incident narrative")
    title: Optional[str] = Field(None, max_length=255, description="Optional title for the investigation")
    source: Optional[str] = Field("Manual Submission", max_length=255, description="Intelligence source or origin")
    notes: Optional[str] = Field(None, description="Optional initial analyst notes")

class IndicatorAnalysisRequest(BaseModel):
    indicator: str = Field(..., min_length=2, description="Target technical indicator (IPv4, domain, URL, hash, CVE)")
    indicator_type: Optional[str] = Field(None, description="Optional indicator type hint")
    notes: Optional[str] = Field(None, description="Optional notes")

class IndicatorItemSchema(BaseModel):
    id: Optional[str] = None
    original_value: str
    normalized_value: str
    defanged_value: Optional[str] = None
    indicator_type: str
    reputation_status: Optional[str] = "Not checked"
    verification_status: Optional[str] = "Unverified"
    evidence_snippet: Optional[str] = None
    confidence: Optional[float] = 1.0

class EntityItemSchema(BaseModel):
    id: Optional[str] = None
    entity_type: str
    entity_value: str
    evidence_snippet: Optional[str] = None
    confidence: Optional[float] = 0.85
    verification_status: Optional[str] = "Unverified"

class TechniqueItemSchema(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    description: Optional[str] = None
    evidence: Optional[str] = None
    mapping_confidence: Optional[float] = 0.8
    verification_status: Optional[str] = "Potential Mapping"
    url: Optional[str] = None

class AnalysisResponse(BaseModel):
    id: str
    title: str
    original_text: str
    input_type: str
    file_name: Optional[str] = None
    source: Optional[str] = None
    predicted_category: str
    confidence: float
    prediction_method: str
    model_version: Optional[str] = None
    is_uncertain: bool
    severity: str
    severity_score: float
    severity_rationale: Dict[str, Any]
    defensive_recommendations: List[Dict[str, str]]
    indicators: List[IndicatorItemSchema]
    entities: List[EntityItemSchema]
    techniques: List[TechniqueItemSchema]
    notes: List[Dict[str, Any]]
    status: str
    created_at: str
    updated_at: str

class AnalysisSummary(BaseModel):
    id: str
    title: str
    input_type: str
    predicted_category: str
    severity: str
    confidence: float
    prediction_method: str
    indicators_count: int
    created_at: str
    status: str
