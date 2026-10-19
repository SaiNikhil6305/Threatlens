from pydantic import BaseModel
from typing import List, Dict, Any, Optional

class IndicatorUpdateRequest(BaseModel):
    verification_status: Optional[str] = None  # Unverified, Analyst Confirmed, False Positive
    analyst_note: Optional[str] = None

class IndicatorResponse(BaseModel):
    id: str
    normalized_value: str
    original_value: str
    defanged_value: str
    indicator_type: str
    reputation_status: str
    reputation_source: Optional[str] = None
    verification_status: str
    associated_reports_count: int
    associated_reports: List[Dict[str, Any]]
    analyst_notes: List[Dict[str, Any]]
    first_observed: str
    last_observed: str
    last_enriched_at: Optional[str] = None
