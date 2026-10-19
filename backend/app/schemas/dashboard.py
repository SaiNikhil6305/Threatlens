from pydantic import BaseModel
from typing import List, Dict, Any, Optional

class DashboardSummary(BaseModel):
    total_reports: int
    total_indicators: int
    high_critical_count: int
    top_threat_category: str
    pending_review_count: int
    category_distribution: Dict[str, int]
    severity_distribution: Dict[str, int]
    indicator_distribution: Dict[str, int]
    activity_timeline: List[Dict[str, Any]]
    recent_investigations: List[Dict[str, Any]]
