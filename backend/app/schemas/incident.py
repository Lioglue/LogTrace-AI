from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class IncidentResponse(BaseModel):
    id: int
    title: str
    description: Optional[str] = None
    severity: Optional[str] = None
    risk_score: float = 0
    confidence: float = 0
    status: str = "open"
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    event_count: int = 0
    related_ips: List[str] = []
    related_users: List[str] = []

    class Config:
        from_attributes = True


class IncidentDetail(IncidentResponse):
    affected_systems: List[str] = []
    detection_reasons: List[str] = []


class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
