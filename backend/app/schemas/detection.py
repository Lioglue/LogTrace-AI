from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class DetectionAlertResponse(BaseModel):
    id: int
    event_id: Optional[int] = None
    rule_name: str
    severity: str
    description: Optional[str] = None
    risk_points: int = 0
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True
