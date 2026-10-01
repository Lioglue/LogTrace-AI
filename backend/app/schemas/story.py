from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class AttackStoryEntryResponse(BaseModel):
    id: int
    sequence_order: int
    timestamp: Optional[datetime] = None
    title: Optional[str] = None
    description: Optional[str] = None
    event_ids: str = "[]"
    event_type: Optional[str] = None
    severity: Optional[str] = None

    class Config:
        from_attributes = True


class AttackStoryResponse(BaseModel):
    id: int
    incident_id: int
    title: Optional[str] = None
    summary: Optional[str] = None
    timeline_json: str = "[]"
    conclusion: Optional[str] = None
    created_at: Optional[datetime] = None
    entries: List[AttackStoryEntryResponse] = []

    class Config:
        from_attributes = True
