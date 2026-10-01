from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from datetime import datetime


class LogEventResponse(BaseModel):
    id: int
    log_file_id: Optional[int] = None
    timestamp: Optional[datetime] = None
    source: Optional[str] = None
    event_type: Optional[str] = None
    ip_address: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    resource: Optional[str] = None
    severity: Optional[str] = None
    raw_message: Optional[str] = None
    is_suspicious: int = 0
    importance: int = 0
    created_at: Optional[datetime] = None
    alerts: List[Any] = []

    class Config:
        from_attributes = True


class LogEventDetail(LogEventResponse):
    metadata_json: Optional[str] = "{}"
    related_events: List["LogEventResponse"] = []
    related_incidents: List[Any] = []
