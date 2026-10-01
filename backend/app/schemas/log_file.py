from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class LogFileResponse(BaseModel):
    id: int
    filename: str
    source_type: str
    uploaded_at: Optional[datetime] = None
    processing_status: str
    event_count: int = 0
    suspicious_count: int = 0
    lines_total: int = 0
    lines_parsed: int = 0
    lines_skipped: int = 0
    detected_format: Optional[str] = None
    processing_notes: Optional[str] = None

    class Config:
        from_attributes = True
