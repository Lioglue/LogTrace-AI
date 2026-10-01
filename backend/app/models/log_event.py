from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database.connection import Base


class LogEvent(Base):
    __tablename__ = "log_events"

    id = Column(Integer, primary_key=True, index=True)
    log_file_id = Column(Integer, ForeignKey("log_files.id"), nullable=True)
    timestamp = Column(DateTime(timezone=True), index=True)
    source = Column(String(100))
    event_type = Column(String(100), index=True)
    ip_address = Column(String(45), index=True)
    username = Column(String(100), index=True)
    hostname = Column(String(255))
    resource = Column(String(255))
    severity = Column(String(20), index=True)
    raw_message = Column(Text)
    metadata_json = Column(Text, default="{}")
    is_suspicious = Column(Integer, default=0)
    importance = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    log_file = relationship("LogFile", back_populates="events")
    alerts = relationship("DetectionAlert", back_populates="event")
