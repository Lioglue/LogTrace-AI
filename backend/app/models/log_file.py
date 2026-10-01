from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database.connection import Base


class LogFile(Base):
    __tablename__ = "log_files"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    filename = Column(String(255), nullable=False)
    source_type = Column(String(50), nullable=False, default="auto")
    uploaded_at = Column(DateTime(timezone=True), server_default=func.now())
    processing_status = Column(String(50), default="pending")
    event_count = Column(Integer, default=0)
    suspicious_count = Column(Integer, default=0)
    lines_total = Column(Integer, default=0)
    lines_parsed = Column(Integer, default=0)
    lines_skipped = Column(Integer, default=0)
    detected_format = Column(String(50), default="generic")
    processing_notes = Column(Text, default="")

    user = relationship("User", back_populates="log_files")
    events = relationship("LogEvent", back_populates="log_file")
