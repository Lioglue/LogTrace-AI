from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database.connection import Base


class DetectionAlert(Base):
    __tablename__ = "detection_alerts"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("log_events.id"), nullable=True)
    rule_name = Column(String(200), nullable=False)
    severity = Column(String(20), nullable=False)
    description = Column(Text)
    risk_points = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    event = relationship("LogEvent", back_populates="alerts")
