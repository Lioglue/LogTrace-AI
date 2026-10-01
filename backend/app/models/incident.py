from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Float
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database.connection import Base


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(300), nullable=False)
    description = Column(Text)
    severity = Column(String(20), index=True)
    risk_score = Column(Float, default=0)
    confidence = Column(Float, default=0)
    status = Column(String(50), default="open", index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    incident_events = relationship("IncidentEvent", back_populates="incident", cascade="all, delete-orphan")
    stories = relationship("AttackStory", back_populates="incident", cascade="all, delete-orphan")


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    event_id = Column(Integer, ForeignKey("log_events.id"), nullable=False)
    correlation_score = Column(Float, default=0)
    correlation_reasons = Column(Text, default="[]")
    sequence_order = Column(Integer, default=0)

    incident = relationship("Incident", back_populates="incident_events")
    event = relationship("LogEvent")
