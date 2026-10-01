from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database.connection import Base


class AttackStory(Base):
    __tablename__ = "attack_stories"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    title = Column(String(300))
    summary = Column(Text)
    timeline_json = Column(Text, default="[]")
    conclusion = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    incident = relationship("Incident", back_populates="stories")
    entries = relationship("AttackStoryEntry", back_populates="story", cascade="all, delete-orphan")


class AttackStoryEntry(Base):
    __tablename__ = "attack_story_entries"

    id = Column(Integer, primary_key=True, index=True)
    story_id = Column(Integer, ForeignKey("attack_stories.id"), nullable=False)
    sequence_order = Column(Integer, nullable=False)
    timestamp = Column(DateTime(timezone=True))
    title = Column(String(300))
    description = Column(Text)
    event_ids = Column(Text, default="[]")
    event_type = Column(String(100))
    severity = Column(String(20))

    story = relationship("AttackStory", back_populates="entries")
