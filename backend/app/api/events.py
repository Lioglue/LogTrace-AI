import json
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime
from app.database.connection import get_db
from app.api.auth import get_current_user
from app.models.log_event import LogEvent
from app.models.detection_alert import DetectionAlert
from app.models.incident import IncidentEvent
from app.schemas.log_event import LogEventResponse, LogEventDetail

router = APIRouter(prefix="/api/events", tags=["Events"])


@router.get("", response_model=list[LogEventResponse])
def list_events(
    skip: int = 0,
    limit: int = 50,
    search: Optional[str] = None,
    ip_address: Optional[str] = None,
    username: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    event_type: Optional[str] = None,
    suspicious_only: bool = False,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    query = db.query(LogEvent)

    if search:
        query = query.filter(LogEvent.raw_message.contains(search))
    if ip_address:
        query = query.filter(LogEvent.ip_address == ip_address)
    if username:
        query = query.filter(LogEvent.username == username)
    if severity:
        query = query.filter(LogEvent.severity == severity)
    if source:
        query = query.filter(LogEvent.source == source)
    if event_type:
        query = query.filter(LogEvent.event_type == event_type)
    if suspicious_only:
        query = query.filter(LogEvent.is_suspicious == 1)

    events = query.order_by(LogEvent.timestamp.desc()).offset(skip).limit(limit).all()

    result = []
    for event in events:
        event_dict = LogEventResponse.model_validate(event)
        alerts = db.query(DetectionAlert).filter(DetectionAlert.event_id == event.id).all()
        event_dict.alerts = [
            {"rule_name": a.rule_name, "severity": a.severity, "description": a.description}
            for a in alerts
        ]
        result.append(event_dict)

    return result


@router.get("/{event_id}", response_model=LogEventDetail)
def get_event(
    event_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    event = db.query(LogEvent).filter(LogEvent.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    event_dict = LogEventDetail.model_validate(event)

    alerts = db.query(DetectionAlert).filter(DetectionAlert.event_id == event.id).all()
    event_dict.alerts = [
        {"rule_name": a.rule_name, "severity": a.severity, "description": a.description}
        for a in alerts
    ]

    related_incidents = (
        db.query(IncidentEvent)
        .filter(IncidentEvent.event_id == event.id)
        .all()
    )
    event_dict.related_incidents = [
        {"incident_id": ie.incident_id, "correlation_score": ie.correlation_score}
        for ie in related_incidents
    ]

    return event_dict
