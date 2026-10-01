import json
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional
from app.database.connection import get_db
from app.api.auth import get_current_user
from app.models.incident import Incident, IncidentEvent
from app.models.log_event import LogEvent
from app.models.attack_story import AttackStory, AttackStoryEntry
from app.schemas.incident import IncidentResponse, IncidentDetail, IncidentUpdate
from app.schemas.story import AttackStoryResponse, AttackStoryEntryResponse

router = APIRouter(prefix="/api/incidents", tags=["Incidents"])


@router.get("", response_model=list[IncidentResponse])
def list_incidents(
    skip: int = 0,
    limit: int = 50,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    query = db.query(Incident)

    if severity:
        query = query.filter(Incident.severity == severity)
    if status:
        query = query.filter(Incident.status == status)

    incidents = query.order_by(Incident.created_at.desc()).offset(skip).limit(limit).all()

    result = []
    for inc in incidents:
        inc_events = db.query(IncidentEvent).filter(IncidentEvent.incident_id == inc.id).all()
        event_ids = [ie.event_id for ie in inc_events]
        events = db.query(LogEvent).filter(LogEvent.id.in_(event_ids)).all() if event_ids else []

        result.append(IncidentResponse(
            id=inc.id,
            title=inc.title,
            description=inc.description,
            severity=inc.severity,
            risk_score=inc.risk_score,
            confidence=inc.confidence,
            status=inc.status,
            created_at=inc.created_at,
            updated_at=inc.updated_at,
            event_count=len(events),
            related_ips=list(set(e.ip_address for e in events if e.ip_address)),
            related_users=list(set(e.username for e in events if e.username)),
        ))

    return result


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    inc_events = (
        db.query(IncidentEvent)
        .filter(IncidentEvent.incident_id == inc.id)
        .order_by(IncidentEvent.sequence_order)
        .all()
    )

    event_ids = [ie.event_id for ie in inc_events]
    events = db.query(LogEvent).filter(LogEvent.id.in_(event_ids)).all() if event_ids else []
    events_dict = {e.id: e for e in events}

    related_ips = list(set(e.ip_address for e in events if e.ip_address))
    related_users = list(set(e.username for e in events if e.username))
    affected_systems = list(set(e.hostname for e in events if e.hostname))
    detection_reasons = []
    for ie in inc_events:
        try:
            reasons = json.loads(ie.correlation_reasons or "[]")
            detection_reasons.extend(reasons)
        except (json.JSONDecodeError, TypeError):
            pass
    detection_reasons = list(set(detection_reasons))

    detail = IncidentDetail(
        id=inc.id,
        title=inc.title,
        description=inc.description,
        severity=inc.severity,
        risk_score=inc.risk_score,
        confidence=inc.confidence,
        status=inc.status,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
        event_count=len(events),
        related_ips=related_ips,
        related_users=related_users,
        affected_systems=affected_systems,
        detection_reasons=detection_reasons,
    )

    return detail


@router.patch("/{incident_id}", response_model=IncidentResponse)
def update_incident(
    incident_id: int,
    update: IncidentUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    if update.status is not None:
        inc.status = update.status
    if update.title is not None:
        inc.title = update.title
    if update.description is not None:
        inc.description = update.description

    db.commit()
    db.refresh(inc)

    return IncidentResponse.model_validate(inc)


@router.get("/{incident_id}/story", response_model=AttackStoryResponse)
def get_attack_story(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    story = (
        db.query(AttackStory)
        .filter(AttackStory.incident_id == incident_id)
        .order_by(AttackStory.created_at.desc())
        .first()
    )

    if not story:
        raise HTTPException(status_code=404, detail="Attack story not found for this incident")

    entries = (
        db.query(AttackStoryEntry)
        .filter(AttackStoryEntry.story_id == story.id)
        .order_by(AttackStoryEntry.sequence_order)
        .all()
    )

    story_dict = AttackStoryResponse.model_validate(story)
    story_dict.entries = [AttackStoryEntryResponse.model_validate(e) for e in entries]

    return story_dict
