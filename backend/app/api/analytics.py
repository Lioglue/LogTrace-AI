from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, cast, Date
from datetime import datetime, timedelta
from app.database.connection import get_db
from app.api.auth import get_current_user
from app.models.log_file import LogFile
from app.models.log_event import LogEvent
from app.models.detection_alert import DetectionAlert
from app.models.incident import Incident
from app.schemas.analytics import DashboardAnalytics, EventAnalytics

router = APIRouter(prefix="/api/analytics", tags=["Analytics"])


@router.get("/dashboard", response_model=DashboardAnalytics)
def get_dashboard(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    total_logs = db.query(func.count(LogFile.id)).filter(LogFile.user_id == current_user.id).scalar() or 0
    total_events = db.query(func.count(LogEvent.id)).scalar() or 0
    suspicious_events = db.query(func.count(LogEvent.id)).filter(LogEvent.is_suspicious == 1).scalar() or 0
    active_incidents = db.query(func.count(Incident.id)).filter(Incident.status == "open").scalar() or 0
    critical_incidents = db.query(func.count(Incident.id)).filter(Incident.severity == "critical").scalar() or 0

    now = datetime.utcnow()
    events_over_time = []
    for i in range(13, -1, -1):
        day = now - timedelta(days=i)
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        count = db.query(func.count(LogEvent.id)).filter(
            LogEvent.timestamp >= day_start,
            LogEvent.timestamp < day_end,
        ).scalar() or 0
        events_over_time.append({"date": day_start.strftime("%Y-%m-%d"), "count": count})

    severity_dist = []
    for sev in ["low", "medium", "high", "critical"]:
        count = db.query(func.count(LogEvent.id)).filter(LogEvent.severity == sev).scalar() or 0
        severity_dist.append({"severity": sev, "count": count})

    risk_levels = [
        {"level": "Low", "range": "0-25", "count": 0},
        {"level": "Medium", "range": "26-50", "count": 0},
        {"level": "High", "range": "51-75", "count": 0},
        {"level": "Critical", "range": "76-100", "count": 0},
    ]
    incidents = db.query(Incident).all()
    for inc in incidents:
        if inc.risk_score <= 25:
            risk_levels[0]["count"] += 1
        elif inc.risk_score <= 50:
            risk_levels[1]["count"] += 1
        elif inc.risk_score <= 75:
            risk_levels[2]["count"] += 1
        else:
            risk_levels[3]["count"] += 1

    recent_incidents = (
        db.query(Incident)
        .order_by(Incident.created_at.desc())
        .limit(10)
        .all()
    )
    recent_inc_list = [
        {
            "id": inc.id, "title": inc.title, "severity": inc.severity,
            "risk_score": inc.risk_score, "confidence": inc.confidence,
            "status": inc.status, "created_at": inc.created_at.isoformat() if inc.created_at else None,
        }
        for inc in recent_incidents
    ]

    recent_suspicious = (
        db.query(LogEvent)
        .filter(LogEvent.is_suspicious == 1)
        .order_by(LogEvent.timestamp.desc())
        .limit(10)
        .all()
    )
    recent_susp_list = [
        {
            "id": e.id, "event_type": e.event_type, "severity": e.severity,
            "ip_address": e.ip_address, "username": e.username,
            "raw_message": (e.raw_message or "")[:200],
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        }
        for e in recent_suspicious
    ]

    return DashboardAnalytics(
        total_logs=total_logs,
        total_events=total_events,
        suspicious_events=suspicious_events,
        active_incidents=active_incidents,
        critical_incidents=critical_incidents,
        events_over_time=events_over_time,
        severity_distribution=severity_dist,
        incidents_by_risk=risk_levels,
        recent_incidents=recent_inc_list,
        recent_suspicious=recent_susp_list,
    )


@router.get("/events", response_model=EventAnalytics)
def get_event_analytics(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    now = datetime.utcnow()
    events_over_time = []
    for i in range(29, -1, -1):
        day = now - timedelta(days=i)
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        total = db.query(func.count(LogEvent.id)).filter(
            LogEvent.timestamp >= day_start, LogEvent.timestamp < day_end
        ).scalar() or 0
        suspicious = db.query(func.count(LogEvent.id)).filter(
            LogEvent.timestamp >= day_start, LogEvent.timestamp < day_end,
            LogEvent.is_suspicious == 1
        ).scalar() or 0
        events_over_time.append({
            "date": day_start.strftime("%Y-%m-%d"),
            "total": total,
            "suspicious": suspicious,
        })

    suspicious_over_time = [
        {"date": d["date"], "count": d["suspicious"]} for d in events_over_time
    ]

    incidents_over_time = []
    for i in range(29, -1, -1):
        day = now - timedelta(days=i)
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        count = db.query(func.count(Incident.id)).filter(
            Incident.created_at >= day_start, Incident.created_at < day_end
        ).scalar() or 0
        incidents_over_time.append({"date": day_start.strftime("%Y-%m-%d"), "count": count})

    top_ips = (
        db.query(LogEvent.ip_address, func.count(LogEvent.id).label("count"))
        .filter(LogEvent.ip_address.isnot(None))
        .group_by(LogEvent.ip_address)
        .order_by(func.count(LogEvent.id).desc())
        .limit(10)
        .all()
    )

    top_event_types = (
        db.query(LogEvent.event_type, func.count(LogEvent.id).label("count"))
        .group_by(LogEvent.event_type)
        .order_by(func.count(LogEvent.id).desc())
        .limit(10)
        .all()
    )

    top_rules = (
        db.query(DetectionAlert.rule_name, func.count(DetectionAlert.id).label("count"))
        .group_by(DetectionAlert.rule_name)
        .order_by(func.count(DetectionAlert.id).desc())
        .limit(10)
        .all()
    )

    severity_dist = []
    for sev in ["low", "medium", "high", "critical"]:
        count = db.query(func.count(LogEvent.id)).filter(LogEvent.severity == sev).scalar() or 0
        severity_dist.append({"severity": sev, "count": count})

    return EventAnalytics(
        events_over_time=events_over_time,
        suspicious_over_time=suspicious_over_time,
        incidents_over_time=incidents_over_time,
        top_ips=[{"ip": r[0], "count": r[1]} for r in top_ips],
        top_event_types=[{"type": r[0], "count": r[1]} for r in top_event_types],
        top_rules=[{"rule": r[0], "count": r[1]} for r in top_rules],
        severity_distribution=severity_dist,
    )
