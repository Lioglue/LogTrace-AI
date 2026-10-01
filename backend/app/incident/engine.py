import json
from typing import List, Dict, Any, Tuple
from datetime import datetime
from sqlalchemy.orm import Session
from app.models.log_event import LogEvent
from app.models.incident import Incident, IncidentEvent
from app.models.detection_alert import DetectionAlert

SEVERITY_WEIGHTS = {
    "low": 5,
    "medium": 10,
    "high": 20,
    "critical": 30,
}


class IncidentEngine:
    def __init__(self, db: Session):
        self.db = db

    def cluster_incidents(
        self, events: List[LogEvent],
        correlated_groups: List[List[Tuple[LogEvent, float, List[str]]]]
    ) -> List[Incident]:
        incidents = []

        for group in correlated_groups:
            incident = self._create_incident_from_group(group)
            if incident:
                incidents.append(incident)

        individual_suspicious = [
            e for e in events
            if e.is_suspicious
            and not any(e.id == ge.id for group in correlated_groups for ge, _, _ in group)
        ]

        for event in individual_suspicious:
            incident = self._create_incident_from_single(event)
            if incident:
                incidents.append(incident)

        return incidents

    def _create_incident_from_group(
        self, group: List[Tuple[LogEvent, float, List[str]]]
    ) -> Incident:
        events = [e for e, _, _ in group]

        ips = list(set(e.ip_address for e in events if e.ip_address))
        users = list(set(e.username for e in events if e.username))
        hosts = list(set(e.hostname for e in events if e.hostname))
        sources = list(set(e.source for e in events if e.source))

        event_types = [e.event_type for e in events]
        has_auth_failure = "LOGIN_FAILED" in event_types
        has_auth_success = "LOGIN_SUCCESS" in event_types
        has_sensitive_access = any(
            e.resource and any(
                kw in (e.resource or "").lower()
                for kw in ["/admin", "/database", "/secret", "/backup", "financial"]
            )
            for e in events
        )

        if has_auth_failure and has_auth_success and has_sensitive_access:
            title = "Possible Brute Force Attack With Resource Access"
            description = (
                f"Multiple failed authentication attempts were followed by a successful login "
                f"and subsequent access to a sensitive resource. Events were detected from "
                f"{len(ips)} IP address(es) and {len(users)} user(s)."
            )
        elif has_auth_failure and has_auth_success:
            title = "Possible Credential Stuffing Attempt"
            description = (
                f"Multiple failed authentication attempts were followed by a successful login. "
                f"The events share common attributes and may represent a potential security incident."
            )
        elif has_auth_failure:
            title = "Repeated Authentication Failures"
            description = (
                f"Multiple failed authentication attempts were detected. "
                f"{len(events)} related events were correlated."
            )
        else:
            title = f"Correlated Suspicious Activity ({len(events)} events)"
            description = (
                f"Multiple suspicious events were correlated. "
                f"The events share common attributes and may represent related activity."
            )

        severity = self._determine_severity(events, has_auth_failure, has_auth_success, has_sensitive_access)

        first_ts = min((e.timestamp for e in events if e.timestamp), default=datetime.utcnow())
        last_ts = max((e.timestamp for e in events if e.timestamp), default=datetime.utcnow())

        incident = Incident(
            title=title,
            description=description,
            severity=severity,
            status="open",
        )
        self.db.add(incident)
        self.db.flush()

        reasons_map: Dict[int, List[str]] = {}
        for e, score, reasons in group:
            if e.id not in reasons_map:
                reasons_map[e.id] = []
            reasons_map[e.id].extend(reasons)

        for i, (e, score, reasons) in enumerate(group):
            incident_event = IncidentEvent(
                incident_id=incident.id,
                event_id=e.id,
                correlation_score=score,
                correlation_reasons=json.dumps(reasons_map.get(e.id, [])),
                sequence_order=i,
            )
            self.db.add(incident_event)

        self.db.flush()
        return incident

    def _create_incident_from_single(self, event: LogEvent) -> Incident:
        if event.importance < 3:
            return None

        title = f"Isolated Suspicious Event: {event.event_type}"
        description = (
            f"A single suspicious event of type '{event.event_type}' was detected. "
            f"The event has a severity of '{event.severity}' and may require investigation."
        )

        incident = Incident(
            title=title,
            description=description,
            severity=event.severity,
            status="open",
        )
        self.db.add(incident)
        self.db.flush()

        incident_event = IncidentEvent(
            incident_id=incident.id,
            event_id=event.id,
            correlation_score=0,
            correlation_reasons=json.dumps(["Isolated suspicious event"]),
            sequence_order=0,
        )
        self.db.add(incident_event)
        self.db.flush()

        return incident

    def _determine_severity(
        self, events: List[LogEvent],
        has_failures: bool, has_success: bool, has_sensitive: bool
    ) -> str:
        max_sev = "low"
        severity_order = ["low", "medium", "high", "critical"]

        for e in events:
            if severity_order.index(e.severity or "low") > severity_order.index(max_sev):
                max_sev = e.severity or "low"

        if has_failures and has_success and has_sensitive:
            return "critical"
        if has_failures and has_success:
            return "high"
        if has_sensitive:
            return "high"

        return max_sev

    def calculate_risk_scores(self, incidents: List[Incident]) -> List[Incident]:
        for incident in incidents:
            incident_events = self.db.query(IncidentEvent).filter(
                IncidentEvent.incident_id == incident.id
            ).all()

            event_ids = [ie.event_id for ie in incident_events]
            events = self.db.query(LogEvent).filter(LogEvent.id.in_(event_ids)).all()

            risk_score = self._calculate_risk(incident, events, incident_events)
            confidence = self._calculate_confidence(incident, events, incident_events)

            incident.risk_score = risk_score
            incident.confidence = confidence
            incident.severity = self._score_to_severity(risk_score)

        self.db.flush()
        return incidents

    def _calculate_risk(
        self, incident: Incident, events: List[LogEvent],
        incident_events: List[IncidentEvent]
    ) -> float:
        score = 0.0

        for e in events:
            score += SEVERITY_WEIGHTS.get(e.severity, 5)

        avg_corr = 0
        if incident_events:
            scores = [ie.correlation_score for ie in incident_events]
            avg_corr = sum(scores) / len(scores)
        score += avg_corr * 0.15

        has_sensitive = any(
            e.resource and any(
                kw in (e.resource or "").lower()
                for kw in ["/admin", "/database", "/secret", "/backup", "financial"]
            )
            for e in events
        )
        if has_sensitive:
            score += 15

        event_types = set(e.event_type for e in events)
        if "LOGIN_FAILED" in event_types and "LOGIN_SUCCESS" in event_types:
            score += 20

        if len(events) > 5:
            score += 10

        distinct_hosts = len(set(e.hostname for e in events if e.hostname))
        if distinct_hosts > 1:
            score += distinct_hosts * 3

        score = min(score, 100)
        return round(score, 1)

    def _calculate_confidence(
        self, incident: Incident, events: List[LogEvent],
        incident_events: List[IncidentEvent]
    ) -> float:
        if not incident_events:
            return 30.0

        confidence = 0.0

        scores = [ie.correlation_score for ie in incident_events]
        avg_score = sum(scores) / len(scores) if scores else 0
        confidence += avg_score * 0.4

        unique_reasons = set()
        for ie in incident_events:
            try:
                reasons = json.loads(ie.correlation_reasons or "[]")
                unique_reasons.update(reasons)
            except (json.JSONDecodeError, TypeError):
                pass
        confidence += min(len(unique_reasons) * 5, 25)

        event_count = len(events)
        if event_count >= 3:
            confidence += 10
        if event_count >= 5:
            confidence += 5

        has_sequence = any(
            ie.correlation_score > 60 for ie in incident_events
        )
        if has_sequence:
            confidence += 15

        confidence = min(confidence, 95)
        return round(confidence, 1)

    def _score_to_severity(self, score: float) -> str:
        if score >= 76:
            return "critical"
        elif score >= 51:
            return "high"
        elif score >= 26:
            return "medium"
        return "low"
