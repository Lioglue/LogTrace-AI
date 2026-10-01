import json
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.models.incident import Incident, IncidentEvent
from app.models.log_event import LogEvent
from app.models.detection_alert import DetectionAlert
from app.models.attack_story import AttackStory, AttackStoryEntry


EVENT_DESCRIPTIONS = {
    "LOGIN_FAILED": "Failed authentication attempt detected",
    "LOGIN_SUCCESS": "Successful authentication event",
    "ACCOUNT_LOCKED": "Account lockout detected",
    "PRIVILEGE_CHANGE": "Privilege change detected",
    "SESSION_START": "Session initiated",
    "SESSION_END": "Session terminated",
    "HTTP_REQUEST": "HTTP request processed",
    "HTTP_ERROR": "HTTP error response",
    "ACCESS_DENIED": "Access denied",
    "FIREWALL_BLOCK": "Traffic blocked by firewall",
    "FIREWALL_ALLOW": "Traffic allowed by firewall",
    "NETWORK_CONNECTION": "Network connection detected",
    "RESOURCE_ACCESS": "Resource access detected",
    "APP_ERROR": "Application error detected",
    "APP_WARNING": "Application warning detected",
    "APP_LOG": "Application event logged",
    "SYSTEM_ERROR": "System error detected",
    "SYSTEM_WARNING": "System warning detected",
    "SYSTEM_EVENT": "System event logged",
    "GENERIC": "Generic event detected",
    "GENERIC_ERROR": "Error event detected",
    "CSV_RECORD": "CSV record imported",
}


class StoryGenerator:
    def __init__(self, db: Session):
        self.db = db

    def generate(self, incidents: List[Incident]) -> List[AttackStory]:
        stories = []
        for incident in incidents:
            story = self._generate_for_incident(incident)
            if story:
                stories.append(story)
        return stories

    def _generate_for_incident(self, incident: Incident) -> AttackStory:
        incident_events = (
            self.db.query(IncidentEvent)
            .filter(IncidentEvent.incident_id == incident.id)
            .order_by(IncidentEvent.sequence_order)
            .all()
        )

        if not incident_events:
            return None

        event_ids = [ie.event_id for ie in incident_events]
        events = self.db.query(LogEvent).filter(LogEvent.id.in_(event_ids)).all()
        events_by_id = {e.id: e for e in events}
        events.sort(key=lambda x: x.timestamp or datetime.min)

        story = AttackStory(
            incident_id=incident.id,
            title=f"Investigation Story: {incident.title}",
            summary=self._generate_summary(events, incident),
            conclusion=self._generate_conclusion(events, incident),
        )
        self.db.add(story)
        self.db.flush()

        entries = self._build_entries(events, incident)
        for i, entry_data in enumerate(entries):
            entry = AttackStoryEntry(
                story_id=story.id,
                sequence_order=i,
                timestamp=entry_data["timestamp"],
                title=entry_data["title"],
                description=entry_data["description"],
                event_ids=json.dumps(entry_data["event_ids"]),
                event_type=entry_data["event_type"],
                severity=entry_data["severity"],
            )
            self.db.add(entry)

        timeline = []
        for i, entry_data in enumerate(entries):
            timeline.append({
                "order": i,
                "timestamp": entry_data["timestamp"].isoformat() if entry_data["timestamp"] else None,
                "title": entry_data["title"],
                "severity": entry_data["severity"],
            })
        story.timeline_json = json.dumps(timeline)

        self.db.flush()
        return story

    def _build_entries(self, events: List[LogEvent], incident: Incident) -> List[Dict[str, Any]]:
        entries = []
        grouped = self._group_events(events)

        for group in grouped:
            entry = self._create_entry_from_group(group)
            entries.append(entry)

        return entries

    def _group_events(self, events: List[LogEvent]) -> List[List[LogEvent]]:
        if not events:
            return []

        groups: List[List[LogEvent]] = []
        current_group: List[LogEvent] = [events[0]]

        for i in range(1, len(events)):
            prev = events[i - 1]
            curr = events[i]

            same_type = curr.event_type == prev.event_type
            time_close = False
            if curr.timestamp and prev.timestamp:
                time_close = (curr.timestamp - prev.timestamp) <= timedelta(minutes=2)
            same_ip = curr.ip_address and prev.ip_address and curr.ip_address == prev.ip_address

            if same_type and (time_close or same_ip):
                current_group.append(curr)
            else:
                groups.append(current_group)
                current_group = [curr]

        groups.append(current_group)
        return groups

    def _create_entry_from_group(self, group: List[LogEvent]) -> Dict[str, Any]:
        first = group[0]
        last = group[-1]

        start_time = first.timestamp
        end_time = last.timestamp

        event_type = first.event_type
        count = len(group)

        if count == 1:
            title = EVENT_DESCRIPTIONS.get(event_type, f"{event_type} detected")
        else:
            time_range = ""
            if start_time and end_time:
                time_range = f" ({start_time.strftime('%H:%M')}–{end_time.strftime('%H:%M')})"
            base = EVENT_DESCRIPTIONS.get(event_type, f"{event_type} events")
            title = f"{count}× {base}{time_range}"

        description = self._build_description(group, event_type, count)
        max_severity = max((e.severity for e in group), key=lambda s: ["low", "medium", "high", "critical"].index(s))

        return {
            "timestamp": start_time,
            "title": title,
            "description": description,
            "event_ids": [e.id for e in group],
            "event_type": event_type,
            "severity": max_severity,
        }

    def _build_description(self, group: List[LogEvent], event_type: str, count: int) -> str:
        ips = list(set(e.ip_address for e in group if e.ip_address))
        users = list(set(e.username for e in group if e.username))
        resources = list(set(e.resource for e in group if e.resource))

        parts = []

        if count == 1:
            event = group[0]
            if event.raw_message:
                msg = event.raw_message[:300]
                parts.append(f"Raw log: {msg}")
        else:
            if ips:
                parts.append(f"Source IP(s): {', '.join(ips)}")
            if users:
                parts.append(f"User(s): {', '.join(users)}")

        if resources:
            parts.append(f"Resource(s): {', '.join(resources[:3])}")

        alerts = self.db.query(DetectionAlert).filter(
            DetectionAlert.event_id.in_([e.id for e in group])
        ).all()
        if alerts:
            reasons = list(set(a.rule_name for a in alerts))
            parts.append(f"Detection rules triggered: {', '.join(reasons)}")

        return ". ".join(parts) if parts else f"Event type: {event_type}"

    def _generate_summary(self, events: List[LogEvent], incident: Incident) -> str:
        if not events:
            return "No events available for summary."

        event_types = [e.event_type for e in events]
        ips = list(set(e.ip_address for e in events if e.ip_address))
        users = list(set(e.username for e in events if e.username))

        first_ts = min((e.timestamp for e in events if e.timestamp), default=None)
        last_ts = max((e.timestamp for e in events if e.timestamp), default=None)

        duration = ""
        if first_ts and last_ts:
            diff = (last_ts - first_ts).total_seconds()
            if diff < 60:
                duration = f"within {int(diff)} seconds"
            elif diff < 3600:
                duration = f"within {int(diff // 60)} minutes"
            else:
                duration = f"within {int(diff // 3600)} hours"

        summary_parts = [
            f"This investigation involves {len(events)} related events",
        ]

        if duration:
            summary_parts[0] += f" {duration}"

        summary_parts[0] += "."

        if ips:
            summary_parts.append(f"Source IP addresses involved: {', '.join(ips[:5])}.")
        if users:
            summary_parts.append(f"Users involved: {', '.join(users[:5])}.")

        has_failures = "LOGIN_FAILED" in event_types
        has_success = "LOGIN_SUCCESS" in event_types
        has_sensitive = any(
            e.resource and any(
                kw in (e.resource or "").lower()
                for kw in ["/admin", "/database", "/secret", "/backup", "financial"]
            )
            for e in events
        )

        if has_failures and has_success:
            summary_parts.append(
                "The activity sequence includes failed authentication followed by successful authentication."
            )
        if has_sensitive:
            summary_parts.append("Sensitive resource access was detected.")

        return " ".join(summary_parts)

    def _generate_conclusion(self, events: List[LogEvent], incident: Incident) -> str:
        if not events:
            return "No events available for analysis."

        event_types = set(e.event_type for e in events)
        has_failures = "LOGIN_FAILED" in event_types
        has_success = "LOGIN_SUCCESS" in event_types
        has_sensitive = any(
            e.resource and any(
                kw in (e.resource or "").lower()
                for kw in ["/admin", "/database", "/secret", "/backup", "financial"]
            )
            for e in events
        )

        if has_failures and has_success and has_sensitive:
            return (
                "Multiple related authentication and resource access events were detected within a short period. "
                "The events share common attributes and may represent a potential security incident. "
                "Failed authentication was followed by successful authentication and subsequent access to a sensitive resource. "
                "Further investigation is recommended to determine if unauthorized access occurred."
            )
        elif has_failures and has_success:
            return (
                "Multiple related authentication events were detected. Failed login attempts were followed by "
                "a successful authentication from the same source. This pattern may indicate a credential guessing "
                "or stuffing attack. Further investigation is recommended."
            )
        elif has_failures:
            return (
                "Multiple failed authentication attempts were detected. While no successful authentication was "
                "observed, the volume and pattern of failures may warrant monitoring. "
                "Further investigation may be warranted if the activity continues."
            )
        else:
            return (
                f"Multiple related suspicious events were detected and correlated. "
                f"The evidence suggests these events may be connected. "
                f"Investigation is recommended to determine the nature and impact of the activity."
            )
