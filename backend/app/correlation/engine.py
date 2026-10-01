import json
from typing import List, Dict, Any, Tuple
from datetime import timedelta
from sqlalchemy.orm import Session
from app.models.log_event import LogEvent
from app.config.settings import settings

SAME_IP_POINTS = 30
SAME_USERNAME_POINTS = 25
SAME_HOSTNAME_POINTS = 15
SAME_SOURCE_POINTS = 10
WITHIN_5MIN_POINTS = 20
WITHIN_15MIN_POINTS = 10
RELATED_SEQUENCE_POINTS = 30
MAX_SCORE = 100


class CorrelationEngine:
    def __init__(self, db: Session):
        self.db = db
        self.threshold = settings.CORRELATION_THRESHOLD
        self.time_window = settings.CORRELATION_TIME_WINDOW_MINUTES

    def correlate(self, events: List[LogEvent]) -> List[List[Tuple[LogEvent, float, List[str]]]]:
        suspicious = [e for e in events if e.is_suspicious]
        if not suspicious:
            return []

        groups: List[List[Tuple[LogEvent, float, List[str]]]] = []
        used = set()

        for i, event in enumerate(suspicious):
            if event.id in used:
                continue

            group = [(event, 100.0, ["Initiating event"])]
            used.add(event.id)

            queue = [event]
            while queue:
                current = queue.pop(0)
                for other in suspicious:
                    if other.id in used:
                        continue
                    score, reasons = self._calculate_correlation(current, other)
                    if score >= self.threshold:
                        group.append((other, score, reasons))
                        used.add(other.id)
                        queue.append(other)

            if len(group) >= 2:
                groups.append(group)

        return groups

    def _calculate_correlation(self, a: LogEvent, b: LogEvent) -> Tuple[float, List[str]]:
        score = 0.0
        reasons = []

        if a.ip_address and b.ip_address and a.ip_address == b.ip_address:
            score += SAME_IP_POINTS
            reasons.append("Same IP address")

        if a.username and b.username and a.username.lower() == b.username.lower():
            score += SAME_USERNAME_POINTS
            reasons.append("Same username")

        if a.hostname and b.hostname and a.hostname == b.hostname:
            score += SAME_HOSTNAME_POINTS
            reasons.append("Same hostname")

        if a.source and b.source and a.source == b.source:
            score += SAME_SOURCE_POINTS
            reasons.append("Same source system")

        if a.timestamp and b.timestamp:
            diff = abs((a.timestamp - b.timestamp).total_seconds())
            if diff <= 300:
                score += WITHIN_5MIN_POINTS
                reasons.append(f"Events occurred within {int(diff // 60)} minute(s)")
            elif diff <= 900:
                score += WITHIN_15MIN_POINTS
                reasons.append(f"Events occurred within {int(diff // 60)} minute(s)")

        if self._are_related_sequence(a, b) or self._are_related_sequence(b, a):
            score += RELATED_SEQUENCE_POINTS
            reasons.append("Events form a related sequence")

        score = min(score, MAX_SCORE)
        return score, reasons

    def _are_related_sequence(self, a: LogEvent, b: LogEvent) -> bool:
        related_pairs = [
            ("LOGIN_FAILED", "LOGIN_SUCCESS"),
            ("LOGIN_SUCCESS", "RESOURCE_ACCESS"),
            ("LOGIN_SUCCESS", "HTTP_REQUEST"),
            ("FIREWALL_BLOCK", "FIREWALL_ALLOW"),
            ("ACCESS_DENIED", "LOGIN_SUCCESS"),
        ]

        if a.event_type == "LOGIN_FAILED" and b.event_type == "LOGIN_SUCCESS":
            return True

        if a.event_type in ("LOGIN_SUCCESS", "SESSION_START") and b.event_type in (
            "RESOURCE_ACCESS", "HTTP_REQUEST", "ACCESS_DENIED",
        ):
            return True

        if a.event_type == "ACCESS_DENIED" and b.event_type in ("LOGIN_SUCCESS", "HTTP_REQUEST"):
            return True

        return False

    def get_correlation_summary(self, group: List[Tuple[LogEvent, float, List[str]]]) -> Dict[str, Any]:
        all_reasons = []
        for _, _, reasons in group:
            all_reasons.extend(reasons)

        avg_score = sum(s for _, s, _ in group) / len(group) if group else 0

        return {
            "event_count": len(group),
            "average_correlation_score": round(avg_score, 1),
            "unique_reasons": list(set(all_reasons)),
            "ip_addresses": list(set(e.ip_address for e, _, _ in group if e.ip_address)),
            "usernames": list(set(e.username for e, _, _ in group if e.username)),
            "hostnames": list(set(e.hostname for e, _, _ in group if e.hostname)),
        }
