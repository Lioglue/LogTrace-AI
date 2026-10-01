from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime


class DashboardAnalytics(BaseModel):
    total_logs: int = 0
    total_events: int = 0
    suspicious_events: int = 0
    active_incidents: int = 0
    critical_incidents: int = 0
    events_over_time: List[Dict[str, Any]] = []
    severity_distribution: List[Dict[str, Any]] = []
    incidents_by_risk: List[Dict[str, Any]] = []
    recent_incidents: List[Dict[str, Any]] = []
    recent_suspicious: List[Dict[str, Any]] = []


class EventAnalytics(BaseModel):
    events_over_time: List[Dict[str, Any]] = []
    suspicious_over_time: List[Dict[str, Any]] = []
    incidents_over_time: List[Dict[str, Any]] = []
    top_ips: List[Dict[str, Any]] = []
    top_event_types: List[Dict[str, Any]] = []
    top_rules: List[Dict[str, Any]] = []
    severity_distribution: List[Dict[str, Any]] = []
