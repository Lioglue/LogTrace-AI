import re
import json
from typing import Optional, Dict, Any
from datetime import datetime
from app.parsers.base_parser import BaseParser


class ApplicationParser(BaseParser):
    ERROR_RE = re.compile(r'\b(error|exception|fatal|panic|critical)\b', re.IGNORECASE)
    WARN_RE = re.compile(r'\b(warning|warn)\b', re.IGNORECASE)
    INFO_RE = re.compile(r'\b(info|information)\b', re.IGNORECASE)

    def parse(self, raw_line: str) -> Optional[Dict[str, Any]]:
        if not raw_line.strip():
            return None

        raw = raw_line.strip()
        event_type = "APP_LOG"
        severity = "low"
        resource = None
        metadata = {}

        try:
            if raw.startswith("{"):
                data = json.loads(raw)
                event_type = data.get("level", data.get("type", "APP_LOG")).upper()
                severity = self._map_log_level(data.get("level", "info"))
                return {
                    "timestamp": self.extract_timestamp(raw) or datetime.utcnow(),
                    "ip_address": data.get("ip") or self.extract_ip(raw),
                    "username": data.get("user") or data.get("username"),
                    "hostname": data.get("host") or data.get("hostname"),
                    "source": data.get("source", "application"),
                    "event_type": event_type,
                    "severity": severity,
                    "resource": data.get("resource") or data.get("path"),
                    "raw_message": raw,
                    "metadata": json.dumps(data, default=str)[:2000],
                }
        except json.JSONDecodeError:
            pass

        if self.ERROR_RE.search(raw):
            severity = "high"
            event_type = "APP_ERROR"
        elif self.WARN_RE.search(raw):
            severity = "medium"
            event_type = "APP_WARNING"
        elif self.INFO_RE.search(raw):
            severity = "low"

        return {
            "timestamp": self.extract_timestamp(raw),
            "ip_address": self.extract_ip(raw),
            "username": self.extract_username(raw),
            "hostname": self.extract_hostname(raw),
            "source": "application",
            "event_type": event_type,
            "severity": severity,
            "resource": resource,
            "raw_message": raw,
            "metadata": metadata,
        }

    def _map_log_level(self, level: str) -> str:
        level = level.lower()
        if level in ("error", "fatal", "panic", "critical"):
            return "high"
        elif level in ("warning", "warn"):
            return "medium"
        return "low"
