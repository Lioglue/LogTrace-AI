import re
from typing import Optional, Dict, Any
from datetime import datetime
from app.parsers.base_parser import BaseParser


class SystemParser(BaseParser):
    ERROR_RE = re.compile(r'\b(error|fail|crit|emerg)\b', re.IGNORECASE)
    WARN_RE = re.compile(r'\b(warning|warn)\b', re.IGNORECASE)
    KERNEL_RE = re.compile(r'kernel', re.IGNORECASE)
    SERVICE_RE = re.compile(r'systemd|service|daemon', re.IGNORECASE)

    def parse(self, raw_line: str) -> Optional[Dict[str, Any]]:
        if not raw_line.strip():
            return None

        raw = raw_line.strip()
        event_type = "SYSTEM_EVENT"
        severity = "low"
        resource = None

        if self.ERROR_RE.search(raw):
            severity = "high"
            event_type = "SYSTEM_ERROR"
        elif self.WARN_RE.search(raw):
            severity = "medium"
            event_type = "SYSTEM_WARNING"

        if self.KERNEL_RE.search(raw):
            resource = "kernel"
        elif self.SERVICE_RE.search(raw):
            service_match = re.search(r'(\w+)\.service', raw)
            if service_match:
                resource = service_match.group(1)

        return {
            "timestamp": self.extract_timestamp(raw),
            "ip_address": self.extract_ip(raw),
            "username": self.extract_username(raw),
            "hostname": self.extract_hostname(raw),
            "source": "system",
            "event_type": event_type,
            "severity": severity,
            "resource": resource,
            "raw_message": raw,
        }
