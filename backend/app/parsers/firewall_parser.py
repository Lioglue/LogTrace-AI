import re
from typing import Optional, Dict, Any
from datetime import datetime
from app.parsers.base_parser import BaseParser


class FirewallParser(BaseParser):
    BLOCKED_RE = re.compile(r'\b(blocked|denied|dropped|rejected)\b', re.IGNORECASE)
    ALLOWED_RE = re.compile(r'\b(allowed|accepted|permitted)\b', re.IGNORECASE)
    SRC_RE = re.compile(r'SRC[=:](\S+)', re.IGNORECASE)
    DST_RE = re.compile(r'DST[=:](\S+)', re.IGNORECASE)
    DPT_RE = re.compile(r'DPT[=:](\d+)', re.IGNORECASE)
    PROTO_RE = re.compile(r'PROTO[=:](\w+)', re.IGNORECASE)

    def parse(self, raw_line: str) -> Optional[Dict[str, Any]]:
        if not raw_line.strip():
            return None

        raw = raw_line.strip()
        event_type = "NETWORK_CONNECTION"
        severity = "low"
        resource = None

        if self.BLOCKED_RE.search(raw):
            event_type = "FIREWALL_BLOCK"
            severity = "medium"
        elif self.ALLOWED_RE.search(raw):
            event_type = "FIREWALL_ALLOW"

        dpt_match = self.DPT_RE.search(raw)
        if dpt_match:
            port = dpt_match.group(1)
            resource = f"port:{port}"
            if port in ("22", "23", "3389", "445", "135", "139"):
                severity = "high"

        proto_match = self.PROTO_RE.search(raw)
        if proto_match and not resource:
            resource = f"proto:{proto_match.group(1)}"

        src_match = self.SRC_RE.search(raw)
        dst_match = self.DST_RE.search(raw)

        ip = self.extract_ip(raw)
        metadata = {}
        if src_match:
            metadata["src_ip"] = src_match.group(1)
        if dst_match:
            metadata["dst_ip"] = dst_match.group(1)
        if proto_match:
            metadata["protocol"] = proto_match.group(1)
        if dpt_match:
            metadata["dest_port"] = int(dpt_match.group(1))

        return {
            "timestamp": self.extract_timestamp(raw),
            "ip_address": ip,
            "username": None,
            "hostname": self.extract_hostname(raw),
            "source": "firewall",
            "event_type": event_type,
            "severity": severity,
            "resource": resource,
            "raw_message": raw,
            "metadata": metadata,
        }
